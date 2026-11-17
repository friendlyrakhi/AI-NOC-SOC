"""Temporal workflows (deterministic; all I/O happens in activities).

- ``ActionWorkflow``: one action request. Waits for a decision signal or the approval window,
  then asks the ``execute_action`` activity to claim and run it.
- ``PlaybookWorkflow``: a published playbook against an incident. Before each step it calls
  ``checkpoint`` (kill switch, cancellation), then requests the step's action from the API, waits
  for approval when the policy requires it, and executes.

Durable state (which step, which decisions arrived) lives in Temporal's event history, so a
worker that dies mid-run is replaced by another that continues exactly where it stopped.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy

ACTIVITY_TIMEOUT = timedelta(seconds=60)
# API calls are idempotent and retried; execution itself is protected by the database claim.
RETRY = RetryPolicy(initial_interval=timedelta(seconds=1), maximum_interval=timedelta(seconds=20), maximum_attempts=10)


async def _act(name: str, arg: Any) -> Any:
    return await workflow.execute_activity(name, arg, start_to_close_timeout=ACTIVITY_TIMEOUT, retry_policy=RETRY)


@workflow.defn(name="ActionWorkflow")
class ActionWorkflow:
    def __init__(self) -> None:
        self._decision: str | None = None

    @workflow.signal(name="decide")
    def decide(self, payload: dict[str, Any]) -> None:
        self._decision = str(payload.get("decision"))

    @workflow.run
    async def run(self, args: dict[str, Any]) -> dict[str, Any]:
        request_id = args["request_id"]
        if args.get("needs_approval"):
            try:
                await workflow.wait_condition(
                    lambda: self._decision is not None, timeout=timedelta(seconds=int(args["expires_in_seconds"]))
                )
            except TimeoutError:
                expired = await _act("expire_request", request_id)
                if expired["status"] != "approved":
                    return {"status": expired["status"]}
            if self._decision is not None and self._decision != "approved":
                return {"status": self._decision}
        return dict(await _act("execute_action", request_id))


@workflow.defn(name="PlaybookWorkflow")
class PlaybookWorkflow:
    def __init__(self) -> None:
        self._decisions: dict[str, str] = {}

    @workflow.signal(name="decide")
    def decide(self, payload: dict[str, Any]) -> None:
        self._decisions[str(payload.get("request_id"))] = str(payload.get("decision"))

    async def _wait_for(self, request_id: str, window: timedelta) -> str:
        await workflow.wait_condition(lambda: request_id in self._decisions, timeout=window)
        return self._decisions[request_id]

    async def _record(self, run_id: str, step_id: str, status: str, request_id: str | None, detail: str = "") -> None:
        await _act(
            "step_result",
            {"run_id": run_id, "step_id": step_id, "status": status, "request_id": request_id, "detail": detail},
        )

    @workflow.run
    async def run(self, args: dict[str, Any]) -> dict[str, Any]:
        run_id = args["run_id"]
        timeout = timedelta(seconds=int(args.get("approval_timeout_seconds", 1800)))
        results: dict[str, str] = {}
        for step in args["steps"]:
            sid = step["id"]
            if any(results.get(r) != "succeeded" for r in step.get("requires", [])):
                results[sid] = "skipped"
                await self._record(run_id, sid, "skipped", None, "A required step did not succeed.")
                continue
            cp = await _act("checkpoint", run_id)
            if cp["halt"]:
                final = "halted" if "kill switch" in cp["reason"] else "cancelled"
                await _act("finish_run", {"run_id": run_id, "status": final, "error": cp["reason"]})
                return {"status": final, "steps": results}
            req = await _act("request_step", {"run_id": run_id, "step_id": sid})
            request_id = req.get("request_id")
            status = req["status"]
            if request_id and status in ("approved", "pending_approval"):
                if req["needs_approval"]:
                    await self._record(run_id, sid, "awaiting_approval", request_id, req.get("detail", ""))
                    try:
                        status = await self._wait_for(request_id, timeout)
                    except TimeoutError:
                        status = (await _act("expire_request", request_id))["status"]
                if status == "approved":
                    outcome = await _act("execute_action", request_id)
                    status = outcome["status"]
                    if status == "halted":
                        await self._record(run_id, sid, "halted", request_id, outcome.get("detail", ""))
                        await _act("finish_run", {"run_id": run_id, "status": "halted", "error": "kill switch engaged"})
                        return {"status": "halted", "steps": results}
            results[sid] = status
            await self._record(run_id, sid, status, request_id, req.get("detail", "") if status == "denied" else "")
            if status != "succeeded" and step.get("on_failure", "stop") == "stop":
                await _act("finish_run", {"run_id": run_id, "status": "failed", "error": f"step {sid} {status}"})
                return {"status": "failed", "steps": results}
        final = "succeeded" if all(s in ("succeeded", "skipped") for s in results.values()) else "failed"
        await _act("finish_run", {"run_id": run_id, "status": final, "error": None})
        return {"status": final, "steps": results}
