"""Temporal activities. Each one is a single call to the platform API, or one claimed execution.

``execute_action`` can only run something the API's database ``claim`` approves: workflow input
and signals never authorise execution by themselves (threat model T21, SEC-ACT-01).
"""

from __future__ import annotations

from typing import Any

from temporalio import activity

from workflow_worker.api import WorkflowApi
from workflow_worker.executors import ExecutionRefusedError, execute_connector_action


class Activities:
    def __init__(self, api: WorkflowApi) -> None:
        self.api = api

    @activity.defn(name="execute_action")
    async def execute_action(self, request_id: str) -> dict[str, Any]:
        claim = await self.api.claim(request_id)
        if not claim["claimed"]:
            if claim.get("code") == "action.kill_switch":
                return {"status": "halted", "detail": claim.get("detail", "")}
            current = await self.api.request_status(request_id)
            if current["status"] == "executing":
                # A previous attempt claimed it and the worker died mid-execution. The outcome is
                # unknown, so it is recorded as failed rather than run a second time.
                await self.api.complete(
                    request_id, "failed", {}, "Worker interrupted during execution; not re-run automatically."
                )
                return {"status": "failed", "detail": "interrupted"}
            return {"status": "refused", "detail": claim.get("detail", ""), "code": claim.get("code", "")}
        spec = claim["spec"]
        try:
            if spec["connector_id"] == "platform":
                result = await self.api.platform_execute(request_id)
            else:
                result = await execute_connector_action(spec)
        except ExecutionRefusedError as exc:
            await self.api.complete(request_id, "failed", {}, f"Refused by executor: {exc}")
            return {"status": "failed", "detail": str(exc)}
        except Exception as exc:  # report the failure, never retry an action blindly
            await self.api.complete(request_id, "failed", {}, f"{type(exc).__name__}: {str(exc)[:300]}")
            return {"status": "failed", "detail": type(exc).__name__}
        status = "succeeded" if result.get("status") == "succeeded" else "failed"
        await self.api.complete(request_id, status, result, None if status == "succeeded" else result.get("message"))
        return {"status": status, "detail": str(result.get("message", ""))[:300]}

    @activity.defn(name="expire_request")
    async def expire_request(self, request_id: str) -> dict[str, Any]:
        return await self.api.expire(request_id)

    @activity.defn(name="request_step")
    async def request_step(self, args: dict[str, str]) -> dict[str, Any]:
        return await self.api.request_step(args["run_id"], args["step_id"])

    @activity.defn(name="checkpoint")
    async def checkpoint(self, run_id: str) -> dict[str, Any]:
        return await self.api.checkpoint(run_id)

    @activity.defn(name="step_result")
    async def step_result(self, args: dict[str, Any]) -> None:
        await self.api.step_result(
            args["run_id"], args["step_id"], args["status"], args.get("request_id"), args.get("detail", "")
        )

    @activity.defn(name="finish_run")
    async def finish_run(self, args: dict[str, Any]) -> None:
        await self.api.finish(args["run_id"], args["status"], args.get("error"))

    def all(self) -> list[Any]:
        return [
            self.execute_action,
            self.expire_request,
            self.request_step,
            self.checkpoint,
            self.step_result,
            self.finish_run,
        ]
