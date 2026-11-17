"""Starting and signalling workflows. The API refers to workflows by name only and never imports
the worker package; the worker is the only runtime that executes actions (threat model T21)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from app.errors import ProblemError
from app.services import Services

TASK_QUEUE = "nocsoc-automation"
ACTION_WORKFLOW = "ActionWorkflow"
PLAYBOOK_WORKFLOW = "PlaybookWorkflow"


async def _client(services: Services) -> Any:
    try:
        client = await services.temporal()
    except Exception as exc:
        raise ProblemError(
            503, "automation.unavailable", "Automation unavailable", "The workflow engine could not be reached."
        ) from exc
    if client is None:
        raise ProblemError(
            503, "automation.disabled", "Automation not configured", "Start the 'workflow' profile to run actions."
        )
    return client


async def start_action(services: Services, request_id: str, *, needs_approval: bool, expires_in_seconds: int) -> str:
    client = await _client(services)
    workflow_id = f"action-{request_id}"
    await client.start_workflow(
        ACTION_WORKFLOW,
        {"request_id": request_id, "needs_approval": needs_approval, "expires_in_seconds": expires_in_seconds},
        id=workflow_id,
        task_queue=TASK_QUEUE,
        execution_timeout=timedelta(days=2),
    )
    return workflow_id


async def start_playbook(
    services: Services, run_id: str, steps: list[dict[str, Any]], approval_timeout_seconds: int
) -> str:
    client = await _client(services)
    workflow_id = f"playbook-{run_id}"
    await client.start_workflow(
        PLAYBOOK_WORKFLOW,
        {"run_id": run_id, "steps": steps, "approval_timeout_seconds": approval_timeout_seconds},
        id=workflow_id,
        task_queue=TASK_QUEUE,
        execution_timeout=timedelta(days=2),
    )
    return workflow_id


async def signal_decision(services: Services, workflow_id: str, request_id: str, decision: str) -> None:
    """Tells a waiting workflow that a request was approved, denied or cancelled. The workflow
    still re-checks the request in the database before executing anything."""
    client = await _client(services)
    handle = client.get_workflow_handle(workflow_id)
    await handle.signal("decide", {"request_id": request_id, "decision": decision})


async def cancel(services: Services, workflow_id: str) -> None:
    client = await _client(services)
    await client.get_workflow_handle(workflow_id).cancel()
