"""
Workflow correlation context for Kavach security telemetry.

This is a *correlation* mechanism only.  It never influences an authorization
decision: the pipeline does not read it, Cedar never sees it, and it is not
part of the ActionRequest contract.

It exists so that every AUTHORIZATION_DECISION event emitted while a
WorkflowSupervisor workflow is executing can be correlated back to that
workflow through ``workflow_id`` — without changing the enforcement boundary
or duplicating the ActionRequest's ``task_id``.
"""

import contextvars

# Default None = "no workflow context" (e.g. a direct /authorize call).
_current_workflow_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "kavach_workflow_id",
    default=None,
)


def set_current_workflow_id(workflow_id: str | None):
    """Bind a workflow_id for the current context. Returns the reset token."""
    return _current_workflow_id.set(workflow_id)


def reset_current_workflow_id(token) -> None:
    """Undo a previous set_current_workflow_id() call."""
    _current_workflow_id.reset(token)


def get_current_workflow_id() -> str | None:
    """Return the workflow_id bound to the current context, if any."""
    return _current_workflow_id.get()
