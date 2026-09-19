"""
WorkflowRegistry — process-level store of WorkflowSupervisor instances.
"""
from agents.supervisor.service import WorkflowSupervisor, WorkflowNotFoundError


class WorkflowRegistry:
    def __init__(self) -> None:
        self._supervisor = WorkflowSupervisor()

    def create(self, task: str, runtime=None) -> "WorkflowSupervisor":
        """Create a workflow via the supervisor and return the supervisor (for API compat)."""
        workflow_id = self._supervisor.create_workflow(task)
        return _WorkflowHandle(self._supervisor, workflow_id)

    def get(self, workflow_id: str):
        try:
            wf = self._supervisor.get_workflow(workflow_id)
            return _WorkflowHandle(self._supervisor, workflow_id)
        except WorkflowNotFoundError:
            return None

    def list_all(self):
        return self._supervisor.list_workflows()


class _WorkflowHandle:
    """Thin adapter so registry.get() returns an object with .snapshot() and .get_events()."""

    def __init__(self, supervisor: WorkflowSupervisor, workflow_id: str) -> None:
        self._supervisor = supervisor
        self.workflow_id = workflow_id

    def _workflow(self):
        return self._supervisor.get_workflow(self.workflow_id)

    @property
    def status(self):
        return self._workflow().status

    def snapshot(self):
        from agents.supervisor.models import WorkflowSnapshot
        wf = self._workflow()
        steps = [p.agent for p in wf.phases if p.status.value == "COMPLETED"]
        return WorkflowSnapshot(
            workflow_id=wf.workflow_id,
            task=wf.task,
            status=wf.status,
            created_at=wf.created_at.isoformat() if wf.created_at else None,
            started_at=wf.started_at.isoformat() if wf.started_at else None,
            completed_at=wf.completed_at.isoformat() if wf.completed_at else None,
            error=wf.error,
            steps_completed=steps,
        )

    def start(self):
        self._supervisor.start_workflow(self.workflow_id)

    def stop(self):
        self._supervisor.stop_workflow(self.workflow_id)

    def get_events(self):
        return self._supervisor.get_workflow_events(self.workflow_id)


_registry: WorkflowRegistry | None = None


def get_registry() -> WorkflowRegistry:
    global _registry
    if _registry is None:
        _registry = WorkflowRegistry()
    return _registry


def reset_registry() -> WorkflowRegistry:
    """FOR TESTING ONLY."""
    global _registry
    _registry = WorkflowRegistry()
    return _registry
