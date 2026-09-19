"""Kavach multi-agent workflow - thin CLI/demo wrapper.

The authoritative workflow execution now lives in the P1 Workflow
Supervisor (agents/supervisor/service.py). This script is only a
human-friendly demo entry point:

    python -m scripts.run_workflow

or programmatic use:

    from agents.supervisor import WorkflowSupervisor
    supervisor = WorkflowSupervisor()
    workflow_id = supervisor.create_workflow("Research a simple Fibonacci algorithm.")
    workflow = supervisor.start_workflow(workflow_id)
    print(workflow.summary())
"""

from agents.supervisor import WorkflowSupervisor


def main() -> None:
    print("=" * 60)
    print("KAVACH MULTI-AGENT WORKFLOW")
    print("=" * 60)

    supervisor = WorkflowSupervisor()
    workflow_id = supervisor.create_workflow(
        "Research a simple Fibonacci algorithm."
    )
    print()
    print(f"[1] Workflow created: {workflow_id}")
    print("[2] Starting workflow (protected actions via KavachGuard)...")
    workflow = supervisor.start_workflow(workflow_id)

    print()
    print(f"[3] Workflow finished: {workflow.status.value}")
    print(f"    Phases: {len(workflow.phases)}")
    msgs = workflow.result.get("messages_received") if workflow.result else "n/a"
    print(f"    Messages received by orchestrator: {msgs}")

    if workflow.error:
        print(f"    Error: {workflow.error}")

    print()
    print("Supervisor lifecycle events:")
    for event in supervisor.get_workflow_events(workflow_id):
        suffix = f" ({event.agent})" if event.agent else ""
        print(f"- {event.event_type.value}{suffix}")

    print()
    print("=" * 60)
    if workflow.status.value == "COMPLETED":
        print("WORKFLOW FINISHED SUCCESSFULLY")
    else:
        print(f"WORKFLOW ENDED: {workflow.status.value}")
    print("=" * 60)


if __name__ == "__main__":
    main()
