from agents.orchestrator.agent import OrchestratorAgent
from agents.research.agent import ResearchAgent
from agents.coding.agent import CodingAgent
from agents.deployment.agent import DeploymentAgent
from agents.verification.agent import VerificationAgent
from sandbox.runtime.message_bus import MessageBus


def main() -> None:
    print("=" * 60)
    print("KAVACH MULTI-AGENT WORKFLOW")
    print("=" * 60)

    # Create the shared local message bus.
    bus = MessageBus()

    # Create all five agents.
    orchestrator = OrchestratorAgent(bus)
    research = ResearchAgent(bus)
    coding = CodingAgent(bus)
    deployment = DeploymentAgent(bus)
    verification = VerificationAgent(bus)

    print("\n[1] All agents initialized.")

    print("\n[2] Orchestrator → Research")
    orchestrator.delegate(
        "research",
        {
            "task": "Research a simple Fibonacci algorithm.",
        },
    )

    research_result = research.search(
        "Fibonacci algorithm"
    )

    print("Research result:")
    print(research_result)

    research.write_research(
        "fibonacci.txt",
        "Fibonacci research completed.",
    )

    research.send_result(
        "orchestrator",
        {
            "status": "RESEARCH_COMPLETE",
            "topic": "Fibonacci",
        },
    )

    print("\n[3] Orchestrator → Coding")
    orchestrator.delegate(
        "coding",
        {
            "task": "Create a simple Fibonacci implementation.",
        },
    )

    coding.write_file(
        "fibonacci.py",
        "def fibonacci(n):\n"
        "    if n <= 1:\n"
        "        return n\n"
        "    return fibonacci(n - 1) + fibonacci(n - 2)\n",
    )

    coding_result = coding.run_tests()

    print("Coding test result:")
    print(coding_result)

    coding.send_result(
        "verification",
        {
            "status": "CODE_READY",
            "file": "fibonacci.py",
        },
    )

    print("\n[4] Verification")
    verification_result = verification.run_tests()

    print("Verification result:")
    print(verification_result)

    verification.send_result(
        "orchestrator",
        {
            "status": "VERIFIED",
            "tests_passed": verification_result["tests_passed"],
        },
    )

    print("\n[5] Orchestrator → Deployment")
    orchestrator.delegate(
        "deployment",
        {
            "task": "Simulate deployment to staging.",
        },
    )

    deployment_result = deployment.simulate_deployment(
        "staging"
    )

    print("Deployment result:")
    print(deployment_result)

    deployment.send_result(
        "orchestrator",
        {
            "status": "DEPLOYMENT_COMPLETE",
            "target": "staging",
            "simulated": True,
        },
    )

    print("\n[6] Workflow complete.")

    print("\nOrchestrator received messages:")
    for message in orchestrator.get_results():
        print(
            f"- {message.message_type} "
            f"from {message.sender}: "
            f"{message.content}"
        )

    print("\n" + "=" * 60)
    print("WORKFLOW FINISHED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()