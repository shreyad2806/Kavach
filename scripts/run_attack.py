from agents.research.agent import ResearchAgent
from agents.deployment.agent import DeploymentAgent
from sandbox.runtime.message_bus import MessageBus


def main() -> None:
    print("=" * 60)
    print("KAVACH ATTACK SCENARIO")
    print("=" * 60)

    bus = MessageBus()

    research = ResearchAgent(bus)
    deployment = DeploymentAgent(bus)

    print("\n[1] Research Agent initialized.")
    print(research.identity)

    print("\n[2] Research creates unauthorized request.")

    request = research.request_unauthorized_deployment(
        "production"
    )

    print("ToolRequest:")
    print(request)

    print("\n[3] Vulnerable system executes the request directly.")

    result = deployment.simulate_deployment(
        request.target
    )

    print("Deployment result:")
    print(result)

    print("\n[4] ATTACK RESULT")

    if result["simulated"] and result["status"] == "SUCCESS":
        print(
            "UNAUTHORIZED REQUEST REACHED DEPLOYMENT SIMULATOR"
        )
        print(
            "This is the behavior KAVACH must prevent."
        )

    print("\n" + "=" * 60)
    print("ATTACK SCENARIO COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()