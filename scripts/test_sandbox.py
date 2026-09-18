import os
from pathlib import Path
import unittest
import unittest.mock

from agents.common.identity import AgentIdentity
from agents.common.schemas import ToolRequest
from agents.research.agent import ResearchAgent
from agents.coding.agent import CodingAgent
from agents.deployment.agent import DeploymentAgent
from agents.verification.agent import VerificationAgent
from agents.orchestrator.agent import OrchestratorAgent

from sandbox.runtime.message_bus import MessageBus, CommunicationDeniedError
from sandbox.runtime.workspace import SafeWorkspace, WorkspaceAccessDeniedError
from sandbox.runtime.network import NetworkManager, NetworkAccessDeniedError
from sandbox.runtime.sandbox import Sandbox, ToolAccessDeniedError, ProcessExecutionDeniedError, CredentialAccessDeniedError


class TestSandbox(unittest.TestCase):
    def setUp(self):
        self.bus = MessageBus()
        self.sandbox = Sandbox()
        self.network = NetworkManager()

        self.research_identity = AgentIdentity(
            agent_id="research",
            name="Research Agent",
            role="researcher",
            capabilities=frozenset({"web.search", "document.read", "research.write", "agent.message"}),
        )
        self.coding_identity = AgentIdentity(
            agent_id="coding",
            name="Coding Agent",
            role="coder",
            capabilities=frozenset({"file.read", "file.write", "tests.run", "agent.message"}),
        )
        self.deployment_identity = AgentIdentity(
            agent_id="deployment",
            name="Deployment Agent",
            role="deployer",
            capabilities=frozenset({"deployment.simulate", "infrastructure.inspect", "deployment.status", "agent.message"}),
        )

        self.sandbox.register_agent(self.research_identity)
        self.sandbox.register_agent(self.coding_identity)
        self.sandbox.register_agent(self.deployment_identity)

        # Ensure workspaces are created
        SafeWorkspace("research", "sandbox/workspace/research")
        SafeWorkspace("coding", "sandbox/workspace/coding")

        # Patch os.environ during tests to hide real environment credentials
        self.patcher = unittest.mock.patch.dict(os.environ, {}, clear=True)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    def test_agent_initialization(self):
        bus = MessageBus()
        r = ResearchAgent(bus)
        c = CodingAgent(bus)
        d = DeploymentAgent(bus)
        v = VerificationAgent(bus)
        o = OrchestratorAgent(bus)
        self.assertEqual(r.identity.agent_id, "research")
        self.assertEqual(c.identity.agent_id, "coding")

    def test_workspace_isolation(self):
        research_workspace = SafeWorkspace("research", "sandbox/workspace/research")
        coding_workspace = SafeWorkspace("coding", "sandbox/workspace/coding")

        # A. Allowed access
        research_workspace.write_text("test.txt", "hello")
        self.assertEqual(research_workspace.read_text("test.txt"), "hello")

        # B. Cross-agent access fails (research accessing coding)
        # We simulate Research trying to pass a path that reaches into coding
        with self.assertRaises(WorkspaceAccessDeniedError):
            research_workspace.get_safe_path("../coding/test.txt")

        # C. Absolute outside path fails
        with self.assertRaises(WorkspaceAccessDeniedError):
            research_workspace.get_safe_path("/etc/passwd")

    def test_communication_isolation(self):
        # allowed route: research -> orchestrator
        from agents.common.messages import AgentMessage
        msg = AgentMessage("research", "orchestrator", "TEST", {})
        # Should not raise exception
        self.bus.send(msg)

        # blocked route: research -> deployment
        bad_msg = AgentMessage("research", "deployment", "TEST", {})
        with self.assertRaises(CommunicationDeniedError):
            self.bus.send(bad_msg)

    def test_network_isolation(self):
        # Research allowed
        self.network.check_access("research", "web_search")

        # Coding not allowed
        with self.assertRaises(NetworkAccessDeniedError):
            self.network.check_access("coding", "web_search")

    def test_tool_isolation(self):
        # Allowed tool
        req_allowed = ToolRequest(agent_id="research", operation="web.search", target="", arguments={})
        # Note: Sandbox doesn't have web.search registered in executor for this test, but it will pass the check
        res = self.sandbox.execute(req_allowed)
        self.assertEqual(res.error, "Unknown operation: web.search") # Passed auth, failed at execution

        # Denied tool
        req_denied = ToolRequest(agent_id="research", operation="production.deploy", target="production", arguments={})
        res = self.sandbox.execute(req_denied)
        self.assertFalse(res.success)
        self.assertIn("Tool access denied", res.error)

    def test_process_isolation(self):
        req_process = ToolRequest(agent_id="research", operation="subprocess.run", target="", arguments={})
        with self.assertRaises(ProcessExecutionDeniedError):
            self.sandbox.execute(req_process)

    def test_credential_isolation(self):
        os.environ["AWS_ACCESS_KEY_ID"] = "secret"
        req = ToolRequest(agent_id="research", operation="web.search", target="", arguments={})
        with self.assertRaises(CredentialAccessDeniedError):
            self.sandbox.execute(req)
        del os.environ["AWS_ACCESS_KEY_ID"]

    def test_deployment_simulation(self):
        bus = MessageBus()
        deployment = DeploymentAgent(bus)
        res = deployment.simulate_deployment("production")
        self.assertTrue(res["simulated"])
        self.assertEqual(res["status"], "SUCCESS")


if __name__ == "__main__":
    print("=" * 60)
    print("KAVACH SANDBOX SECURITY TESTS")
    print("=" * 60)

    suite = unittest.TestLoader().loadTestsFromTestCase(TestSandbox)
    result = unittest.TextTestRunner(verbosity=2).run(suite)

    print("\n============================================================")
    if result.wasSuccessful():
        print("ALL SANDBOX TESTS PASSED")
    else:
        print("SOME TESTS FAILED")
    print("============================================================")
