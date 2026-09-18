import os
import unittest
from typing import Any
import sys

from agents.common.messages import AgentMessage
from agents.common.schemas import ToolRequest
from agents.orchestrator.agent import OrchestratorAgent
from agents.research.agent import ResearchAgent
from agents.coding.agent import CodingAgent
from agents.deployment.agent import DeploymentAgent
from agents.verification.agent import VerificationAgent

from sandbox.runtime.message_bus import MessageBus, CommunicationDeniedError
from sandbox.runtime.workspace import SafeWorkspace, WorkspaceAccessDeniedError
from sandbox.runtime.network import NetworkManager, NetworkAccessDeniedError
from sandbox.runtime.sandbox import Sandbox


class P1AgentIsolationTest:
    def __init__(self):
        self.bus = MessageBus()
        self.sandbox = Sandbox()
        self.network = NetworkManager()

        self.orchestrator = OrchestratorAgent(self.bus)
        self.research = ResearchAgent(self.bus)
        self.coding = CodingAgent(self.bus)
        self.deployment = DeploymentAgent(self.bus)
        self.verification = VerificationAgent(self.bus)

        self.sandbox.register_agent(self.orchestrator.identity)
        self.sandbox.register_agent(self.research.identity)
        self.sandbox.register_agent(self.coding.identity)
        self.sandbox.register_agent(self.deployment.identity)
        self.sandbox.register_agent(self.verification.identity)

        self.workspaces = {
            "orchestrator": SafeWorkspace("orchestrator", "sandbox/workspace/orchestrator"),
            "research": SafeWorkspace("research", "sandbox/workspace/research"),
            "coding": SafeWorkspace("coding", "sandbox/workspace/coding"),
            "deployment": SafeWorkspace("deployment", "sandbox/workspace/deployment"),
            "verification": SafeWorkspace("verification", "sandbox/workspace/verification"),
        }

        self.results = {}

    def run_tests(self):
        print("=" * 60)
        print("P1 AGENT ISOLATION TEST")
        print("=" * 60)

        # We need to temporarily scrub env for sandbox tests
        original_env = dict(os.environ)
        os.environ.clear()

        try:
            self.test_orchestrator()
            self.test_research()
            self.test_coding()
            self.test_deployment()
            self.test_verification()
        finally:
            os.environ.clear()
            os.environ.update(original_env)

        all_passed = all(
            all(v for v in checks.values())
            for checks in self.results.values()
        )

        if all_passed:
            print("\n============================================================")
            print("ALL P1 AGENT ISOLATION TESTS PASSED")
            print("============================================================")
            sys.exit(0)
        else:
            print("\n============================================================")
            print("SOME TESTS FAILED")
            print("============================================================")
            sys.exit(1)

    def _test_tool(self, agent_id: str, operation: str, expected_success: bool):
        req = ToolRequest(agent_id=agent_id, operation=operation, target="test", arguments={})
        res = self.sandbox.execute(req)
        # It's a success if the authorization result matches expected
        # If authorized, executor will say "Unknown operation" because we didn't register the dummy tool,
        # but the authorization passed.
        # If denied, it will say "Tool access denied"
        if expected_success:
            return res.success or (res.error and "Unknown operation" in res.error)
        else:
            return not res.success and "Tool access denied" in res.error

    def _test_comm(self, sender: str, receiver: str, expected_success: bool):
        msg = AgentMessage(sender=sender, receiver=receiver, message_type="TEST", content={})
        try:
            self.bus.send(msg)
            return expected_success is True
        except CommunicationDeniedError:
            return expected_success is False

    def _test_workspace(self, agent_id: str, path: str, expected_success: bool):
        ws = self.workspaces[agent_id]
        try:
            ws.get_safe_path(path)
            return expected_success is True
        except WorkspaceAccessDeniedError:
            return expected_success is False

    def _test_network(self, agent_id: str, expected_success: bool):
        try:
            self.network.check_access(agent_id, "web_search")
            return expected_success is True
        except NetworkAccessDeniedError:
            return expected_success is False


    def test_orchestrator(self):
        print("\nORCHESTRATOR")
        checks = {}

        # Allowed Operations
        checks["Allowed operations"] = all([
            self._test_tool("orchestrator", "task.delegate", True)
        ])

        # Forbidden Operations
        checks["Forbidden operations"] = all([
            self._test_tool("orchestrator", "web.search", False),
            self._test_tool("orchestrator", "file.write", False),
            self._test_tool("orchestrator", "production.deploy", False),
        ])

        # Communication
        checks["Communication isolation"] = all([
            self._test_comm("orchestrator", "research", True),
            self._test_comm("orchestrator", "coding", True),
            self._test_comm("orchestrator", "deployment", True),
            self._test_comm("orchestrator", "verification", True),
            self._test_comm("orchestrator", "unknown", False),
        ])

        # Workspace
        checks["Workspace isolation"] = all([
            self._test_workspace("orchestrator", "test.txt", True),
            self._test_workspace("orchestrator", "../coding/test.txt", False),
            self._test_workspace("orchestrator", "/etc/passwd", False),
        ])

        for k, v in checks.items():
            print(f"{k}: {'PASS' if v else 'FAIL'}")

        self.results["orchestrator"] = checks


    def test_research(self):
        print("\nRESEARCH")
        checks = {}

        checks["Allowed operations"] = all([
            self._test_tool("research", "web.search", True),
            self._test_tool("research", "document.read", True),
            self._test_tool("research", "research.write", True),
        ])

        checks["Forbidden operations"] = all([
            self._test_tool("research", "production.deploy", False),
            self._test_tool("research", "file.write", False),
        ])

        checks["Communication isolation"] = all([
            self._test_comm("research", "orchestrator", True),
            self._test_comm("research", "coding", False),
            self._test_comm("research", "deployment", False),
            self._test_comm("research", "verification", False),
        ])

        checks["Workspace isolation"] = all([
            self._test_workspace("research", "file.txt", True),
            self._test_workspace("research", "../coding/file.txt", False),
            self._test_workspace("research", "../deployment/file.txt", False),
            self._test_workspace("research", "../verification/file.txt", False),
        ])

        checks["Network capability"] = self._test_network("research", True)

        for k, v in checks.items():
            print(f"{k}: {'PASS' if v else 'FAIL'}")

        self.results["research"] = checks


    def test_coding(self):
        print("\nCODING")
        checks = {}

        checks["Allowed operations"] = all([
            self._test_tool("coding", "file.read", True),
            self._test_tool("coding", "file.write", True),
            self._test_tool("coding", "tests.run", True),
        ])

        checks["Forbidden operations"] = all([
            self._test_tool("coding", "production.deploy", False),
            self._test_tool("coding", "web.search", False),
        ])

        checks["Communication isolation"] = all([
            self._test_comm("coding", "orchestrator", True),
            self._test_comm("coding", "research", True),
            self._test_comm("coding", "verification", True),
            self._test_comm("coding", "deployment", False),
        ])

        checks["Workspace isolation"] = all([
            self._test_workspace("coding", "file.txt", True),
            self._test_workspace("coding", "../deployment/file.txt", False),
            self._test_workspace("coding", "../research/file.txt", False),
        ])

        checks["Network capability"] = self._test_network("coding", False)

        for k, v in checks.items():
            # Only print what was requested
            if k == "Network capability": continue
            print(f"{k}: {'PASS' if v else 'FAIL'}")

        self.results["coding"] = checks


    def test_deployment(self):
        print("\nDEPLOYMENT")
        checks = {}

        checks["Allowed operations"] = all([
            self._test_tool("deployment", "deployment.simulate", True),
            self._test_tool("deployment", "infrastructure.inspect", True),
        ])

        checks["Forbidden operations"] = all([
            self._test_tool("deployment", "web.search", False),
            self._test_tool("deployment", "file.write", False),
        ])

        checks["Communication isolation"] = all([
            self._test_comm("deployment", "orchestrator", True),
            self._test_comm("deployment", "verification", True),
            self._test_comm("deployment", "research", False),
            self._test_comm("deployment", "coding", False),
        ])

        checks["Workspace isolation"] = all([
            self._test_workspace("deployment", "file.txt", True),
            self._test_workspace("deployment", "../coding/file.txt", False),
            self._test_workspace("deployment", "../research/file.txt", False),
        ])

        for k, v in checks.items():
            print(f"{k}: {'PASS' if v else 'FAIL'}")

        self.results["deployment"] = checks


    def test_verification(self):
        print("\nVERIFICATION")
        checks = {}

        checks["Allowed operations"] = all([
            self._test_tool("verification", "output.inspect", True),
            self._test_tool("verification", "tests.run", True),
        ])

        checks["Forbidden operations"] = all([
            self._test_tool("verification", "production.deploy", False),
            self._test_tool("verification", "file.write", False),
        ])

        checks["Communication isolation"] = all([
            self._test_comm("verification", "orchestrator", True),
            self._test_comm("verification", "research", False),
            self._test_comm("verification", "coding", False),
            self._test_comm("verification", "deployment", False),
        ])

        checks["Workspace isolation"] = all([
            self._test_workspace("verification", "output.txt", True),
            self._test_workspace("verification", "../coding/file.txt", False),
        ])

        for k, v in checks.items():
            print(f"{k}: {'PASS' if v else 'FAIL'}")

        self.results["verification"] = checks


if __name__ == "__main__":
    P1AgentIsolationTest().run_tests()
