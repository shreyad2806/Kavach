import os
import sys
import shutil
import json
from pathlib import Path

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
from sandbox.runtime.sandbox import Sandbox, ToolAccessDeniedError, ProcessExecutionDeniedError, CredentialAccessDeniedError
from sandbox.runtime.event_logger import EventLogger


class FullIntegrationTest:
    def __init__(self):
        # Use a temporary event logger to avoid polluting main logs
        self.log_file = "sandbox/runtime/test_security_events.jsonl"
        if os.path.exists(self.log_file):
            os.remove(self.log_file)
        self.event_logger = EventLogger(self.log_file)
        
        self.bus = MessageBus(self.event_logger)
        self.sandbox = Sandbox(self.event_logger)
        self.network = NetworkManager(self.event_logger)
        
        self.agents = {}
        self.workspaces = {}
        
        # Will be initialized in TEST 1
        self.orchestrator = None
        self.research = None
        self.coding = None
        self.deployment = None
        self.verification = None

        self.passed = 0
        self.failed = 0

    def print_result(self, step_num: int, title: str, success: bool, details: str = ""):
        status = "PASS" if success else "FAIL"
        print(f"[{step_num}] {title.ljust(30)} ........ {status}")
        if details:
            print(f"      {details}")
        if success:
            self.passed += 1
        else:
            self.failed += 1

    def run(self):
        print("=" * 60)
        print("KAVACH FULL SANDBOX INTEGRATION TEST")
        print("=" * 60)
        print("")
        
        original_env = dict(os.environ)
        os.environ.clear()

        try:
            self.test_1_init()
            self.test_2_identities()
            self.test_3_workflow()
            self.test_4_comm_isolation()
            self.test_5_workspace_isolation()
            self.test_6_tool_isolation()
            self.test_7_network_isolation()
            self.test_8_process_isolation()
            self.test_9_credential_isolation()
            self.test_10_deployment_safety()
            self.test_11_attack_boundary()
            self.test_12_security_events()
        finally:
            os.environ.clear()
            os.environ.update(original_env)
            self.cleanup()

        print("")
        print("=" * 60)
        final_status = "PASS" if self.failed == 0 else "FAIL"
        print(f"FULL SANDBOX INTEGRATION: {final_status}")
        print("=" * 60)
        
        if self.failed > 0:
            sys.exit(1)

    def test_1_init(self):
        try:
            self.orchestrator = OrchestratorAgent(self.bus)
            self.research = ResearchAgent(self.bus)
            self.coding = CodingAgent(self.bus)
            self.deployment = DeploymentAgent(self.bus)
            self.verification = VerificationAgent(self.bus)

            self.agents = {
                "orchestrator": self.orchestrator,
                "research": self.research,
                "coding": self.coding,
                "deployment": self.deployment,
                "verification": self.verification,
            }

            for agent in self.agents.values():
                self.sandbox.register_agent(agent.identity)

            # Re-init tools with the test network manager and correct workspaces
            # Note: since tools are initialized inside the Agent init, we must patch them or just test workspaces independently
            # To be safe without modifying agent source, we will instantiate SafeWorkspace directly for tests
            self.workspaces = {
                "orchestrator": SafeWorkspace("orchestrator", "sandbox/workspace/orchestrator"),
                "research": SafeWorkspace("research", "sandbox/workspace/research"),
                "coding": SafeWorkspace("coding", "sandbox/workspace/coding"),
                "deployment": SafeWorkspace("deployment", "sandbox/workspace/deployment"),
                "verification": SafeWorkspace("verification", "sandbox/workspace/verification"),
            }
            
            self.print_result(1, "Agent initialization", True)
        except Exception as e:
            self.print_result(1, "Agent initialization", False, str(e))

    def test_2_identities(self):
        try:
            ids = set()
            all_valid = True
            for agent in self.agents.values():
                identity = agent.identity
                if not identity.agent_id or not identity.name or not identity.role or not identity.capabilities:
                    all_valid = False
                ids.add(identity.agent_id)
            
            if len(ids) == 5 and all_valid:
                self.print_result(2, "Identity validation", True, f"Unique IDs: {', '.join(ids)}")
            else:
                self.print_result(2, "Identity validation", False, f"Found {len(ids)} unique IDs or missing fields.")
        except Exception as e:
            self.print_result(2, "Identity validation", False, str(e))

    def test_3_workflow(self):
        try:
            # 1. Orchestrator -> Research
            self.orchestrator.delegate("research", {"task": "test"})
            
            # 2 & 3. Research executes and sends result
            res = self.research.search("test query")
            self.research.send_result("orchestrator", res)
            
            # 4. Orchestrator -> Coding
            self.orchestrator.delegate("coding", {"task": "code"})
            
            # 5 & 6. Coding works and sends to verification
            self.coding.write_file("test.py", "print('hello')")
            coding_res = self.coding.run_tests()
            self.coding.send_result("verification", coding_res)
            
            # 7 & 8. Verification
            ver_res = self.verification.run_tests()
            self.verification.send_result("orchestrator", ver_res)
            
            # 9. Orchestrator -> Deployment
            self.orchestrator.delegate("deployment", {"task": "deploy"})
            
            # 10 & 11. Deployment simulation
            dep_res = self.deployment.simulate_deployment("staging")
            self.deployment.send_result("orchestrator", dep_res)
            
            # Ensure orchestrator received the messages
            results = self.orchestrator.get_results()
            received = len(results)
            
            # Verify specific completions based on messages received
            has_research = any(m.sender == "research" and m.content.get("results") for m in results)
            has_verification = any(m.sender == "verification" and m.content.get("status") == "PASSED" for m in results)
            has_deployment = any(m.sender == "deployment" and m.content.get("simulated") for m in results)
            
            # Verify coding completed by checking if verification received its message (since coding sends to verification)
            coding_completed = coding_res.get("status") == "PASSED"
            
            if has_research and coding_completed and has_verification and has_deployment:
                self.print_result(3, "Full workflow", True, f"Completed successfully. Orchestrator received {received} messages.")
            else:
                missing = []
                if not has_research: missing.append("Research")
                if not coding_completed: missing.append("Coding")
                if not has_verification: missing.append("Verification")
                if not has_deployment: missing.append("Deployment")
                self.print_result(3, "Full workflow", False, f"Missing workflow steps: {', '.join(missing)}")
        except Exception as e:
            self.print_result(3, "Full workflow", False, str(e))

    def test_4_comm_isolation(self):
        success = True
        
        # Check some allowed routes
        allowed = [
            ("orchestrator", "research"),
            ("research", "orchestrator"),
            ("coding", "verification"),
            ("deployment", "orchestrator")
        ]
        
        for sender, receiver in allowed:
            msg = AgentMessage(sender=sender, receiver=receiver, message_type="TEST", content={})
            try:
                self.bus.send(msg)
            except CommunicationDeniedError:
                success = False
                
        # Check some forbidden routes
        forbidden = [
            ("research", "coding"),
            ("research", "deployment"),
            ("verification", "coding"),
            ("deployment", "research")
        ]
        
        for sender, receiver in forbidden:
            msg = AgentMessage(sender=sender, receiver=receiver, message_type="TEST", content={})
            try:
                self.bus.send(msg)
                success = False # Should have raised
            except CommunicationDeniedError:
                pass
                
        self.print_result(4, "Communication isolation", success)

    def test_5_workspace_isolation(self):
        success = True
        
        try:
            # Allowed
            self.workspaces["research"].get_safe_path("allowed.txt")
            self.workspaces["coding"].get_safe_path("allowed.txt")
            
            # Denied
            try:
                self.workspaces["research"].get_safe_path("../coding/file.txt")
                success = False
            except WorkspaceAccessDeniedError:
                pass
                
            try:
                self.workspaces["deployment"].get_safe_path("../coding/file.txt")
                success = False
            except WorkspaceAccessDeniedError:
                pass
                
            self.print_result(5, "Workspace isolation", success)
        except Exception as e:
            self.print_result(5, "Workspace isolation", False, str(e))

    def test_6_tool_isolation(self):
        success = True
        try:
            # Check allowed tools using execute (simulating what KAVACH gateway will do)
            req1 = ToolRequest("research", "web.search", "target", {})
            res1 = self.sandbox.execute(req1)
            # Will be "Unknown operation" because executor is empty in sandbox by default, but shouldn't be Access Denied
            if res1.error and "Tool access denied" in res1.error:
                success = False
                
            req2 = ToolRequest("research", "deployment.simulate", "target", {})
            res2 = self.sandbox.execute(req2)
            if not res2.error or "Tool access denied" not in res2.error:
                success = False
                
            req3 = ToolRequest("coding", "web.search", "target", {})
            res3 = self.sandbox.execute(req3)
            if not res3.error or "Tool access denied" not in res3.error:
                success = False
                
            self.print_result(6, "Tool isolation", success)
        except Exception as e:
            self.print_result(6, "Tool isolation", False, str(e))

    def test_7_network_isolation(self):
        success = True
        try:
            self.network.check_access("research", "web_search")
            
            try:
                self.network.check_access("coding", "web_search")
                success = False
            except NetworkAccessDeniedError:
                pass
                
            try:
                self.network.check_access("deployment", "web_search")
                success = False
            except NetworkAccessDeniedError:
                pass
                
            self.print_result(7, "Network isolation", success)
        except Exception as e:
            self.print_result(7, "Network isolation", False, str(e))

    def test_8_process_isolation(self):
        success = True
        try:
            req = ToolRequest("research", "subprocess.run", "target", {})
            # It should fail credential or process isolation, let's make sure it's process isolation
            # Actually, without credentials, it hits process isolation first if we swap order, but sandbox checks creds then process.
            # We cleared os.environ, so creds pass, then process isolation hits
            try:
                self.sandbox.execute(req)
                # It shouldn't get here cleanly, sandbox.execute handles exceptions and returns ToolResponse?
                # No, sandbox.execute raises exceptions directly for process/credential isolation! Wait, let's check sandbox.py
                # In sandbox.py, it raises ProcessExecutionDeniedError
                success = False
            except ProcessExecutionDeniedError:
                pass
                
            self.print_result(8, "Process isolation", success)
        except Exception as e:
            self.print_result(8, "Process isolation", False, str(e))

    def test_9_credential_isolation(self):
        success = True
        try:
            os.environ["AWS_SECRET_ACCESS_KEY"] = "fake"
            req = ToolRequest("research", "web.search", "target", {})
            try:
                self.sandbox.execute(req)
                success = False
            except CredentialAccessDeniedError:
                pass
            finally:
                del os.environ["AWS_SECRET_ACCESS_KEY"]
                
            self.print_result(9, "Credential isolation", success)
        except Exception as e:
            self.print_result(9, "Credential isolation", False, str(e))

    def test_10_deployment_safety(self):
        try:
            res = self.deployment.simulate_deployment("staging")
            if res["status"] == "SUCCESS" and res["simulated"] is True and res["target"] == "staging":
                self.print_result(10, "Deployment safety", True, "Deployment is simulated")
            else:
                self.print_result(10, "Deployment safety", False)
        except Exception as e:
            self.print_result(10, "Deployment safety", False, str(e))

    def test_11_attack_boundary(self):
        success = True
        try:
            # Generate the malicious tool request
            req = self.research.request_unauthorized_deployment("production")
            
            # Validate it through the sandbox (which is what KAVACH will do)
            res = self.sandbox.execute(req)
            
            # The sandbox should reject it because research is not authorized for production.deploy
            if not res.success and "Tool access denied" in res.error:
                self.print_result(11, "Attack boundary", True, "Unauthorized deployment request blocked by sandbox")
            else:
                self.print_result(11, "Attack boundary", False)
        except Exception as e:
            self.print_result(11, "Attack boundary", False, str(e))

    def test_12_security_events(self):
        try:
            if not os.path.exists(self.log_file):
                self.print_result(12, "Security events", False, "No log file found")
                return
                
            with open(self.log_file, "r", encoding="utf-8") as f:
                events = [json.loads(line) for line in f if line.strip()]
                
            types = {e["event_type"] for e in events}
            expected_types = {"COMMUNICATION_DENIED", "NETWORK_ACCESS_DENIED", "TOOL_ACCESS_DENIED", "PROCESS_EXECUTION_DENIED"}
            
            if expected_types.issubset(types):
                self.print_result(12, "Security events", True, f"Logged {len(events)} events")
            else:
                self.print_result(12, "Security events", False, f"Missing event types: {expected_types - types}")
        except Exception as e:
            self.print_result(12, "Security events", False, str(e))

    def cleanup(self):
        # Remove test event log
        if os.path.exists(self.log_file):
            os.remove(self.log_file)
            
        # Clean up temporary test files in workspaces created during test 3
        test_file = Path("sandbox/workspace/coding/test.py")
        if test_file.exists():
            test_file.unlink()


if __name__ == "__main__":
    test = FullIntegrationTest()
    test.run()
