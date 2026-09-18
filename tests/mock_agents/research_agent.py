"""
Mock Research Agent for testing Kavach authorization.

This agent represents research-01 and sends authorization requests
to the Kavach HTTP gateway. It does NOT implement any authorization logic -
it simply constructs ActionRequests and sends them to POST /authorize.
"""

from typing import Any


class MockResearchAgent:
    """
    Mock Research Agent (research-01).
    
    This agent has the capability: research.search
    It sends requests to the Kavach /authorize endpoint and returns the Decision.
    """
    
    def __init__(self, http_client):
        """
        Initialize the mock agent with an HTTP client.
        
        Args:
            http_client: FastAPI TestClient or similar HTTP client
        """
        self.client = http_client
        self.agent_id = "research-01"
        self.capability = "research.search"
    
    def send_authorize_request(self, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Send an authorization request to POST /authorize.
        
        Args:
            payload: JSON payload for the /authorize endpoint
            
        Returns:
            The Decision JSON response from Kavach
        """
        response = self.client.post("/authorize", json=payload)
        response.raise_for_status()
        return response.json()
    
    def request_a_normal_research(self) -> dict[str, Any]:
        """
        Request A — Normal Research.
        
        Legitimate research activity that should be ALLOWED.
        """
        payload = {
            "source_agent": self.agent_id,
            "target_agent": self.agent_id,
            "task_id": "task-001",
            "action": "research.search",
            "resource": "research-data",
            "claimed_authority": "orchestrator-01",
            "capability": self.capability,
            "provenance": {
                "task_origin": "orchestrator-01",
                "delegation_chain": ["orchestrator-01", self.agent_id],
            },
        }
        return self.send_authorize_request(payload)
    
    def request_b_production_deployment(self) -> dict[str, Any]:
        """
        Request B — Production Deployment Attempt.
        
        Research agent attempting deployment.deploy - should be DENIED.
        """
        payload = {
            "source_agent": self.agent_id,
            "target_agent": "deployment-01",
            "task_id": "task-002",
            "action": "deployment.deploy",
            "resource": "production-environment",
            "claimed_authority": "orchestrator-01",
            "capability": self.capability,
            "provenance": {
                "task_origin": "orchestrator-01",
                "delegation_chain": ["orchestrator-01", self.agent_id],
            },
        }
        return self.send_authorize_request(payload)
    
    def request_c_authority_mismatch(self) -> dict[str, Any]:
        """
        Request C — Authority Mismatch.
        
        Claimed authority does not match delegation chain - should be DENIED.
        """
        payload = {
            "source_agent": self.agent_id,
            "target_agent": self.agent_id,
            "task_id": "task-003",
            "action": "research.search",
            "resource": "research-data",
            "claimed_authority": "orchestrator-01",  # Not in delegation chain
            "capability": self.capability,
            "provenance": {
                "task_origin": self.agent_id,
                "delegation_chain": [self.agent_id],  # Only self, no orchestrator
            },
        }
        return self.send_authorize_request(payload)
    
    def request_d_unknown_agent(self) -> dict[str, Any]:
        """
        Request D — Unknown Agent.
        
        Attempt with an unknown agent ID - should be DENIED.
        
        Note: If the ActionRequest schema constrains source_agent to known IDs,
        this will fail validation at the API boundary (HTTP 422).
        The security requirement is that unknown identity cannot receive ALLOW.
        """
        payload = {
            "source_agent": "unknown-01",  # Unknown agent
            "target_agent": "research-01",
            "task_id": "task-004",
            "action": "research.search",
            "resource": "research-data",
            "claimed_authority": "orchestrator-01",
            "capability": "research.search",
            "provenance": {
                "task_origin": "orchestrator-01",
                "delegation_chain": ["orchestrator-01", "unknown-01"],
            },
        }
        try:
            return self.send_authorize_request(payload)
        except Exception as e:
            # If validation fails (HTTP 422), this is acceptable
            # as it prevents unknown agents from receiving ALLOW
            return {"error": str(e), "status": "validation_failed"}
    
    def request_e_quarantined_agent(self) -> dict[str, Any]:
        """
        Request E — Quarantined Research Agent.
        
        Normal research request from a quarantined agent - should be DENIED.
        """
        payload = {
            "source_agent": self.agent_id,
            "target_agent": self.agent_id,
            "task_id": "task-005",
            "action": "research.search",
            "resource": "research-data",
            "claimed_authority": "orchestrator-01",
            "capability": self.capability,
            "provenance": {
                "task_origin": "orchestrator-01",
                "delegation_chain": ["orchestrator-01", self.agent_id],
            },
        }
        return self.send_authorize_request(payload)
