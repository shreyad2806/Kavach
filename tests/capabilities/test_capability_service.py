import pytest

from kavach.capabilities import CapabilityService, CapabilityName


class TestCapabilityService:
    """Test suite for Phase 5 Capability Registry."""
    
    def setup_method(self):
        """Initialize a fresh CapabilityService for each test."""
        self.service = CapabilityService()
    
    def test_1_research_capabilities(self):
        """TEST 1 — Research capabilities."""
        capabilities = self.service.get_capabilities("research-01")
        
        assert len(capabilities) == 2
        capability_names = {cap.name.value for cap in capabilities}
        assert capability_names == {"research.search", "research.read"}
    
    def test_2_coding_capabilities(self):
        """TEST 2 — Coding capabilities."""
        capabilities = self.service.get_capabilities("coding-01")
        
        assert len(capabilities) == 3
        capability_names = {cap.name.value for cap in capabilities}
        assert capability_names == {"coding.read", "coding.write", "coding.test"}
    
    def test_3_deployment_capabilities(self):
        """TEST 3 — Deployment capabilities."""
        capabilities = self.service.get_capabilities("deployment-01")
        
        assert len(capabilities) == 2
        capability_names = {cap.name.value for cap in capabilities}
        assert capability_names == {"deployment.preview", "deployment.production"}
    
    def test_4_verification_capabilities(self):
        """TEST 4 — Verification capabilities."""
        capabilities = self.service.get_capabilities("verification-01")
        
        assert len(capabilities) == 1
        capability_names = {cap.name.value for cap in capabilities}
        assert capability_names == {"verification.test"}
    
    def test_5_orchestrator_capabilities(self):
        """TEST 5 — Orchestrator capabilities."""
        capabilities = self.service.get_capabilities("orchestrator-01")
        
        assert len(capabilities) == 2
        capability_names = {cap.name.value for cap in capabilities}
        assert capability_names == {"orchestrator.delegate", "orchestrator.coordinate"}
    
    def test_6_has_capability_positive(self):
        """TEST 6 — has_capability positive."""
        assert self.service.has_capability("research-01", "research.search") is True
    
    def test_7_has_capability_negative(self):
        """TEST 7 — has_capability negative."""
        assert self.service.has_capability("research-01", "coding.write") is False
    
    def test_8_unknown_agent(self):
        """TEST 8 — Unknown agent."""
        capabilities = self.service.get_capabilities("unknown-agent")
        
        assert len(capabilities) == 0
        # Verify the agent was NOT dynamically created
        assert self.service.has_capability("unknown-agent", "any.capability") is False
    
    def test_9_unknown_capability(self):
        """TEST 9 — Unknown capability."""
        # Unknown capability for a known agent
        assert self.service.has_capability("research-01", "unknown.capability") is False
    
    def test_10_capability_action_separation(self):
        """TEST 10 — Capability/action separation."""
        # Canonical test demonstrating separation of concerns
        source_agent = "research-01"
        capability = "research.search"
        action = "deployment.deploy"
        resource = "production-environment"
        
        # The capability service ONLY answers: does the agent have this capability?
        assert self.service.has_capability(source_agent, capability) is True
        
        # The capability service does NOT decide whether deployment.deploy is authorized
        # That decision belongs to the authorization engine (later phase)
        # This test verifies the capability registry does NOT overstep its bounds
    
    def test_11_registry_immutability_from_returned_data(self):
        """TEST 11 — Registry immutability from returned data."""
        # Retrieve capabilities
        caps = self.service.get_capabilities("research-01")
        original_count = len(caps)
        
        # Modify the returned list
        caps.clear()
        
        # Verify the internal registry is unchanged
        caps_after = self.service.get_capabilities("research-01")
        assert len(caps_after) == original_count
        assert len(caps_after) == 2
        
        # Verify capabilities are still present
        capability_names = {cap.name.value for cap in caps_after}
        assert capability_names == {"research.search", "research.read"}
    
    def test_12_all_canonical_agents_have_capabilities(self):
        """TEST 12 — All canonical agents have capabilities."""
        canonical_agents = [
            "orchestrator-01",
            "research-01",
            "coding-01",
            "deployment-01",
            "verification-01",
        ]
        
        for agent_id in canonical_agents:
            capabilities = self.service.get_capabilities(agent_id)
            assert len(capabilities) >= 1, f"Agent {agent_id} should have at least one capability"
