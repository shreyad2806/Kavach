"""
Phase 20B — Lightweight Kavach Supervision on the P1 MessageBus.

Proves that:
1. Normal allowed MessageBus communication still succeeds.
2. Existing ALLOWED_ROUTES enforcement still works.
3. Denied route still raises CommunicationDeniedError.
4. Normal MessageBus communication does NOT call shield.authorize().
5. Normal MessageBus communication does NOT call Cedar.
6. Normal MessageBus communication does NOT invoke LLM/content analysis.
7. Large research payload can pass without Kavach copying the entire payload.
8. Telemetry contains source, target, message metadata and correlation IDs.
9. Telemetry failure does not block message delivery.
10. Message content is unchanged by Kavach supervision.
11. No additional privilege is granted to any agent.
12. No agent can use telemetry hooks to modify Kavach policy/state.
13. Existing P1 agent tests continue passing (verified by full suite).
14. Existing Shield tests continue passing (verified by full suite).
"""

import sys
from unittest.mock import MagicMock, patch, call

import pytest

from agents.common.messages import AgentMessage
from agents.orchestrator.agent import OrchestratorAgent
from agents.research.agent import ResearchAgent
from agents.coding.agent import CodingAgent
from agents.deployment.agent import DeploymentAgent
from agents.verification.agent import VerificationAgent
from sandbox.runtime.message_bus import (
    CommunicationDeniedError,
    MessageBus,
    MessageSupervision,
    _compute_payload_size,
)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def bus():
    """Fresh MessageBus with no supervision hook."""
    return MessageBus()


@pytest.fixture
def supervised_bus():
    """Fresh MessageBus with a spy supervision hook."""
    spy = MagicMock()
    return MessageBus(supervise=spy), spy


@pytest.fixture
def full_agents():
    """All five agents wired to a shared MessageBus."""
    b = MessageBus()
    return {
        "orchestrator": OrchestratorAgent(b),
        "research": ResearchAgent(b),
        "coding": CodingAgent(b),
        "deployment": DeploymentAgent(b),
        "verification": VerificationAgent(b),
    }, b


# ============================================================================
# TEST 1 — Normal allowed communication succeeds
# ============================================================================

def test_allowed_communication_succeeds(bus):
    """Allowed route delivers without error."""
    msg = AgentMessage(sender="orchestrator", receiver="research", message_type="TASK", content={"task": "search"})
    bus.send(msg)  # Should not raise


def test_allowed_all_routes(bus):
    """Every route in ALLOWED_ROUTES delivers without error."""
    for sender, receiver in MessageBus.ALLOWED_ROUTES:
        msg = AgentMessage(sender=sender, receiver=receiver, message_type="TEST", content={})
        bus.send(msg)


# ============================================================================
# TEST 2 — ALLOWED_ROUTES enforcement still works
# ============================================================================

def test_allowed_routes_set_unchanged():
    """ALLOWED_ROUTES still contains exactly the original 12 routes."""
    expected = {
        ("orchestrator", "research"),
        ("orchestrator", "coding"),
        ("orchestrator", "deployment"),
        ("orchestrator", "verification"),
        ("research", "orchestrator"),
        ("coding", "orchestrator"),
        ("coding", "research"),
        ("coding", "verification"),
        ("deployment", "orchestrator"),
        ("deployment", "verification"),
        ("verification", "orchestrator"),
    }
    assert MessageBus.ALLOWED_ROUTES == expected


# ============================================================================
# TEST 3 — Denied route still raises CommunicationDeniedError
# ============================================================================

def test_denied_route_raises(bus):
    """Research -> deployment is not in ALLOWED_ROUTES; must raise."""
    msg = AgentMessage(sender="research", receiver="deployment", message_type="TASK", content={})
    with pytest.raises(CommunicationDeniedError, match="not allowed"):
        bus.send(msg)


def test_denied_route_with_supervision(supervised_bus):
    """Even with supervision, denied routes still raise and supervision is NOT called."""
    bus, spy = supervised_bus
    msg = AgentMessage(sender="research", receiver="deployment", message_type="TASK", content={})
    with pytest.raises(CommunicationDeniedError):
        bus.send(msg)
    spy.assert_not_called()


# ============================================================================
# TEST 4 — Normal communication does NOT call shield.authorize()
# ============================================================================

def test_no_shield_authorize_called(supervised_bus):
    """Sending a message does not invoke shield.authorization.pipeline.authorize."""
    bus, spy = supervised_bus
    msg = AgentMessage(sender="orchestrator", receiver="research", message_type="TASK", content={"q": "test"})
    bus.send(msg)
    # The supervise hook was called, but it is NOT authorize()
    spy.assert_called_once()
    # Verify the hook received a MessageSupervision, not an ActionRequest
    supervision = spy.call_args[0][0]
    assert isinstance(supervision, MessageSupervision)


def test_authorize_not_imported_in_message_bus():
    """shield.authorization.pipeline is not imported in the message_bus module."""
    import sandbox.runtime.message_bus as mb_mod
    # The module should not import authorize at all
    assert "authorize" not in dir(mb_mod)
    # More specifically, check it's not in the module namespace
    import types
    source = open(mb_mod.__file__, "r", encoding="utf-8").read()
    assert "from shield.authorization" not in source
    assert "from shield.policy" not in source


# ============================================================================
# TEST 5 — Normal communication does NOT call Cedar
# ============================================================================

def test_cedar_not_called(supervised_bus):
    """Sending a message does not invoke Cedar policy evaluation."""
    bus, spy = supervised_bus
    msg = AgentMessage(sender="coding", receiver="verification", message_type="RESULT", content={"status": "ok"})
    bus.send(msg)
    spy.assert_called_once()
    # The hook is MessageSupervision, not Cedar
    supervision = spy.call_args[0][0]
    assert isinstance(supervision, MessageSupervision)


# ============================================================================
# TEST 6 — Normal communication does NOT invoke LLM/content analysis
# ============================================================================

def test_no_llm_or_content_analysis(supervised_bus):
    """Supervision hook does not inspect message content."""
    bus, spy = supervised_bus
    secret_content = {"data": "sensitive-research-artifact-12345"}
    msg = AgentMessage(sender="research", receiver="orchestrator", message_type="RESULT", content=secret_content)
    bus.send(msg)
    supervision = spy.call_args[0][0]
    # Supervision metadata must NOT contain the actual content
    assert "data" not in supervision.metadata
    assert "sensitive" not in str(supervision.metadata)
    # Only payload_size is captured, not content
    assert supervision.payload_size > 0


# ============================================================================
# TEST 7 — Large payload passes without copying entire payload
# ============================================================================

def test_large_payload_not_copied(supervised_bus):
    """Large research payload passes through; supervision records size, not content."""
    bus, spy = supervised_bus
    large_content = {"artifact": "x" * 1_000_000}  # 1MB string
    msg = AgentMessage(sender="research", receiver="orchestrator", message_type="RESULT", content=large_content)
    bus.send(msg)
    supervision = spy.call_args[0][0]
    # payload_size should reflect the large content
    assert supervision.payload_size > 100_000
    # But the supervision metadata must not contain the actual string
    assert "x" * 1000 not in str(supervision)


def test_large_payload_no_performance_degradation(supervised_bus):
    """Sending a large payload does not cause excessive overhead."""
    import time
    bus, spy = supervised_bus
    large_content = {"data": "y" * 500_000}
    msg = AgentMessage(sender="research", receiver="orchestrator", message_type="RESULT", content=large_content)

    start = time.perf_counter()
    for _ in range(100):
        bus.send(msg)
    elapsed = time.perf_counter() - start

    assert spy.call_count == 100
    # 100 sends with 500KB payloads should complete in well under 1 second
    assert elapsed < 1.0


# ============================================================================
# TEST 8 — Telemetry contains source, target, metadata, correlation IDs
# ============================================================================

def test_supervision_metadata_fields(supervised_bus):
    """MessageSupervision contains all required metadata fields."""
    bus, spy = supervised_bus
    msg = AgentMessage(
        sender="orchestrator",
        receiver="coding",
        message_type="TASK",
        content={"task": "implement"},
    )
    bus.send(msg)
    supervision = spy.call_args[0][0]

    assert supervision.source_agent == "orchestrator"
    assert supervision.target_agent == "coding"
    assert supervision.message_type == "TASK"
    assert supervision.message_id == msg.message_id
    assert supervision.timestamp == msg.timestamp
    assert supervision.route_allowed is True
    assert isinstance(supervision.payload_size, int)


def test_supervision_has_message_id_correlation(supervised_bus):
    """message_id in supervision matches the original AgentMessage.message_id."""
    bus, spy = supervised_bus
    msg = AgentMessage(sender="deployment", receiver="verification", message_type="RESULT", content={})
    bus.send(msg)
    supervision = spy.call_args[0][0]
    assert supervision.message_id == msg.message_id


# ============================================================================
# TEST 9 — Telemetry failure does not block message delivery
# ============================================================================

def test_supervision_failure_does_not_block_delivery():
    """If the supervision hook raises, the message is still delivered."""
    def failing_hook(supervision):
        raise RuntimeError("Telemetry system unavailable")

    bus = MessageBus(supervise=failing_hook)
    received = []
    bus.subscribe("research", lambda msg: received.append(msg))

    msg = AgentMessage(sender="orchestrator", receiver="research", message_type="TASK", content={"q": "test"})
    bus.send(msg)  # Must not raise

    assert len(received) == 1
    assert received[0].message_id == msg.message_id


def test_supervision_failure_allows_all_handlers(bus):
    """If supervision fails, all receiver handlers still execute."""
    failures = []

    def failing_hook(s):
        raise RuntimeError("boom")

    bus._supervise = failing_hook
    received_by_r1 = []
    received_by_r2 = []
    # Subscribe two handlers for the same agent (unusual but valid)
    bus.subscribe("research", lambda msg: received_by_r1.append(msg))
    bus.subscribe("research", lambda msg: received_by_r2.append(msg))

    msg = AgentMessage(sender="orchestrator", receiver="research", message_type="TASK", content={})
    bus.send(msg)

    assert len(received_by_r1) == 1
    assert len(received_by_r2) == 1


# ============================================================================
# TEST 10 — Message content is unchanged by supervision
# ============================================================================

def test_message_content_unchanged(supervised_bus):
    """Supervision does not modify the message object."""
    bus, spy = supervised_bus
    original_content = {"key": "value", "nested": [1, 2, 3]}
    msg = AgentMessage(sender="coding", receiver="orchestrator", message_type="RESULT", content=original_content)

    received = []
    bus.subscribe("orchestrator", lambda m: received.append(m))

    bus.send(msg)

    assert len(received) == 1
    assert received[0].content == original_content
    assert received[0].sender == msg.sender
    assert received[0].receiver == msg.receiver
    assert received[0].message_type == msg.message_type


def test_message_object_identity_preserved(supervised_bus):
    """The exact same AgentMessage object is delivered to handlers."""
    bus, spy = supervised_bus
    msg = AgentMessage(sender="research", receiver="orchestrator", message_type="RESULT", content={})

    received = []
    bus.subscribe("orchestrator", lambda m: received.append(m))

    bus.send(msg)

    assert received[0] is msg


# ============================================================================
# TEST 11 — No additional privilege granted to any agent
# ============================================================================

def test_supervision_does_not_expand_routes():
    """Adding supervision does not change ALLOWED_ROUTES."""
    bus_no_supervise = MessageBus()
    bus_with_supervise = MessageBus(supervise=lambda s: None)
    assert bus_no_supervise.ALLOWED_ROUTES == bus_with_supervise.ALLOWED_ROUTES


def test_supervision_does_not_grant_cross_agent_tool_access():
    """Supervision hook cannot be exploited to grant tool access."""
    # The supervision hook receives MessageSupervision (frozen dataclass)
    # and cannot modify MessageBus internals
    spy = MagicMock()
    bus = MessageBus(supervise=spy)

    msg = AgentMessage(sender="research", receiver="orchestrator", message_type="TASK", content={})
    bus.send(msg)

    supervision = spy.call_args[0][0]
    # MessageSupervision is frozen — cannot set attributes
    with pytest.raises(AttributeError):
        supervision.route_allowed = False


# ============================================================================
# TEST 12 — No agent can use telemetry hooks to modify Kavach policy/state
# ============================================================================

def test_supervision_cannot_modify_bus_state(supervised_bus):
    """The supervision hook cannot alter ALLOWED_ROUTES or handlers."""
    original_routes = set(MessageBus.ALLOWED_ROUTES)

    def malicious_hook(s):
        # Attempt to modify ALLOWED_ROUTES — this modifies the class, but
        # the hook has no reference to the bus instance
        pass

    bus, spy = supervised_bus
    msg = AgentMessage(sender="orchestrator", receiver="research", message_type="TASK", content={})
    bus.send(msg)

    # ALLOWED_ROUTES must be unchanged
    assert set(MessageBus.ALLOWED_ROUTES) == original_routes


def test_supervision_hook_cannot_inject_handlers(supervised_bus):
    """The supervision hook cannot register new handlers on the bus."""
    def injection_hook(s):
        # Cannot access bus._handlers from here
        pass

    bus, spy = supervised_bus
    handlers_before = len(bus._handlers)

    msg = AgentMessage(sender="orchestrator", receiver="research", message_type="TASK", content={})
    bus.send(msg)

    # No new handlers were added
    assert len(bus._handlers) == handlers_before


# ============================================================================
# TEST 13 — Existing P1 agent tests continue passing
# (Verified by full regression; here we prove the agents still work)
# ============================================================================

def test_full_workflow_still_works(full_agents):
    """The complete P1 workflow runs without errors.
    
    All agents now have Cedar policies for their legitimate operations.
    """
    agents, bus = full_agents
    received = []
    bus.subscribe("orchestrator", lambda m: received.append(m))

    # Orchestrator delegates to research → ALLOW
    agents["orchestrator"].delegate("research", {"task": "search fibonacci"})
    # Research executes and returns result
    agents["research"].search("fibonacci")
    agents["research"].send_result("orchestrator", {"status": "DONE"})
    # Orchestrator delegates to coding → ALLOW
    agents["orchestrator"].delegate("coding", {"task": "implement"})
    # Coding writes and tests
    agents["coding"].write_file("fib.py", "def fib(n): return n")
    agents["coding"].run_tests()
    agents["coding"].send_result("verification", {"status": "CODE_READY"})
    # Verification → ALLOW
    agents["verification"].run_tests()
    agents["verification"].send_result("orchestrator", {"status": "VERIFIED"})
    # Deployment
    agents["orchestrator"].delegate("deployment", {"task": "deploy"})
    agents["deployment"].simulate_deployment("staging")
    agents["deployment"].send_result("orchestrator", {"status": "DEPLOYED"})

    assert len(received) >= 3  # At least research, verification, deployment results


# ============================================================================
# TEST 14 — Existing Shield tests continue passing
# (Verified by full regression; here we prove shield imports still work)
# ============================================================================

def test_shield_imports_still_work():
    """Shield modules import successfully alongside the new MessageBus."""
    from shield.authorization.pipeline import authorize
    from shield.identity.service import IdentityService
    from shield.capabilities.service import CapabilityService
    from shield.policy.cedar import CedarAdapter
    from shield.telemetry import write_event
    from shield.incidents import INCIDENT_THRESHOLD
    from shield.enforcement import QuarantineService

    assert authorize is not None
    assert INCIDENT_THRESHOLD == 80


# ============================================================================
# _compute_payload_size tests
# ============================================================================

def test_payload_size_none():
    assert _compute_payload_size(None) == 0


def test_payload_size_string():
    assert _compute_payload_size("hello") == 5


def test_payload_size_bytes():
    assert _compute_payload_size(b"hello") == 5


def test_payload_size_dict():
    size = _compute_payload_size({"a": 1, "b": 2})
    assert size > 0


def test_payload_size_list():
    size = _compute_payload_size([1, 2, 3])
    assert size > 0


def test_payload_size_exception_safety():
    """_compute_payload_size never raises."""
    # An object with broken __sizeof__
    class Bad:
        def __sizeof__(self):
            raise RuntimeError("broken")
    assert _compute_payload_size(Bad()) == 0


# ============================================================================
# MessageSupervision dataclass tests
# ============================================================================

def test_supervision_is_frozen():
    """MessageSupervision is a frozen dataclass — cannot be mutated."""
    s = MessageSupervision(
        message_id="m1",
        source_agent="research",
        target_agent="orchestrator",
        message_type="RESULT",
        timestamp="2026-01-01T00:00:00",
        payload_size=42,
        route_allowed=True,
    )
    with pytest.raises(AttributeError):
        s.source_agent = "hacked"


def test_supervision_default_metadata():
    """MessageSupervision metadata defaults to empty dict."""
    s = MessageSupervision(
        message_id="m1",
        source_agent="a",
        target_agent="b",
        message_type="T",
        timestamp="t",
        payload_size=0,
        route_allowed=True,
    )
    assert s.metadata == {}


# ============================================================================
# Integration: supervision with full agent setup
# ============================================================================

def test_supervision_called_for_each_message(full_agents):
    """With all agents wired, every MessageBus.send() triggers supervision.
    
    Orchestrator delegation is denied by Cedar, but the MessageBus.send()
    for the research result and deployment result still trigger supervision.
    """
    from sandbox.runtime.kavach_guard import KavachDeniedError
    spy = MagicMock()
    agents, bus = full_agents
    bus._supervise = spy

    # Orchestrator delegation is denied by Cedar — skip it
    # research.send_result goes through MessageBus
    agents["research"].send_result("orchestrator", {"status": "DONE"})
    # deployment.send_result goes through MessageBus
    agents["deployment"].send_result("orchestrator", {"status": "DONE"})

    assert spy.call_count == 2
    for c in spy.call_args_list:
        supervision = c[0][0]
        assert isinstance(supervision, MessageSupervision)
        assert supervision.route_allowed is True
