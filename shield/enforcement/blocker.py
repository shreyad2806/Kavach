"""
Blocker — synchronous enforcement gate.
Checks agent state before allowing a request to proceed.
"""

from kavach.gateway.models import (
    ActionRequest,
    AuthorizationChecks,
    AuthorizationDecision,
    AuthorizationResult,
    ReasonCode,
)
from kavach.identity.models import SecurityState
from kavach.identity.service import IdentityService

_BLOCKED_STATES = {SecurityState.QUARANTINED, SecurityState.TERMINATED}


class Blocker:
    def __init__(self, identity_service: IdentityService) -> None:
        self._identity = identity_service

    def is_blocked(self, request: ActionRequest) -> AuthorizationResult | None:
        """
        Returns a DENY AuthorizationResult if the agent is in a blocked state,
        otherwise returns None (proceed normally).
        """
        agent = self._identity.get_agent(request.source_agent)
        if agent is None:
            return AuthorizationResult(
                request_id=request.request_id,
                decision=AuthorizationDecision.DENY,
                reason_codes=[ReasonCode.IDENTITY_FAILURE],
                risk_score=100,
                checks=AuthorizationChecks(identity=False),
                agent_state=SecurityState.TERMINATED,
            )
        if agent.state in _BLOCKED_STATES:
            reason = (
                ReasonCode.AGENT_QUARANTINED
                if agent.state == SecurityState.QUARANTINED
                else ReasonCode.IDENTITY_FAILURE
            )
            return AuthorizationResult(
                request_id=request.request_id,
                decision=AuthorizationDecision.DENY,
                reason_codes=[reason],
                risk_score=100,
                checks=AuthorizationChecks(identity=True),
                agent_state=agent.state,
            )
        return None
