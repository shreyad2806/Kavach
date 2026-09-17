from shield.gateway.models import AuthorizationResult


result = AuthorizationResult(
    request_id="req-attack-001",
    decision="DENY",
    reason_codes=[
        "CAPABILITY_MISMATCH",
        "AUTHORITY_MISMATCH",
    ],
    risk_score=94,
    agent_state="ACTIVE",
)

print(result)