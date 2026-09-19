"""
Kavach HTTP Gateway - FastAPI Application.

Exposes the Kavach authorization pipeline through HTTP endpoints.
"""

from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from shield.authorization.pipeline import authorize
from shield.capabilities.models import CapabilityName
from shield.gateway.models import (
    ActionName,
    ActionRequest,
    AuthorizationResult,
    ResourceName,
)
from shield.identity.models import AgentId
from shield.identity.service import IdentityService
from shield.provenance.models import Provenance
from shield.runtime.services import get_shield_runtime


# ============================================================================
# Application Service Dependencies
# ============================================================================

_default_identity_service = get_shield_runtime().identity_service


def get_identity_service() -> IdentityService:
    """Dependency provider for IdentityService."""
    return _default_identity_service


# ============================================================================
# FastAPI Application
# ============================================================================

app = FastAPI(
    title="Kavach Authorization Gateway",
    description="HTTP gateway for Kavach authorization pipeline",
    version="1.0.0",
)


# ============================================================================
# Request/Response Models
# ============================================================================

class AuthorizeRequest(BaseModel):
    """HTTP request model for /authorize endpoint."""
    
    source_agent: str
    target_agent: str
    task_id: str
    action: str
    resource: str
    claimed_authority: str
    capability: str
    provenance: dict[str, list[str] | str]
    
    def to_action_request(self) -> ActionRequest:
        """Convert HTTP request to ActionRequest."""
        provenance_data = self.provenance
        task_origin = AgentId(provenance_data["task_origin"])
        delegation_chain = [AgentId(agent) for agent in provenance_data["delegation_chain"]]
        
        return ActionRequest(
            request_id=f"http-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
            timestamp=datetime.now(timezone.utc),
            source_agent=AgentId(self.source_agent),
            target_agent=AgentId(self.target_agent),
            task_id=self.task_id,
            action=ActionName(self.action),
            resource=ResourceName(self.resource),
            claimed_authority=AgentId(self.claimed_authority),
            capability=CapabilityName(self.capability),
            provenance=Provenance(
                task_origin=task_origin,
                delegation_chain=delegation_chain,
            ),
        )


# ============================================================================
# Health Endpoint
# ============================================================================

class HealthResponse(BaseModel):
    """Health check response."""
    status: str


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Health check endpoint."""
    return HealthResponse(status="ok")


# ============================================================================
# Authorize Endpoint
# ============================================================================

@app.post("/authorize", response_model=AuthorizationResult)
async def authorize_request(
    request: AuthorizeRequest,
    identity_service: Annotated[IdentityService, Depends(get_identity_service)],
) -> AuthorizationResult:
    """
    Authorize an action request.
    
    This endpoint accepts an ActionRequest via HTTP, validates it,
    passes it through the Kavach authorization pipeline, and returns
    the Decision (AuthorizationResult).
    
    The API layer does NOT implement any authorization logic.
    All security decisions come from the Kavach authorize() function.
    """
    try:
        # Convert HTTP request to ActionRequest
        action_request = request.to_action_request()
        
        # Call the unchanged Kavach authorization pipeline with the same
        # long-lived runtime dependencies used by P1 guards and quarantine.
        runtime = get_shield_runtime()
        decision = authorize(
            action_request,
            identity_service=identity_service,
            capability_service=runtime.capability_service,
            cedar_adapter=runtime.cedar_adapter,
            incident_service=runtime.incident_service,
        )
        
        return decision
    except ValueError as e:
        # Invalid enum value
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        # Unexpected error
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")
