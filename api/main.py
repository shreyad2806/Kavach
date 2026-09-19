"""Kavach unified local backend — ONE integrated Python process.

This is the single HTTP control plane the Node BFF proxies to (api.main on
:8000).  It owns the real P1 runtime end to end:

    WorkflowSupervisor  (real P1 agents)
    MessageBus
    KavachGuard
    ShieldRuntime  <- get_shield_runtime(), the ONE authoritative state
    IdentityService / QuarantineService / IncidentService
    Shield HTTP API (/authorize)

Critical invariant: HTTP quarantine and the real P1 AgentTools share the SAME
ShieldRuntime, so

    HTTP isolate -> QuarantineService -> get_shield_runtime().identity_service
    real P1 tool -> KavachGuard -> get_shield_runtime() -> authorize() -> DENY

There is no second, process-local Shield state.  No service is instantiated
per-request; routes resolve everything from the shared runtime (see api.deps).

Run locally:
    uvicorn api.main:app --host 0.0.0.0 --port 8000
"""

from fastapi import FastAPI

from api.routes.agents import router as agents_router
from api.routes.artifacts import router as artifacts_router
from api.routes.dashboard import router as dashboard_router
from api.routes.events import router as events_router
from api.routes.incidents import router as incidents_router
from api.routes.policies import router as policies_router
from api.routes.workflows import router as workflows_router
from shield.api.app import router as authorize_router

app = FastAPI(
    title="Kavach Unified Backend",
    description="Integrated local control plane for the Kavach P1 runtime and Shield",
    version="1.0.0",
)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


# Shield authorization gateway (reused verbatim — one implementation of /authorize).
app.include_router(authorize_router)

# Control plane.
app.include_router(agents_router, prefix="/agents", tags=["agents"])
app.include_router(workflows_router, prefix="/workflows", tags=["workflows"])
app.include_router(events_router, prefix="/events", tags=["events"])
app.include_router(incidents_router, prefix="/incidents", tags=["incidents"])
app.include_router(dashboard_router, prefix="/dashboard", tags=["dashboard"])
app.include_router(policies_router, prefix="/policies", tags=["policies"])

# Scanner gateway (separate concern; AWS-backed, requires x-api-key).
app.include_router(artifacts_router, prefix="/artifacts", tags=["artifacts"])
