from fastapi import FastAPI
from kavach_logger import get_logger

from api.routes.agents import router as agents_router
from api.routes.artifacts import router as artifacts_router
from api.routes.dashboard import router as dashboard_router
from api.routes.events import router as events_router
from api.routes.incidents import router as incidents_router
from api.routes.policies import router as policies_router

log = get_logger("kavach.api")

app = FastAPI(title="Kavach API", version="1.0.0")


@app.on_event("startup")
async def _startup():
    log.info("Kavach API starting up")


@app.on_event("shutdown")
async def _shutdown():
    log.info("Kavach API shutting down")


@app.get("/health")
async def health():
    log.debug("health check")
    return {"status": "ok"}


app.include_router(artifacts_router, prefix="/artifacts")
app.include_router(agents_router, prefix="/agents")
app.include_router(incidents_router, prefix="/incidents")
app.include_router(events_router, prefix="/events")
app.include_router(policies_router, prefix="/policies")
app.include_router(dashboard_router, prefix="/dashboard")
