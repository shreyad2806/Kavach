"""
Kavach HTTP Gateway — FastAPI Application (Phase 21D).

Exposes:
  - /health
  - /authorize          (existing — preserved)
  - /workflows          (Phase 21D)
  - /agents             (Phase 21D)
  - /incidents          (Phase 21D)
  - /events             (Phase 21D)
  - /dashboard          (Phase 21D)
  - /policies           (Phase 21D — read-only)

All security state is owned by the shared ShieldRuntime singleton.
All workflow state is owned by the shared WorkflowRegistry singleton.
No security services are constructed per-request.
"""

import asyncio
import json
import os
from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel


async def require_api_key(x_api_key: str = Header(default="")):
    expected = os.environ.get("API_KEY", "")
    # When API_KEY env var is not set, auth is disabled (local dev / tests)
    if expected and x_api_key != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")

from agents.supervisor.registry import WorkflowRegistry, get_registry
from agents.supervisor.workflow import WorkflowStatus
from sandbox.runtime.kavach_guard import configure_all_guards
from shield.api.models import (
    AgentResponse,
    AgentStateResponse,
    CreateWorkflowRequest,
    DashboardResponse,
    IncidentResponse,
    PolicyResponse,
    SecurityEventResponse,
    WorkflowEventsResponse,
    WorkflowEventResponse,
    WorkflowResponse,
)
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
from shield.policy.cedar.engine import _POLICIES_PATH
from shield.capabilities.registry import ACTION_CAPABILITY_MAP
from shield.provenance.models import Provenance
from shield.runtime.services import ShieldRuntime, get_runtime
from shield.telemetry.events import get_audit_log_path


# ============================================================================
# Startup — wire module-level KavachGuards to shared runtime
# ============================================================================

_runtime = get_runtime()
configure_all_guards(_runtime)


# ============================================================================
# FastAPI Application
# ============================================================================

app = FastAPI(
    title="Kavach Authorization Gateway",
    description="HTTP gateway for Kavach authorization pipeline and P1 workflow",
    version="2.0.0",
    dependencies=[Depends(require_api_key)],
)


# ============================================================================
# Dependency providers — always return the shared singletons
# ============================================================================

def get_identity_service() -> IdentityService:
    """Backward-compatible dependency — returns the shared runtime's IdentityService."""
    return get_runtime().identity_service


def get_shield_runtime() -> ShieldRuntime:
    return get_runtime()


def get_workflow_registry() -> WorkflowRegistry:
    return get_registry()


# ============================================================================
# Existing: /health
# ============================================================================

class HealthResponse(BaseModel):
    status: str


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    return HealthResponse(status="ok")


# ============================================================================
# Existing: /authorize  (preserved exactly)
# ============================================================================

class AuthorizeRequest(BaseModel):
    source_agent: str
    target_agent: str
    task_id: str
    action: str
    resource: str
    claimed_authority: str
    capability: str
    provenance: dict[str, list[str] | str]

    def to_action_request(self) -> ActionRequest:
        provenance_data = self.provenance
        task_origin = AgentId(provenance_data["task_origin"])
        delegation_chain = [AgentId(a) for a in provenance_data["delegation_chain"]]
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


@app.post("/authorize", response_model=AuthorizationResult)
async def authorize_request(
    request: AuthorizeRequest,
    identity_service: Annotated[IdentityService, Depends(get_identity_service)],
) -> AuthorizationResult:
    try:
        action_request = request.to_action_request()
        # Use the injected identity_service (supports dependency_overrides in tests)
        # while keeping other services from the shared runtime
        runtime = get_runtime()
        from shield.authorization.pipeline import authorize as _authorize
        return _authorize(
            action_request,
            identity_service=identity_service,
            capability_service=runtime.capability_service,
            cedar_adapter=runtime.cedar_adapter,
            incident_service=runtime.incident_service,
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


# ============================================================================
# Workflows
# ============================================================================

@app.post("/workflows", response_model=WorkflowResponse, status_code=201)
async def create_workflow(
    body: CreateWorkflowRequest,
    registry: Annotated[WorkflowRegistry, Depends(get_workflow_registry)],
    runtime: Annotated[ShieldRuntime, Depends(get_shield_runtime)],
) -> WorkflowResponse:
    wf = registry.create(task=body.task, runtime=runtime)
    snap = wf.snapshot()
    return WorkflowResponse(
        workflow_id=snap.workflow_id,
        task=snap.task,
        status=snap.status.value,
        created_at=snap.created_at,
    )


@app.get("/workflows/{workflow_id}", response_model=WorkflowResponse)
async def get_workflow(
    workflow_id: str,
    registry: Annotated[WorkflowRegistry, Depends(get_workflow_registry)],
) -> WorkflowResponse:
    wf = registry.get(workflow_id)
    if wf is None:
        raise HTTPException(status_code=404, detail=f"Workflow '{workflow_id}' not found")
    snap = wf.snapshot()
    return WorkflowResponse(
        workflow_id=snap.workflow_id,
        task=snap.task,
        status=snap.status.value,
        created_at=snap.created_at,
        started_at=snap.started_at,
        completed_at=snap.completed_at,
        error=snap.error,
        steps_completed=snap.steps_completed,
    )


@app.post("/workflows/{workflow_id}/start", response_model=WorkflowResponse)
async def start_workflow(
    workflow_id: str,
    registry: Annotated[WorkflowRegistry, Depends(get_workflow_registry)],
) -> WorkflowResponse:
    wf = registry.get(workflow_id)
    if wf is None:
        raise HTTPException(status_code=404, detail=f"Workflow '{workflow_id}' not found")
    if wf.status != WorkflowStatus.CREATED:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot start workflow in state '{wf.status.value}'",
        )
    try:
        await asyncio.to_thread(wf.start)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Workflow execution error: {str(e)}")
    snap = wf.snapshot()
    return WorkflowResponse(
        workflow_id=snap.workflow_id,
        task=snap.task,
        status=snap.status.value,
        created_at=snap.created_at,
        started_at=snap.started_at,
        completed_at=snap.completed_at,
        error=snap.error,
        steps_completed=snap.steps_completed,
    )


@app.post("/workflows/{workflow_id}/stop", response_model=WorkflowResponse)
async def stop_workflow(
    workflow_id: str,
    registry: Annotated[WorkflowRegistry, Depends(get_workflow_registry)],
) -> WorkflowResponse:
    wf = registry.get(workflow_id)
    if wf is None:
        raise HTTPException(status_code=404, detail=f"Workflow '{workflow_id}' not found")
    wf.stop()
    snap = wf.snapshot()
    return WorkflowResponse(
        workflow_id=snap.workflow_id,
        task=snap.task,
        status=snap.status.value,
        created_at=snap.created_at,
        started_at=snap.started_at,
        completed_at=snap.completed_at,
        error=snap.error,
        steps_completed=snap.steps_completed,
    )


@app.get("/workflows/{workflow_id}/events", response_model=WorkflowEventsResponse)
async def get_workflow_events(
    workflow_id: str,
    registry: Annotated[WorkflowRegistry, Depends(get_workflow_registry)],
) -> WorkflowEventsResponse:
    wf = registry.get(workflow_id)
    if wf is None:
        raise HTTPException(status_code=404, detail=f"Workflow '{workflow_id}' not found")
    return WorkflowEventsResponse(
        workflow_id=workflow_id,
        events=[
            WorkflowEventResponse(
                event_id=e.event_id,
                workflow_id=e.workflow_id,
                timestamp=e.timestamp.isoformat() if hasattr(e.timestamp, 'isoformat') else str(e.timestamp),
                step=e.event_type.value,
                status=e.event_type.value,
                detail=str(e.detail) if e.detail else "",
            )
            for e in wf.get_events()
        ],
    )


# ============================================================================
# Agents
# ============================================================================

@app.get("/agents", response_model=list[AgentResponse])
async def list_agents(
    runtime: Annotated[ShieldRuntime, Depends(get_shield_runtime)],
) -> list[AgentResponse]:
    return [
        AgentResponse(
            agent_id=a.agent_id.value,
            role=a.role.value,
            state=a.state.value,
        )
        for a in runtime.identity_service.list_agents()
    ]


@app.get("/agents/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: str,
    runtime: Annotated[ShieldRuntime, Depends(get_shield_runtime)],
) -> AgentResponse:
    agent = runtime.identity_service.get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    return AgentResponse(
        agent_id=agent.agent_id.value,
        role=agent.role.value,
        state=agent.state.value,
    )


@app.post("/agents/{agent_id}/isolate", response_model=AgentStateResponse)
async def isolate_agent(
    agent_id: str,
    runtime: Annotated[ShieldRuntime, Depends(get_shield_runtime)],
) -> AgentStateResponse:
    try:
        runtime.quarantine_service.quarantine(agent_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    return AgentStateResponse(agent_id=agent_id, state="QUARANTINED")


@app.post("/agents/{agent_id}/restore", response_model=AgentStateResponse)
async def restore_agent(
    agent_id: str,
    runtime: Annotated[ShieldRuntime, Depends(get_shield_runtime)],
) -> AgentStateResponse:
    try:
        runtime.quarantine_service.release(agent_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    return AgentStateResponse(agent_id=agent_id, state="ACTIVE")


# ============================================================================
# Incidents
# ============================================================================

@app.get("/incidents", response_model=list[IncidentResponse])
async def list_incidents(
    runtime: Annotated[ShieldRuntime, Depends(get_shield_runtime)],
) -> list[IncidentResponse]:
    return [
        IncidentResponse(
            incident_id=i.incident_id,
            timestamp=i.timestamp.isoformat(),
            agent_id=i.agent_id.value,
            severity=i.severity.value,
            status=i.status.value,
            reason_codes=[r.value for r in i.reason_codes],
            request_ids=i.request_ids,
            description=i.description,
        )
        for i in runtime.incident_service.list_all()
    ]


@app.get("/incidents/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: str,
    runtime: Annotated[ShieldRuntime, Depends(get_shield_runtime)],
) -> IncidentResponse:
    incident = runtime.incident_service.get(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    return IncidentResponse(
        incident_id=incident.incident_id,
        timestamp=incident.timestamp.isoformat(),
        agent_id=incident.agent_id.value,
        severity=incident.severity.value,
        status=incident.status.value,
        reason_codes=[r.value for r in incident.reason_codes],
        request_ids=incident.request_ids,
        description=incident.description,
    )


@app.patch("/incidents/{incident_id}/resolve")
async def resolve_incident(
    incident_id: str,
    runtime: Annotated[ShieldRuntime, Depends(get_shield_runtime)],
):
    from shield.incidents.models import IncidentStatus
    try:
        runtime.incident_service.update_status(incident_id, IncidentStatus.RESOLVED)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    return {"incident_id": incident_id, "status": IncidentStatus.RESOLVED.value}


# ============================================================================
# Events — reads from the Shield audit log JSONL file
# ============================================================================

@app.get("/events", response_model=list[SecurityEventResponse])
async def list_events(limit: int = 100) -> list[SecurityEventResponse]:
    path = get_audit_log_path()
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    events: list[SecurityEventResponse] = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            events.append(SecurityEventResponse(
                event_id=data.get("event_id", ""),
                timestamp=data.get("timestamp", ""),
                event_type=data.get("event_type", ""),
                source_agent=data.get("source_agent", ""),
                target_agent=data.get("target_agent", ""),
                request_id=data.get("request_id", ""),
                task_id=data.get("task_id", ""),
                action=data.get("action", ""),
                resource=data.get("resource", ""),
                policy_decision=data.get("policy_decision", ""),
                reason_codes=data.get("reason_codes", []),
                risk_score=data.get("risk_score"),
            ))
        except (json.JSONDecodeError, Exception):
            continue
        if len(events) >= limit:
            break
    return events


# ============================================================================
# Dashboard — read-only projection of authoritative state
# ============================================================================

@app.get("/dashboard", response_model=DashboardResponse)
async def dashboard(
    runtime: Annotated[ShieldRuntime, Depends(get_shield_runtime)],
    registry: Annotated[WorkflowRegistry, Depends(get_workflow_registry)],
) -> DashboardResponse:
    agents = runtime.identity_service.list_agents()
    agent_by_state: dict[str, int] = {}
    for a in agents:
        agent_by_state[a.state.value] = agent_by_state.get(a.state.value, 0) + 1

    workflows = registry.list_all()
    wf_by_status: dict[str, int] = {}
    for wf in workflows:
        wf_by_status[wf.status.value] = wf_by_status.get(wf.status.value, 0) + 1

    incidents = runtime.incident_service.list_all()
    inc_by_status: dict[str, int] = {}
    for i in incidents:
        inc_by_status[i.status.value] = inc_by_status.get(i.status.value, 0) + 1

    # Event counts from audit log (last 200 lines)
    path = get_audit_log_path()
    allow_count = deny_count = 0
    if path.exists():
        lines = path.read_text(encoding="utf-8").splitlines()
        for line in lines[-200:]:
            try:
                data = json.loads(line)
                if data.get("policy_decision") == "ALLOW":
                    allow_count += 1
                elif data.get("policy_decision") == "DENY":
                    deny_count += 1
            except Exception:
                continue

    return DashboardResponse(
        agents=agent_by_state,
        workflows=wf_by_status,
        incidents=inc_by_status,
        events={"ALLOW": allow_count, "DENY": deny_count, "total": allow_count + deny_count},
    )


# ============================================================================
# Policies — read-only
# ============================================================================

@app.get("/policies", response_model=PolicyResponse)
async def get_policies() -> PolicyResponse:
    cedar_text = ""
    if _POLICIES_PATH.exists():
        cedar_text = _POLICIES_PATH.read_text(encoding="utf-8")
    capability_map = {
        action.value: cap.value
        for action, cap in ACTION_CAPABILITY_MAP.items()
    }
    return PolicyResponse(
        cedar_policies=cedar_text,
        action_capability_map=capability_map,
        note="Read-only. Cedar policies cannot be modified via HTTP.",
    )
