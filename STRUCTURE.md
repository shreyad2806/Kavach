# Kavach — Project Structure & Architectural Guidelines

Kavach provides **Zero-Trust Runtime Security for Autonomous Systems**.

---

## Core Architectural Principles

1. **Authority Separation**:
   - **Agents execute tasks.**
   - **Kavach owns security authority.**
2. **Agent Boundary Restrictions**:
   Autonomous agents must **NEVER** be able to:
   - Modify Kavach policies
   - Modify security state
   - Disable enforcement
   - Change security thresholds
   - Invoke quarantine or kill controls
   - Directly write to security databases
3. **Deterministic Enforcement Path**:
   No LLM is permitted on the authorization/enforcement critical path. Any future AI analysis is purely advisory and will never override deterministic policy evaluations.
   ```
   Agent
     │
     ▼
   Kavach Gateway
     │
     ▼
   Identity
     │
     ▼
   Capability
     │
     ▼
   Provenance
     │
     ▼
   Cedar Policy
     │
     ▼
   Deterministic Security Rules
     │
     ▼
   ALLOW / DENY
     │
     ▼
   Target Agent / Tool
   ```
4. **Independent Telemetry Path**:
   ```
   Agent / Runtime
     │
     ▼
   Structured Security Events
     │
     ▼
   CloudWatch / EventBridge
     │
     ▼
   Kavach Security Monitoring
   ```

---

## Directory & File Overview

### `architecture/`
Architectural blueprints, threat models, security contracts, and attack test scenarios.
- `architecture.md`: High-level system architecture and interaction topologies.
- `threat-model.md`: STRIDE/threat modeling across agents, tools, and gateways.
- `security-model.md`: Formal zero-trust security invariants and access control boundaries.
- `attack-scenarios.md`: Catalog of threat scenarios (prompt injection, privilege escalation, unauthorized lateral tool invocation, data exfiltration).

### `agents/`
Autonomous agents participating in the multi-agent workflow. Agents focus strictly on domain execution and possess no administrative or policy privileges.
- `orchestrator/`: Directs top-level workflow and delegates tasks (`agent.py`, `tools.py`, `prompts.py`, `config.yaml`).
- `research/`: Information gathering and analysis agent (`agent.py`, `tools.py`, `prompts.py`, `config.yaml`).
- `coding/`: Code generation and modification agent (`agent.py`, `tools.py`, `config.yaml`).
- `deployment/`: CI/CD and deployment staging agent (`agent.py`, `tools.py`, `config.yaml`).
- `verification/`: Automated testing, linting, and verification agent (`agent.py`, `tools.py`, `config.yaml`).
- `common/`: Shared inter-agent message formats, identity schemas, and payload definitions (`messages.py`, `identity.py`, `schemas.py`).

### `kavach/`
The core security kernel and zero-trust runtime engine. All authority resides here.
- `gateway/`: Intercepts, routes, and validates all agent-to-agent and agent-to-tool calls (`router.py`, `interceptor.py`, `validator.py`).
- `identity/`: Agent cryptographic identity verification, SPIFFE/mTLS or token issuance (`service.py`, `models.py`).
- `capabilities/`: Ephemeral capability token management and tool registry (`service.py`, `registry.py`).
- `provenance/`: Execution provenance tracking, DAG validation, and causal lineage (`validator.py`, `graph.py`).
- `policy/`: Cedar policy evaluator and schema definitions (`engine.py`, `cedar/agents.cedar`, `cedar/capabilities.cedar`, `cedar/deployment.cedar`, `schemas/`).
- `detection/`: Real-time behavioral anomaly detection and rule checking (`rules.py`, `anomaly.py`, `signals.py`).
- `enforcement/`: Deterministic response mechanisms for policy violations or attacks (`blocker.py`, `revocation.py`, `quarantine.py`, `kill.py`).
- `incidents/`: Security incident aggregation and management (`service.py`, `models.py`).
- `telemetry/`: Structured audit log publishing and security event streaming (`events.py`, `publisher.py`, `audit.py`).

### `api/`
Administrative control plane and dashboard REST API (isolated from agent execution).
- `main.py`: Application entry point.
- `routes/`: Endpoints for managing agents, policies, security events, incidents, and dashboard telemetry (`agents.py`, `policies.py`, `events.py`, `incidents.py`, `dashboard.py`).
- `middleware/`: Authentication and request validation middleware (`auth.py`, `validation.py`).

### `infrastructure/`
AWS CloudFormation / SAM infrastructure templates.
- `template.yaml`: Main infrastructure orchestration template.
- `dynamodb.yaml`: Security policy and state persistence tables.
- `iam.yaml`: Zero-trust IAM roles, enforcing least privilege for agent runners.
- `eventbridge.yaml`: Security event routing bus configuration.
- `stepfunctions.yaml`: Orchestrated incident response workflows.
- `cloudwatch.yaml`: Metric alarms and log stream configurations.

### `frontend/`
Security operations center (SOC) and real-time observability dashboard.

### `tests/`
Test suites organized by test category:
- `unit/`: Unit tests for individual components.
- `policy/`: Cedar policy and rule evaluation unit tests.
- `integration/`: Gateway and pipeline integration tests.
- `attack/`: Simulated attack scenarios (jailbreaks, capability hijacking).
- `security/`: Invariant testing and regression suites for security controls.

### `scripts/`
Operational and demonstration scripts:
- `seed_agents.py`: Register initial agent identities.
- `seed_policies.py`: Load baseline Cedar security policies.
- `run_attack.py`: Execute simulated attack vectors to test detection and enforcement.
- `reset_demo.py`: Reset test environment and state for demos.
