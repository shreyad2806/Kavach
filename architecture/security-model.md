# Kavach Security Model

## 1. Security Boundary

Kavach operates as an **external runtime security control plane** that sits strictly outside the trust boundary of autonomous agents.

Autonomous agents execute tasks and generate requests, but possess zero security authority. All interactions—whether agent-to-agent communication or agent-to-tool/resource invocations—are intercepted and mediated by the Kavach Gateway.

Agents are untrusted and must never have the ability to:
- Modify or tamper with Kavach policies
- Mutate or forge security state
- Disable or bypass runtime enforcement
- Modify security thresholds or detection parameters
- Trigger administrative quarantine or termination controls
- Directly read or write to Kavach security databases and internal stores

---

## 2. Agents

The system defines exactly five logical agents. Agent identity is cryptographically and structurally distinct from role and permissions. Knowing who an agent is does not grant permissions; capabilities must be explicitly assigned to an agent identity.

| Agent Name | Role & Purpose | Capability Scope Boundary |
| :--- | :--- | :--- |
| **`orchestrator-01`** | Coordinates high-level workflows and delegates subtasks to specialized agents. | Authorized strictly to coordinate and delegate. Does **not** inherit capabilities of downstream agents. |
| **`research-01`** | Performs data gathering, web/document queries, and information retrieval. | Authorized strictly for search and read operations within research contexts. |
| **`coding-01`** | Reads, edits, and writes source code; runs local development test suites. | Authorized strictly for reading, writing, and testing code within development workspaces. |
| **`deployment-01`** | Executes deployment preparation, previewing, and production release workflows. | **Sole** agent authorized to interact with deployment and staging/production targets. |
| **`verification-01`** | Runs verification routines, compliance validations, and independent testing. | Authorized strictly to execute automated verification and test routines. |

*Phase 1 Note: Agents are specified for security modeling only. No agent execution logic is implemented in this phase.*

---

## 3. Capabilities

A **capability** defines what an agent is formally authorized to possess and invoke according to Kavach's capability registry. Capabilities are explicitly assigned; "role" does not automatically grant permissions.

### Exact Capability Vocabulary

- `research.search`
- `research.read`
- `coding.read`
- `coding.write`
- `coding.test`
- `deployment.preview`
- `deployment.production`
- `verification.test`
- `orchestrator.delegate`
- `orchestrator.coordinate`

### Initial Agent-to-Capability Mapping

| Agent Identity | Assigned Capabilities |
| :--- | :--- |
| **`orchestrator-01`** | `orchestrator.delegate`, `orchestrator.coordinate` |
| **`research-01`** | `research.search`, `research.read` |
| **`coding-01`** | `coding.read`, `coding.write`, `coding.test` |
| **`deployment-01`** | `deployment.preview`, `deployment.production` |
| **`verification-01`** | `verification.test` |

---

## 4. Resources

A **resource** represents the protected target entity or environment on which an action operates. Kavach enforces security policies guarding these specific resources:

- **`research-data`**: Datasets, external research caches, and fetched informational documents.
- **`workspace`**: Local filesystem repository containing application source code, scratch files, and configuration.
- **`test-environment`**: Ephemeral sandbox or local test execution environment used for running automated unit/integration tests.
- **`staging-environment`**: Pre-production staging infrastructure where candidate deployments undergo integration and preview validation.
- **`production-environment`**: Live, customer-facing production infrastructure, systems, and release targets.

---

## 5. Actions

A **requested action** represents the operation an agent is attempting to execute at runtime. 

### Critical Distinction: Capability vs. Requested Action

- **Capability**: What an agent is provisioned to possess within the Kavach registry (e.g., `research.search`).
- **Requested Action**: What an agent dynamically asks to execute across the gateway (e.g., `deployment.deploy`).

Possessing one capability does not authorize requested actions outside that capability. When an agent attempts an action that falls outside its assigned capabilities, Kavach treats the discrepancy as an explicit security violation signal (`CAPABILITY_MISMATCH`) resulting in deterministic denial.

### Exact Requested Actions

- `research.search`
- `research.read`
- `coding.read`
- `coding.write`
- `coding.test`
- `deployment.preview`
- `deployment.deploy`
- `verification.test`
- `orchestrator.delegate`
- `orchestrator.coordinate`

---

## 6. Authorization Model

Every runtime request passes through the deterministic Kavach decision pipeline:

```
Agent Request
     │
     ▼
Kavach Gateway
     │
     ▼
Identity Check          (Validates cryptographic agent identity)
     │
     ▼
Capability Check        (Verifies agent possesses the required capability)
     │
     ▼
Provenance Check        (Validates invocation lineage, caller authority, and delegation chain)
     │
     ▼
Cedar Policy Engine     (Evaluates deterministic Cedar policies)
     │
     ▼
Deterministic Rules     (Applies hard invariant security rules)
     │
     ▼
ALLOW / DENY Decision
     │
     ▼
Telemetry / Incidents / Enforcement
```

### Cedar Evaluation Model

Cedar policies reason strictly over four discrete entities:
- **`principal`**: The validated agent identity (e.g., `Agent::"deployment-01"`).
- **`action`**: The explicit requested action (e.g., `Action::"deployment.deploy"`).
- **`resource`**: The target resource being operated on (e.g., `Resource::"production-environment"`).
- **`context`**: Request-specific runtime attributes, including validated provenance metadata, invocation timestamps, and security tags.

*Rule: Identity, action, and resource identifiers must remain first-class Cedar schema entities and must never be collapsed into `context`.*

---

## 7. Security States

Kavach tracks the security status of each agent under an explicit four-state lifecycle:

| Security State | Enforcement Scope (Phase 1) | Definition & Operational Behavior |
| :--- | :--- | :--- |
| **`ACTIVE`** | **In Scope** | The agent is healthy and permitted to submit requests to the gateway, subject to normal identity, capability, provenance, and policy evaluations. |
| **`QUARANTINED`** | **In Scope** | The agent remains registered with Kavach, but all its outbound requests to protected agents, tools, and resources are deterministically blocked by the enforcement layer. Quarantine is an administrative enforcement state, not an ad-hoc policy. |
| **`SUSPICIOUS`** | *Future / Out of Scope* | Agent has triggered non-fatal risk signals or behavioral anomalies requiring advisory monitoring. |
| **`TERMINATED`** | *Future / Out of Scope* | Agent has been permanently revoked, deregistered, and deactivated. |

---

## 8. Security Principles

1. **Default Deny**:
   An action is denied by default unless an explicit, unambiguous policy and capability rule permits it.
2. **Least Privilege**:
   Agents are provisioned strictly with the minimal capability set required to execute their specific domain tasks.
3. **Separation of Identity and Capability**:
   Validating an agent's identity confirms who the caller is; it does not confer authority to perform actions.
4. **Capability / Action Separation**:
   Possessing a capability does not imply or grant authorization for distinct or adjacent requested actions.
5. **Provenance Matters**:
   Every request must carry a verifiable delegation lineage. Kavach independently verifies where a request originated and how authority was delegated.
6. **External Enforcement**:
   Kavach resides completely outside the agent execution runtime. Agents cannot modify Kavach policies, states, or thresholds.
7. **Deterministic Authorization**:
   Authorization decisions are produced exclusively by deterministic logic (Cedar policies and formal rules). Decisions never depend on heuristic or non-deterministic mechanisms.
8. **Risk Score is Advisory**:
   Heuristic risk scores or anomaly alerts provide contextual telemetry for operators, but cannot grant permissions or override policy.
9. **Quarantine is Enforcement**:
   When an agent is transitioned to `QUARANTINED`, runtime enforcement intercepts and denies all further protected actions from that agent.
10. **No LLM in the Authorization Path**:
    Large Language Models are strictly prohibited from evaluating, granting, or overriding authorization decisions. Any future LLM integration is limited to post-hoc advisory telemetry explanations.

---

## 9. Canonical Attack Example

To validate the model prior to implementation, consider the canonical capability escalation attack:

- **Source Agent**: `research-01`
- **Assigned Capability**: `research.search` (and `research.read`)
- **Requested Action**: `deployment.deploy`
- **Target Resource**: `production-environment`

### Evaluation Trace:
1. **Identity Check**: Passed (`research-01` is a recognized agent).
2. **Capability Check**: **Failed**. `research-01` possesses `research.search` and `research.read`; it does not possess `deployment.production`.
3. **Action/Capability Analysis**: `deployment.deploy` requires capability `deployment.production`.
4. **Enforcement Decision**: **`DENY`**
5. **Decision Reason**: **`CAPABILITY_MISMATCH`**

*Phase 1 Note: This scenario documents the baseline security logic for subsequent phases. No active enforcement code is deployed during this phase.*
