# Kavach Threat Model

## 1. Assets

Kavach defends two categories of assets: target execution resources and security-sensitive control-plane data.

### Protected Resources
- **`research-data`**: Proprietary datasets, ingested external research documents, and internal analytical corpora.
- **`workspace`**: Development source tree, build configurations, and sensitive local artifacts.
- **`test-environment`**: Sandbox environments executing test runners, unit suites, and integration harnesses.
- **`staging-environment`**: Pre-production staging infrastructure hosting release candidates.
- **`production-environment`**: Live operational infrastructure, deployment pipelines, customer databases, and production services.

### Security-Sensitive Control-Plane Data
- **Agent Identity Records**: Cryptographic identities, key material, and agent registration manifests.
- **Authorization Policies**: Cedar policy sets, role boundaries, and capability bindings.
- **Provenance Information**: Cryptographic invocation chains, causal DAG nodes, and delegation histories.
- **Security State**: Agent runtime status flags (`ACTIVE`, `QUARANTINED`), incident event records, and audit logs.

---

## 2. Trust Boundaries

Kavach establishes an absolute trust boundary between the external autonomous agent execution environment and the internal security control plane.

```
┌─────────────────────────────────────────────────────────────┐
│ UNTRUSTED / POTENTIALLY COMPROMISED RUNTIME DOMAIN          │
│                                                             │
│  - Autonomous Agents (orchestrator, research, coding, etc.) │
│  - Agent-Generated Request Payloads                         │
│  - Agent-Provided Claims of Authority or Delegation         │
│  - External LLM Context & Prompts                           │
└──────────────────────────────┬──────────────────────────────┘
                               │
               [ Kavach Gateway Interception ]
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ TRUSTED SECURITY CONTROL PLANE (Kavach Authority)           │
│                                                             │
│  - Kavach Identity Records (authoritative identity store)   │
│  - Capability Registry (immutable permission maps)          │
│  - Provenance Validation (verified causal graph)            │
│  - Cedar Policy Engine (deterministic evaluation)           │
│  - Deterministic Enforcement Rules                          │
│  - Quarantine & Isolation State Machine                     │
└─────────────────────────────────────────────────────────────┘
```

### Core Trust Principles
- **Agents are Never Self-Authorizing**: Agents are untrusted clients. No claim of authority made by an agent is accepted without independent verification.
- **Isolation of Authority**: The security control plane does not trust the agent execution context to enforce policies, report violations accurately, or manage access control.

---

## 3. Threats

The initial threat model addresses seven primary attack patterns observed in autonomous multi-agent environments:

### `T1 — Capability Escalation`
An agent attempts an action that lies outside its statically or dynamically assigned capability set (e.g., `research-01` attempting to compile or write code).

### `T2 — Authority Forgery`
An agent fabricates an authorization grant or falsely asserts that an upstream authority (such as `orchestrator-01`) sanctioned the requested action.

### `T3 — Provenance Manipulation`
An agent injects false parent IDs, truncates invocation history, or alters metadata within the causal chain to disguise unauthorized lateral movements or origins.

### `T4 — Unauthorized Production Access`
A non-deployment agent (e.g., `research-01`, `coding-01`, or `verification-01`) attempts direct access or deployment operations targeting `production-environment`.

### `T5 — Cross-Agent Abuse`
A compromised or misaligned agent invokes another agent to perform unauthorized tasks on its behalf, attempting to bypass capability limitations via indirect delegation.

### `T6 — Security Control Tampering`
An agent issues commands or exploits intended to alter Kavach policies, mutate capability registry tables, alter security state records, or disable enforcement hooks.

### `T7 — Quarantined Agent Activity`
An agent previously placed into `QUARANTINED` status attempts to issue subsequent requests to peer agents, tools, or resources.

---

## 4. Security Responses

Kavach enforces deterministic security responses. Every detected violation halts execution at the gateway:

| Threat / Violation Event | Gateway Detection Layer | Intended Enforcement Response |
| :--- | :--- | :--- |
| **Identity Failure** (Invalid/unknown agent) | Identity Check | **`DENY`** |
| **Capability Mismatch** (Action exceeds capability) | Capability Check | **`DENY`** |
| **Authority Mismatch** (Unverified authority claim) | Capability / Cedar Check | **`DENY`** |
| **Provenance Anomaly** (Forged or broken trace) | Provenance Check | **`DENY`** |
| **Unauthorized Production Action** (Non-deployment access) | Cedar Policy & Deterministic Rules | **`DENY`** |
| **Security Control Tampering** (Attempted policy/state edit) | Gateway Interceptor / Security Rules | **`DENY`** |
| **Quarantined Agent Request** (Call from quarantined agent) | Enforcement Layer | **`DENY`** |

### Escalation Policy
- In addition to immediate request **`DENY`**, repeated violations, critical threats (such as production tampering or provenance forgery), or severe anomalous behavior escalate the source agent's state to **`QUARANTINED`**.
- Once quarantined, all subsequent protected interactions from that agent are dropped or denied without evaluating deeper authorization layers.

---

## 5. Explicit Non-Goals

To maintain high assurance and narrow scope, the following capabilities are explicitly designated as **non-goals** for Phase 1:

- **Model-Level Prompt Injection Detection**: Detecting or filtering adversarial prompts inside LLM token streams.
- **Malware Scanning**: Static or binary analysis of code payloads or binaries generated by coding agents.
- **Dependency Scanning**: Vulnerability or supply-chain scanning (e.g., CVE audits) for generated packages.
- **Arbitrary Internet Security**: Deep packet inspection or outbound firewalling for arbitrary web browsing.
- **Full Anomaly Detection**: Statistical or machine-learning-based behavioural anomaly detection algorithms.
- **LLM-Based Security Decisions**: Using LLM inference engines to make authorization decisions.
- **Production AWS Enforcement**: Live enforcement of AWS IAM policies, KMS locks, or cloud-native infrastructure controls.
- **Scanner Functionality**: Automated vulnerability scanning engines or crawlers.

*These capabilities are assigned to subsequent project phases and specialized external modules.*
