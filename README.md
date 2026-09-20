# Kavach

**Zero-Trust Runtime Security for Autonomous Systems**

Kavach is a security platform that enforces zero-trust principles on multi-agent AI environments. It was built in response to real-world attacks like the HuggingFace breach, where AI agents discovered vulnerabilities in an artifact registry and created hidden channels to exfiltrate credentials.

Kavach operates at two layers:

- **Scanner** — pre-execution artifact scanning. Every third-party package, repository, or file an agent wants to use is scanned before it runs.
- **Shield** — runtime monitoring. Every action an agent takes at runtime is intercepted, verified against policy, and either allowed or blocked.

A live operator dashboard and artifact scanner UI are included for real-time visibility into agent activity, security decisions, and scan results.

---

## Architecture

```
Browser (React SPA)
        │
        ▼
  CloudFront + S3
        │
        ▼
  Node BFF (Express)  ──────────────────────────────────────┐
        │                                                    │
        ▼                                                    │
  Python API (FastAPI / Lambda)                             │
  ├── Shield runtime  (authorization, quarantine)           │
  ├── Multi-agent workflow supervisor                       │
  └── Scanner gateway  ─────────────────────────────────────┘
        │
        ▼
  POST /artifacts/scan  (API Gateway + Lambda)
        │
        ▼
  Quarantine S3  ──────────────────────────────────────────┐
        │                                                   │
        ▼                                                   │
  Step Functions Pipeline                                   │
  ┌─────────────────────────────────────┐                  │
  │  Static Scan (parallel)             │                  │
  │  ┌──────────┐  ┌──────────────────┐ │                  │
  │  │  Bandit  │  │     Semgrep      │ │                  │
  │  └──────────┘  └──────────────────┘ │                  │
  │  ┌──────────┐  ┌──────────────────┐ │                  │
  │  │ pip-audit│  │    Gitleaks      │ │                  │
  │  └──────────┘  └──────────────────┘ │                  │
  └─────────────────────────────────────┘                  │
        │                                                   │
        ▼                                                   │
  Fargate Sandbox  ◄─────────────────────────────────────── ┘
  (private subnet, zero outbound, read-only FS, UID 65534)
        │
        ▼
  Verdict Engine  (deterministic — no LLM)
        │
        ▼
  Bedrock Agent  (Claude 3 Haiku — advisory explanation only)
        │
        ▼
  APPROVED → approved/ S3 prefix  (agents can access)
  BLOCKED  → stays in quarantine  (agents cannot access)
  REVIEW   → flagged for operator
```

---

## Components

### Scanner

Pre-execution artifact scanning. Accepts any artifact URL, runs it through a multi-stage pipeline, and produces a deterministic verdict before any agent is allowed to use it.

| Stage | What happens |
|---|---|
| Gateway | Download artifact, SHA-256 hash, upload to quarantine S3, trigger pipeline |
| Static scan (parallel) | Bandit, Semgrep, pip-audit, Gitleaks run concurrently |
| Sandbox | Fargate container executes the artifact under strace, observes runtime behavior |
| Verdict | Deterministic risk score (0–100), hard block rules, APPROVED/BLOCKED/REVIEW decision |
| Agent report | Claude 3 Haiku explains the verdict in plain English for operators |

**Static scanners:**
- **Bandit** — Python security issues: eval/exec abuse, weak crypto, subprocess misuse, hardcoded passwords
- **Semgrep** — Language-aware pattern matching for Python, JavaScript, TypeScript, Go, Java, Ruby, Shell. Rules bundled into the Docker image at build time — no internet needed at runtime
- **pip-audit** — Python CVE scanning via PyPI Advisory Database
- **Gitleaks** — Secret and credential detection. Clones full git history (depth 50) for GitHub/GitLab/Bitbucket URLs

**Verdict thresholds:**

| Risk score | Level | Decision |
|---|---|---|
| 0–20 | LOW | APPROVED |
| 21–50 | MEDIUM | APPROVED |
| 51–79 | HIGH | REVIEW_REQUIRED |
| 80–100 | CRITICAL | BLOCKED |

Hard block overrides (score-independent):
- Any CRITICAL finding from Gitleaks → BLOCKED
- Any CRITICAL CVE from pip-audit → BLOCKED
- Sandbox `SECRET_ACCESS`, `SHELL_EXECUTION`, or `PRIVILEGE_ESCALATION` → BLOCKED

---

### Shield

Runtime monitoring and zero-trust enforcement for the multi-agent system.

- **Authorization pipeline** — every agent action passes through KavachGuard → authorize() before execution
- **Identity service** — tracks agent state (ACTIVE, QUARANTINED, REVOKED)
- **Capability registry** — each agent has a declared capability set; cross-capability actions are denied
- **Quarantine service** — compromised agents are isolated; all subsequent actions are denied
- **Incident service** — security events are recorded and surfaced in the dashboard
- **Cedar policy engine** — declarative allow/deny policies per agent and action type
- **Telemetry** — every authorization decision is emitted as a structured event with workflow correlation

---

### Multi-Agent Workflow

Five agents orchestrated by a supervisor:

| Agent | Role |
|---|---|
| Orchestrator | Delegates tasks, receives results |
| Research | Web search and document read (read-only) |
| Coding | File read/write, test execution |
| Verification | Test runner, quality gate |
| Deployment | Staging preview only — production requires explicit authorization |

Task routing is automatic: the supervisor classifies the task (research / coding / deployment) and runs only the agents the task needs. Every agent action goes through KavachGuard — a Kavach DENY stops the workflow and records the denial without executing the action.

---

### API

FastAPI control plane exposing all Shield, Scanner, and workflow operations over HTTP. Runs locally via uvicorn and on AWS via Lambda (Mangum adapter).

| Route | Description |
|---|---|
| `POST /artifacts/scan` | Submit artifact for scanning |
| `GET /artifacts/{id}` | Poll scan status and results |
| `POST /workflows` | Create a workflow |
| `POST /workflows/{id}/start` | Start workflow execution |
| `GET /workflows/{id}` | Poll workflow status |
| `POST /workflows/demo/reset` | Reset demo session |
| `POST /workflows/simulation/attack` | Simulate capability escalation attack |
| `GET /agents` | List all agents and their states |
| `GET /incidents` | List security incidents |
| `GET /dashboard` | Aggregated dashboard metrics |
| `GET /events` | Authorization event stream |
| `GET /policies` | Active Cedar policies |

---

### Frontend

React + Tailwind operator dashboard with two pages:

- **Dashboard** — live agent fleet status, authorization event stream, security pipeline visualization, attack simulation
- **Artifact Scanner** — submit any URL for scanning, poll results, view findings by severity

---

## Project Structure

```
kavach/
├── agents/                   # Multi-agent workflow
│   ├── coding/               # Coding agent
│   ├── deployment/           # Deployment agent
│   ├── orchestrator/         # Orchestrator agent
│   ├── research/             # Research agent
│   ├── supervisor/           # Workflow lifecycle, task routing
│   └── verification/         # Verification agent
├── api/                      # FastAPI control plane
│   ├── middleware/           # Auth, validation
│   ├── routes/               # All HTTP route handlers
│   ├── lambda_handler.py     # Mangum adapter for Lambda
│   └── main.py               # App entrypoint
├── backend/                  # Node.js BFF (Express proxy)
│   ├── src/
│   │   ├── routes/           # Per-resource proxy routes
│   │   ├── middleware/       # Auth middleware
│   │   ├── proxy.js          # Upstream proxy with timeout handling
│   │   └── index.js          # Server entrypoint
│   └── Dockerfile            # Container image for App Runner
├── frontend/                 # React operator dashboard
│   └── src/
│       ├── components/       # UI components
│       ├── hooks/            # useKavach, useScanner
│       ├── pages/            # DashboardPage, ScannerPage
│       └── App.jsx           # Shell with sidebar navigation
├── infrastructure/
│   ├── scanner/
│   │   ├── template.yaml     # SAM — Scanner Lambda, Step Functions, Fargate, DynamoDB, S3
│   │   ├── stepfunctions.json
│   │   └── samconfig.toml
│   └── shield/
│       ├── template.yaml     # SAM — Shield API Lambda, AgentsTable, IncidentsTable
│       └── samconfig.toml
├── sandbox/                  # Local runtime sandbox
│   └── runtime/              # KavachGuard, MessageBus, workspace
├── scanner/                  # Scanner pipeline
│   ├── agent/                # Bedrock/Strands agent — explains verdicts
│   ├── gateway/              # Downloader, extractor, handler, status
│   ├── models/               # Pydantic models
│   ├── pipeline/             # Step Functions stage handler
│   ├── sandbox/              # Fargate runner, observer, signals
│   │   └── container/        # Fargate container image (Dockerfile + entrypoint)
│   ├── scanners/             # Bandit, Semgrep, pip-audit, Gitleaks wrappers
│   ├── storage/              # DynamoDB and S3 helpers
│   └── verdict/              # Scoring engine and verdict logic
├── shield/                   # Shield runtime
│   ├── authorization/        # Authorization pipeline
│   ├── capabilities/         # Capability registry and service
│   ├── detection/            # Anomaly detection, rules, signals
│   ├── enforcement/          # Quarantine, revocation, kill switch
│   ├── identity/             # Agent identity service
│   ├── incidents/            # Incident tracking
│   ├── policy/               # Cedar policy engine
│   ├── provenance/           # Request provenance validation
│   ├── runtime/              # Shared ShieldRuntime singleton
│   └── telemetry/            # Authorization event emission
├── tests/                    # Full test suite
├── Dockerfile                # Lambda container image (scanner + API)
└── requirements.txt
```

---

## AWS Services

| Service | Role |
|---|---|
| API Gateway | Scanner and Shield HTTP endpoints with API key auth |
| Lambda (container image) | Gateway, pipeline, status, and Shield API handlers |
| Step Functions | Orchestrates parallel static scan → sandbox → verdict |
| S3 | Quarantine prefix (7-day auto-delete) and approved prefix |
| DynamoDB | Artifacts, Findings, Verdicts, SandboxResults, Agents, Incidents tables |
| ECS Fargate | Isolated sandbox container execution |
| ECR | Lambda scanner image, Fargate sandbox image, Node BFF image, API image |
| Bedrock | Claude 3 Haiku for plain-English scan reports |
| App Runner | Node BFF — auto-scaling, no infrastructure management |
| CloudFront + S3 | React frontend static hosting with HTTPS |
| CloudWatch Logs | Structured JSON logs from Lambda and Fargate, filterable by `artifact_id` |
| IAM | Least-privilege roles per service |
| VPC | Private subnet + zero-outbound security group for sandbox isolation |

---

## Local Development

### Prerequisites

- Python 3.11+
- Node.js 18+
- Docker
- AWS CLI configured with credentials for ap-south-1

### Setup

```bash
git clone https://github.com/shreyad2806/Kavach.git
cd Kavach

# Python dependencies
pip install -r requirements.txt

# Node BFF
cd backend && npm install

# Frontend
cd frontend && npm install
```

### Environment variables

Create `.env` at the repo root:

```
AWS_DEFAULT_REGION=ap-south-1
ARTIFACTS_TABLE=<dynamodb-table-name>
FINDINGS_TABLE=<dynamodb-table-name>
VERDICTS_TABLE=<dynamodb-table-name>
SANDBOX_RESULTS_TABLE=<dynamodb-table-name>
SCANNER_BUCKET=<s3-bucket-name>
PIPELINE_STATE_MACHINE_ARN=<step-functions-arn>
API_KEY=kavach-dev-key
```

Create `backend/.env`:

```
PORT=3001
PYTHON_API_URL=http://localhost:8000
API_KEY=kavach-dev-key
FRONTEND_URL=http://localhost:5173
UPSTREAM_TIMEOUT_MS=120000
```

Create `frontend/.env`:

```
VITE_API_KEY=kavach-dev-key
VITE_API_URL=http://localhost:3001
```

### Run locally

```bash
# Terminal 1 — Python API
cd Kavach
uvicorn api.main:app --port 8000 --reload

# Terminal 2 — Node BFF
cd Kavach/backend
npm run dev

# Terminal 3 — Frontend
cd Kavach/frontend
npm run dev
```

Open `http://localhost:5173`.

---

## Tests

```bash
# All scanner tests
pytest tests/scanner/ -v

# All shield/authorization tests
pytest tests/authorization/ -v

# Full suite
pytest tests/ -v
```

---

## Security Model

- The verdict engine is fully deterministic. The LLM (Bedrock agent) is advisory only and cannot modify any verdict or security state.
- The Fargate sandbox task role has exactly two permissions: `s3:GetObject` + `s3:ListBucket` on the quarantine prefix and `dynamodb:PutItem` on the sandbox results table.
- All artifact URLs are SSRF-checked before download. Private IP ranges and the AWS metadata endpoint are blocked.
- Artifacts stay in the quarantine S3 prefix until explicitly approved. Agents only have access to the approved prefix.
- Every agent action passes through KavachGuard → authorize() before execution. A DENY stops the action and records the incident — the unauthorized operation is never executed.
- All logs are structured JSON. Every log entry carries `artifact_id` or `workflow_id` for full trace correlation.

---

## Cost Estimate

At demo/hackathon scale (~100 scans/day):

| Service | Monthly cost |
|---|---|
| Lambda | ~$0.40 |
| Step Functions | ~$0.18 |
| ECS Fargate | ~$0.90 |
| Bedrock (Claude 3 Haiku) | ~$1.20 |
| DynamoDB | ~$0.50 |
| S3 + ECR | ~$0.30 |
| CloudWatch Logs | ~$1.00 |
| API Gateway | ~$0.02 |
| App Runner (BFF) | ~$5.00 |
| CloudFront | ~$1.00 |
| **Total** | **~$10.50/month** |
