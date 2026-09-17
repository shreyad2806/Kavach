# Kavach

**Zero-Trust Runtime Security for Autonomous Systems**

Kavach is a security platform that enforces zero-trust principles on multi-agent AI environments. It was built in response to real-world attacks like the HuggingFace breach, where AI agents discovered vulnerabilities in an artifact registry and created hidden channels to exfiltrate credentials.

Kavach operates at two layers:

- **Scanner** — pre-execution artifact scanning. Every third-party package, repository, or file an agent wants to use is scanned before it runs.
- **Shield** — runtime monitoring. Every action an agent takes at runtime is intercepted, verified against policy, and either allowed or blocked.

---

## Architecture

```
External Artifact (PyPI / GitHub / GitLab / Bitbucket / zip)
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
  Bedrock Agent  (Claude 3.5 Haiku — advisory explanation only)
        │
        ▼
  APPROVED → approved/ S3 prefix  (agents can access)
  BLOCKED  → stays in quarantine  (agents cannot access)
  REVIEW   → flagged for operator
```

---

## Scanner Agent

The scanner agent is the pre-execution security layer. It accepts any artifact URL, runs it through a multi-stage pipeline, and produces a deterministic verdict before any agent is allowed to use it.

### Pipeline Stages

| Stage | What happens |
|---|---|
| Gateway | Download artifact, SHA-256 hash, upload to quarantine S3, trigger pipeline |
| Static scan (parallel) | Bandit, Semgrep, pip-audit, Gitleaks run concurrently |
| Sandbox | Fargate container executes the artifact under strace, observes runtime behavior |
| Verdict | Deterministic risk score (0–100), hard block rules, APPROVED/BLOCKED/REVIEW decision |
| Agent report | Claude 3.5 Haiku explains the verdict in plain English for operators |

### Static Scanners

- **Bandit** — Python security issues: eval/exec abuse, weak crypto, subprocess misuse, hardcoded passwords
- **Semgrep** — Language-aware pattern matching for Python, JavaScript, TypeScript, Go, Java, Ruby, Shell. Rules are bundled into the Docker image at build time — no internet needed at runtime
- **pip-audit** — Python CVE scanning via PyPI Advisory Database. Falls back from requirements.txt → setup.py → AST import extraction
- **Gitleaks** — Secret and credential detection. Clones full git history (depth 50) for GitHub, GitLab, and Bitbucket URLs

### Dynamic Sandbox

The Fargate sandbox runs the artifact in a fully isolated container:

- Private VPC subnet with no internet gateway
- Security group with zero outbound rules
- Read-only root filesystem
- Non-root user (UID 65534 / nobody)
- 0.25 vCPU / 512 MB hard limits
- 30-second execution timeout

Supports: Python (strace), JavaScript/Node.js (strace), Shell scripts (bash+strace), ELF binaries (strings inspection).

Detects 11 behavioral event types: `NETWORK_CONNECT`, `DNS_LOOKUP`, `UNEXPECTED_DOWNLOAD`, `FILE_READ`, `FILE_WRITE`, `FILE_DELETE`, `PROCESS_SPAWN`, `SHELL_EXECUTION`, `SECRET_ACCESS`, `ENV_READ`, `PRIVILEGE_ESCALATION`.

### Verdict Engine

Fully deterministic — no LLM on the critical path.

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

### Security Features

- **SSRF protection** — all artifact URLs are resolved via DNS before download; private IP ranges, localhost, and the AWS metadata endpoint (`169.254.169.254`) are blocked
- **Inter-run comparison** — SHA-256 hash is compared against the previous scan of the same URL; a hash change injects a HIGH finding
- **Path traversal protection** — archive extraction strips `../` and absolute paths
- **Prompt injection hardening** — the Bedrock agent treats all finding content as untrusted data and cannot modify the verdict

---

## AWS Services

| Service | Role |
|---|---|
| API Gateway | `POST /artifacts/scan` and `GET /artifacts/{id}` endpoints with API key auth |
| Lambda (container image) | Gateway, status, and pipeline stage handlers |
| Step Functions | Orchestrates parallel static scan → sandbox → verdict |
| S3 | Quarantine prefix (7-day auto-delete) and approved prefix |
| DynamoDB | Artifacts, Findings, Verdicts, SandboxResults tables |
| ECS Fargate | Isolated sandbox container execution |
| ECR | Lambda scanner image and Fargate sandbox image |
| Bedrock | Claude 3.5 Haiku for plain-English scan reports |
| CloudWatch Logs | Structured JSON logs from Lambda and Fargate, filterable by `artifact_id` |
| IAM | Least-privilege roles — sandbox task role can only read quarantine S3 and write sandbox results |
| VPC | Private subnet + zero-outbound security group for sandbox isolation |

---

## Project Structure

```
kavach/
├── scanner/                  # Pre-execution artifact scanning (this team)
│   ├── agent/                # Bedrock/Strands agent — explains verdicts
│   ├── gateway/              # HTTP handler, downloader, extractor, status endpoint
│   ├── models/               # Pydantic models: artifact, finding, verdict, sandbox
│   ├── pipeline/             # Step Functions stage handler
│   ├── sandbox/              # Fargate runner, observer, signals
│   │   └── container/        # Fargate container image (Dockerfile + entrypoint)
│   ├── scanners/             # Bandit, Semgrep, pip-audit, Gitleaks wrappers
│   ├── storage/              # DynamoDB and S3 helpers
│   ├── verdict/              # Scoring engine and verdict logic
│   └── logger.py             # Structured JSON logger
├── shield/                   # Runtime monitoring (separate team)
├── agents/                   # Multi-agent workflow definitions (separate team)
├── api/                      # Control plane REST API (separate team)
├── infrastructure/
│   └── scanner/
│       ├── template.yaml     # SAM template — all scanner AWS resources
│       └── stepfunctions.json
├── tests/
│   └── scanner/              # 169 tests, all passing
├── Dockerfile                # Lambda container image
├── requirements.txt          # Root dependencies
└── scanner/requirements.txt  # Scanner-specific dependencies
```

---

## Setup

### Prerequisites

- Python 3.11+
- Docker
- AWS CLI + SAM CLI
- AWS account with Bedrock model access enabled for Claude 3.5 Haiku

### Local development

```bash
# Clone
git clone https://github.com/shreyad2806/Kavach.git
cd Kavach

# Install dependencies
pip install -r requirements.txt

# Run scanner tests
pytest tests/scanner/ -v
```

### Deploy to AWS

**1. Enable Bedrock model access**

AWS Console → Bedrock → Model access → Enable Claude 3.5 Haiku (one-time).

**2. Create ECR repositories**

```bash
aws ecr create-repository --repository-name kavach-scanner --region us-east-1
aws ecr create-repository --repository-name kavach-sandbox --region us-east-1
```

**3. Build and push container images**

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com

# Lambda scanner image
docker build -t kavach-scanner .
docker tag kavach-scanner:latest $ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/kavach-scanner:latest
docker push $ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/kavach-scanner:latest

# Fargate sandbox image
docker build -t kavach-sandbox scanner/sandbox/container/
docker tag kavach-sandbox:latest $ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/kavach-sandbox:latest
docker push $ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/kavach-sandbox:latest
```

**4. Create VPC networking for sandbox isolation**

```bash
VPC_ID=$(aws ec2 create-vpc --cidr-block 10.0.0.0/16 --query 'Vpc.VpcId' --output text)
SUBNET_ID=$(aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 10.0.1.0/24 \
  --availability-zone us-east-1a --query 'Subnet.SubnetId' --output text)
SG_ID=$(aws ec2 create-security-group --group-name kavach-sandbox-sg \
  --description "Kavach sandbox — no outbound" --vpc-id $VPC_ID \
  --query 'GroupId' --output text)
aws ec2 revoke-security-group-egress --group-id $SG_ID \
  --protocol -1 --port -1 --cidr 0.0.0.0/0
```

**5. Deploy with SAM**

```bash
cd infrastructure/scanner
sam build
sam deploy \
  --stack-name kavach-scanner \
  --region us-east-1 \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    LambdaImageUri=$ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/kavach-scanner:latest \
    SandboxImageUri=$ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/kavach-sandbox:latest \
    PrivateSubnetId=$SUBNET_ID \
    SandboxSecurityGroupId=$SG_ID
```

SAM outputs the API endpoint URL and API key on completion.

---

## API

All requests require the `x-api-key` header (retrieve from API Gateway console after deploy).

### Submit a scan

```
POST /artifacts/scan
Content-Type: application/json
x-api-key: <key>

{
  "artifact_type": "python_package",
  "source_url": "https://files.pythonhosted.org/packages/.../requests-2.28.0.tar.gz",
  "requested_by": "agent-deployer-01"
}
```

Response `201`:
```json
{
  "artifact_id": "art-a1b2c3d4e5f6",
  "status": "QUEUED",
  "sha256": "e3b0c44298fc1c149afb..."
}
```

Supported `artifact_type` values: `python_package`, `github_repo`, `generic_file`

### Poll for results

```
GET /artifacts/{artifact_id}
x-api-key: <key>
```

Response `200` (completed scan):
```json
{
  "artifact_id": "art-a1b2c3d4e5f6",
  "status": "BLOCKED",
  "sha256": "e3b0c44...",
  "scan_count": 1,
  "total_findings": 3,
  "finding_counts": { "CRITICAL": 1, "HIGH": 2 },
  "verdict": {
    "decision": "BLOCKED",
    "risk_level": "CRITICAL",
    "risk_score": 85,
    "blocked_reasons": ["Secret detected by gitleaks: aws-access-token"],
    "scanner_verdicts": { "gitleaks": "CRITICAL", "bandit": "HIGH" }
  },
  "agent_report": "This artifact was blocked because a hardcoded AWS access key was found..."
}
```

---

## Tests

```bash
# All scanner tests
pytest tests/scanner/ -v

# Specific module
pytest tests/scanner/test_verdict.py -v
```

169 tests, all passing. AWS services mocked via [moto](https://github.com/getmoto/moto). External tools (bandit, semgrep, gitleaks, pip-audit) mocked via `unittest.mock`.

---

## Cost Estimate

At hackathon/demo scale (~100 scans/day):

| Service | Monthly cost |
|---|---|
| Lambda | ~$0.40 |
| Step Functions | ~$0.18 |
| ECS Fargate | ~$0.90 |
| Bedrock (Claude 3.5 Haiku) | ~$1.20 |
| DynamoDB | ~$0.25 |
| S3 + ECR | ~$0.30 |
| CloudWatch Logs | ~$1.00 |
| API Gateway | ~$0.01 |
| **Total** | **~$4.30/month** |

---

## Security Model

- The verdict engine is fully deterministic. The LLM (Bedrock agent) is advisory only and cannot modify any verdict or security state.
- The Fargate sandbox task role has exactly two permissions: `s3:GetObject` on the quarantine prefix and `dynamodb:PutItem` on the sandbox results table. Nothing else.
- All artifact URLs are SSRF-checked before download. Private IP ranges and the AWS metadata endpoint are blocked.
- Artifacts stay in the quarantine S3 prefix until explicitly approved. Agents only have access to the approved prefix.
- All logs are structured JSON emitted to stdout. In Lambda they go to CloudWatch automatically. In Fargate via the awslogs driver. Every log entry carries `artifact_id` for full trace correlation.
