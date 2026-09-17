"""
Pipeline orchestrator — the Step Functions state machine calls this Lambda
at each stage. The `stage` field in the event tells it what to do.

Stages:
  static_scan   — run one static scanner tool (called in parallel per scanner)
  sandbox       — run dynamic sandbox
  verdict       — aggregate findings, produce final verdict, approve/block artifact

Single Lambda handles all stages to keep deployment simple.
Each invocation is stateless — state lives in DynamoDB.
"""

import os
import tempfile

from scanner.models.artifact import ArtifactStatus
from scanner.sandbox.runner import run as sandbox_run
from scanner.scanners.bandit import BanditScanner
from scanner.scanners.gitleaks import GitleaksScanner
from scanner.scanners.pip_audit import PipAuditScanner
from scanner.scanners.semgrep import SemgrepScanner
from scanner.storage.dynamodb import (
    get_artifact,
    get_findings,
    put_finding,
    put_verdict,
    update_artifact_status,
)
from scanner.storage.s3 import download_from_quarantine, promote_to_approved
from scanner.verdict.engine import evaluate

_SCANNERS = {
    "bandit": BanditScanner(),
    "semgrep": SemgrepScanner(),
    "pip_audit": PipAuditScanner(),
    "gitleaks": GitleaksScanner(),
}


def _error(msg: str) -> dict:
    return {"status": "ERROR", "error": msg}


def _ok(payload: dict) -> dict:
    return {"status": "OK", **payload}


def _write_artifact(tmpdir: str, data: bytes) -> str:
    """Write artifact bytes to a temp subdirectory, return the path."""
    artifact_path = os.path.join(tmpdir, "artifact")
    os.makedirs(artifact_path)
    with open(os.path.join(artifact_path, "artifact.py"), "wb") as f:
        f.write(data)
    return artifact_path


def handler(event: dict, context) -> dict:
    stage = event.get("stage")
    artifact_id = event.get("artifact_id")

    if not stage or not artifact_id:
        return _error("Missing stage or artifact_id")

    record = get_artifact(artifact_id)
    if not record:
        return _error(f"Artifact {artifact_id} not found")

    # ------------------------------------------------------------------ #
    # STAGE: static_scan                                                   #
    # Step Functions calls this in parallel once per scanner.              #
    # ------------------------------------------------------------------ #
    if stage == "static_scan":
        scanner_name = event.get("scanner")
        if scanner_name not in _SCANNERS:
            return _error(f"Unknown scanner: {scanner_name}")

        update_artifact_status(artifact_id, ArtifactStatus.SCANNING)

        with tempfile.TemporaryDirectory() as tmpdir:
            data = download_from_quarantine(artifact_id, record.source_url)
            artifact_path = _write_artifact(tmpdir, data)
            findings = _SCANNERS[scanner_name].scan(artifact_id, artifact_path)

        for finding in findings:
            put_finding(finding)

        return _ok({
            "artifact_id": artifact_id,
            "scanner": scanner_name,
            "finding_count": len(findings),
        })

    # ------------------------------------------------------------------ #
    # STAGE: sandbox                                                       #
    # ------------------------------------------------------------------ #
    if stage == "sandbox":
        from datetime import datetime, timezone
        from scanner.models.finding import FindingSeverity, ScanFinding, ScannerType

        update_artifact_status(artifact_id, ArtifactStatus.SANDBOXING)

        with tempfile.TemporaryDirectory() as tmpdir:
            data = download_from_quarantine(artifact_id, record.source_url)
            artifact_path = _write_artifact(tmpdir, data)
            report = sandbox_run(artifact_id, artifact_path)

        for evt in report.events:
            if evt.suspicious:
                put_finding(ScanFinding(
                    artifact_id=artifact_id,
                    scanner=ScannerType.SANDBOX,
                    severity=FindingSeverity.HIGH,
                    title=f"Sandbox: {evt.event_type.value}",
                    description=evt.detail,
                    timestamp=datetime.now(timezone.utc),
                ))

        return _ok({
            "artifact_id": artifact_id,
            "executed": report.executed,
            "suspicious_event_count": report.suspicious_event_count,
        })

    # ------------------------------------------------------------------ #
    # STAGE: verdict                                                       #
    # ------------------------------------------------------------------ #
    if stage == "verdict":
        findings = get_findings(artifact_id)
        verdict = evaluate(
            artifact_id=artifact_id,
            sha256=record.sha256 or "",
            findings=findings,
        )
        put_verdict(verdict)

        if verdict.decision.value == "APPROVED":
            approved_key = promote_to_approved(artifact_id, record.source_url)
            update_artifact_status(
                artifact_id,
                ArtifactStatus.APPROVED,
                approved_key=approved_key,
            )
        elif verdict.decision.value == "BLOCKED":
            update_artifact_status(artifact_id, ArtifactStatus.BLOCKED)
        else:
            update_artifact_status(artifact_id, ArtifactStatus.REVIEW_REQUIRED)

        return _ok({
            "artifact_id": artifact_id,
            "decision": verdict.decision.value,
            "risk_score": verdict.risk_score,
            "risk_level": verdict.risk_level.value,
        })

    return _error(f"Unknown stage: {stage}")
