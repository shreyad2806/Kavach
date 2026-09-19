"""
Artifact status endpoint — GET /artifacts/{id}

Returns the current status, verdict, findings summary, and agent report
for a previously submitted artifact scan.

Response codes:
  200: scan found — returns full status payload
  404: artifact_id not found
"""

import json

from scanner.logger import get_logger
from scanner.storage.dynamodb import get_artifact, get_findings, get_verdict, get_agent_report
from scanner.storage.s3 import generate_approved_presigned_url

log = get_logger(__name__)


def _response(status_code: int, body: dict) -> dict:
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def handler(event: dict, context) -> dict:
    artifact_id = (
        (event.get("pathParameters") or {}).get("artifact_id")
        or event.get("artifact_id")  # direct invocation fallback
    )

    if not artifact_id:
        return _response(400, {"error": "Missing artifact_id"})

    record = get_artifact(artifact_id)
    if not record:
        return _response(404, {"error": f"Artifact {artifact_id} not found"})

    log.info("status requested", extra={"artifact_id": artifact_id, "status": record.status.value})

    findings = get_findings(artifact_id)
    finding_counts: dict[str, int] = {}
    for f in findings:
        finding_counts[f.severity.value] = finding_counts.get(f.severity.value, 0) + 1

    verdict = get_verdict(artifact_id)
    agent_report = get_agent_report(artifact_id)

    payload: dict = {
        "artifact_id": record.artifact_id,
        "status": record.status.value,
        "artifact_type": record.artifact_type.value,
        "source_url": record.source_url,
        "requested_by": record.requested_by,
        "sha256": record.sha256,
        "scan_count": record.scan_count,
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
        "finding_counts": finding_counts,
        "total_findings": len(findings),
        "findings": [
            {
                "scanner": f.scanner.value,
                "severity": f.severity.value,
                "title": f.title,
                "description": f.description,
                "location": f.location,
                "cve_id": f.cve_id,
                "rule_id": f.rule_id,
            }
            for f in findings
        ],
    }

    if verdict:
        payload["verdict"] = {
            "decision": verdict.decision.value,
            "risk_level": verdict.risk_level.value,
            "risk_score": verdict.risk_score,
            "blocked_reasons": verdict.blocked_reasons,
            "scanner_verdicts": verdict.scanner_verdicts,
        }
        if verdict.decision.value == "APPROVED":
            try:
                payload["download_url"] = generate_approved_presigned_url(
                    record.artifact_id, record.source_url
                )
            except Exception:
                pass  # presigned URL is best-effort — don't fail the status response

    if agent_report:
        payload["agent_report"] = agent_report

    if record.previous_sha256:
        payload["previous_sha256"] = record.previous_sha256
        payload["previous_verdict"] = record.previous_verdict

    return _response(200, payload)
