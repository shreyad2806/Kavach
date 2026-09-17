"""
DynamoDB persistence for artifact records, scan findings, and verdicts.

Tables (set via environment variables):
  ARTIFACTS_TABLE   — ArtifactRecord per artifact_id
  FINDINGS_TABLE    — ScanFinding list per artifact_id
  VERDICTS_TABLE    — ScanVerdict per artifact_id

For local dev, point AWS_ENDPOINT_URL at LocalStack.
"""

import json
import os
from datetime import datetime, timezone

import boto3

from scanner.models.artifact import ArtifactRecord, ArtifactStatus
from scanner.models.finding import ScanFinding
from scanner.models.verdict import ScanVerdict


def _ddb():
    endpoint = os.environ.get("AWS_ENDPOINT_URL")
    return boto3.resource("dynamodb", endpoint_url=endpoint)


def _artifacts_table():
    return _ddb().Table(os.environ["ARTIFACTS_TABLE"])


def _findings_table():
    return _ddb().Table(os.environ["FINDINGS_TABLE"])


def _verdicts_table():
    return _ddb().Table(os.environ["VERDICTS_TABLE"])


# ---------- Artifact record ----------

def put_artifact(record: ArtifactRecord) -> None:
    _artifacts_table().put_item(Item=json.loads(record.model_dump_json()))


def get_artifact(artifact_id: str) -> ArtifactRecord | None:
    resp = _artifacts_table().get_item(Key={"artifact_id": artifact_id})
    item = resp.get("Item")
    return ArtifactRecord.model_validate(item) if item else None


def get_latest_artifact_by_url(source_url: str) -> ArtifactRecord | None:
    """
    Return the most recently created artifact record for a given source_url, or None.
    Uses the SourceUrlIndex GSI (source_url → created_at sort key).
    """
    resp = _artifacts_table().query(
        IndexName="SourceUrlIndex",
        KeyConditionExpression="source_url = :url",
        ExpressionAttributeValues={":url": source_url},
        ScanIndexForward=False,  # newest first
        Limit=1,
    )
    items = resp.get("Items", [])
    return ArtifactRecord.model_validate(items[0]) if items else None


def update_artifact_status(artifact_id: str, status: ArtifactStatus, **extra_fields) -> None:
    now = datetime.now(timezone.utc).isoformat()
    update_expr = "SET #s = :s, updated_at = :u"
    expr_names = {"#s": "status"}
    expr_values = {":s": status.value, ":u": now}

    for k, v in extra_fields.items():
        update_expr += f", {k} = :{k}"
        expr_values[f":{k}"] = v

    _artifacts_table().update_item(
        Key={"artifact_id": artifact_id},
        UpdateExpression=update_expr,
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_values,
    )


# ---------- Scan findings ----------

def put_finding(finding: ScanFinding) -> None:
    item = json.loads(finding.model_dump_json())
    # Composite sort key: scanner#timestamp for uniqueness
    item["sk"] = f"{finding.scanner.value}#{finding.timestamp.isoformat()}"
    _findings_table().put_item(Item=item)


def get_findings(artifact_id: str) -> list[ScanFinding]:
    resp = _findings_table().query(
        KeyConditionExpression="artifact_id = :id",
        ExpressionAttributeValues={":id": artifact_id},
    )
    items = resp.get("Items", [])
    # Strip the internal sort key before validating against the model
    for item in items:
        item.pop("sk", None)
    return [ScanFinding.model_validate(item) for item in items]


# ---------- Verdict ----------

def put_verdict(verdict: ScanVerdict, agent_report: str | None = None) -> None:
    item = json.loads(verdict.model_dump_json())
    if agent_report:
        item["agent_report"] = agent_report
    _verdicts_table().put_item(Item=item)


def get_verdict(artifact_id: str) -> ScanVerdict | None:
    resp = _verdicts_table().get_item(Key={"artifact_id": artifact_id})
    item = resp.get("Item")
    if not item:
        return None
    item.pop("agent_report", None)
    return ScanVerdict.model_validate(item)
