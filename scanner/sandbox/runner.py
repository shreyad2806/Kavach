"""
Sandbox runner — triggers an AWS Fargate task to execute the artifact
in an isolated container and waits for the result written to DynamoDB.

Why Fargate instead of Docker subprocess:
  - Lambda has no Docker daemon — subprocess docker run simply fails
  - Fargate gives real container isolation with the same security constraints
  - Network isolation enforced at VPC level (no internet, no agent subnet access)
  - Results are written to DynamoDB by the Fargate task and read back here

Security constraints enforced on the Fargate task (defined in task definition):
  - VPC with no internet gateway (FARGATE_SUBNET_ID must be a private subnet)
  - Security group with no outbound rules
  - Read-only root filesystem
  - Non-root user (UID 65534)
  - Hard CPU (0.25 vCPU) and memory (512 MB) limits
  - 30 second execution timeout enforced by the task itself

Environment variables required:
  FARGATE_CLUSTER_ARN       — ECS cluster to run the task on
  FARGATE_TASK_DEF_ARN      — task definition ARN for the sandbox image
  FARGATE_SUBNET_ID         — private subnet ID (no internet route)
  FARGATE_SECURITY_GROUP_ID — security group with no outbound rules
  SANDBOX_RESULTS_TABLE     — DynamoDB table where Fargate writes its report
"""

import json
import os
import time
from datetime import datetime, timezone

import boto3

from scanner.logger import get_logger
from scanner.models.sandbox import SandboxReport

log = get_logger(__name__)

_POLL_INTERVAL = 5   # seconds between status checks
_MAX_WAIT = 120      # seconds before we give up waiting for the task


def _ecs():
    return boto3.client("ecs")


def _ddb():
    return boto3.resource("dynamodb")


def _get_sandbox_result(artifact_id: str) -> SandboxReport | None:
    """Read the sandbox report written by the Fargate task from DynamoDB."""
    table_name = os.environ.get("SANDBOX_RESULTS_TABLE")
    if not table_name:
        return None
    table = _ddb().Table(table_name)
    resp = table.get_item(Key={"artifact_id": artifact_id})
    item = resp.get("Item")
    if not item:
        return None
    # Strip DynamoDB-managed fields that aren't part of the model
    item.pop("ttl", None)
    return SandboxReport.model_validate(item)


def run(
    artifact_id: str,
    artifact_path: str,  # kept for interface compatibility — Fargate reads from S3 directly
    timeout: int = _MAX_WAIT,
) -> SandboxReport:
    """
    Trigger a Fargate sandbox task for the artifact and wait for its report.
    Returns a SandboxReport regardless of outcome — never raises.
    """
    now = datetime.now(timezone.utc)

    log.info("triggering fargate sandbox", extra={"artifact_id": artifact_id})

    cluster = os.environ.get("FARGATE_CLUSTER_ARN")
    task_def = os.environ.get("FARGATE_TASK_DEF_ARN")
    subnet = os.environ.get("FARGATE_SUBNET_ID")
    sg = os.environ.get("FARGATE_SECURITY_GROUP_ID")

    if not all([cluster, task_def, subnet, sg]):
        log.error("fargate env vars not configured", extra={"artifact_id": artifact_id})
        return SandboxReport(
            artifact_id=artifact_id,
            executed=False,
            execution_error="Fargate environment variables not configured",
            timestamp=now,
        )

    try:
        resp = _ecs().run_task(
            cluster=cluster,
            taskDefinition=task_def,
            launchType="FARGATE",
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": [subnet],
                    "securityGroups": [sg],
                    "assignPublicIp": "DISABLED",  # no public IP — fully private
                }
            },
            overrides={
                "containerOverrides": [{
                    "name": "sandbox",
                    "environment": [
                        {"name": "ARTIFACT_ID", "value": artifact_id},
                        {"name": "ARTIFACTS_TABLE", "value": os.environ.get("ARTIFACTS_TABLE", "")},
                        {"name": "SANDBOX_RESULTS_TABLE", "value": os.environ.get("SANDBOX_RESULTS_TABLE", "")},
                        {"name": "SCANNER_BUCKET", "value": os.environ.get("SCANNER_BUCKET", "")},
                    ],
                }]
            },
        )
    except Exception as e:
        log.error("failed to start fargate task", extra={"artifact_id": artifact_id, "error": str(e)})
        return SandboxReport(
            artifact_id=artifact_id,
            executed=False,
            execution_error=f"Failed to start Fargate task: {e}",
            timestamp=now,
        )

    failures = resp.get("failures", [])
    if failures:
        return SandboxReport(
            artifact_id=artifact_id,
            executed=False,
            execution_error=f"Fargate task failed to start: {failures[0].get('reason', 'unknown')}",
            timestamp=now,
        )

    task_arn = resp["tasks"][0]["taskArn"]
    log.info("fargate task started", extra={"artifact_id": artifact_id, "task_arn": task_arn})

    # Poll until the task stops or we hit the timeout
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(_POLL_INTERVAL)
        try:
            desc = _ecs().describe_tasks(cluster=cluster, tasks=[task_arn])
            task = desc["tasks"][0]
            last_status = task.get("lastStatus", "")
            if last_status == "STOPPED":
                break
        except Exception:
            break
    else:
        return SandboxReport(
            artifact_id=artifact_id,
            executed=True,
            execution_error=f"Timed out waiting for Fargate task after {timeout}s",
            timestamp=now,
        )

    # Read the report the Fargate task wrote to DynamoDB
    report = _get_sandbox_result(artifact_id)
    if report:
        return report

    # Task ran but wrote no report — treat as executed with no findings
    return SandboxReport(
        artifact_id=artifact_id,
        executed=True,
        execution_error="Fargate task completed but wrote no sandbox report",
        timestamp=now,
    )
