"""
Artifact Gateway Lambda handler.

POST /artifacts/scan
  Body: { artifact_type, source_url, requested_by }

Response:
  201: { artifact_id, status, sha256 }
  400: { error }
  500: { error }

On success:
  1. Validates the request body.
  2. Generates a unique artifact_id.
  3. Downloads the artifact to quarantine S3.
  4. Persists the ArtifactRecord to DynamoDB.
  5. Starts the Step Functions pipeline execution.
  6. Returns artifact_id, QUEUED status, and sha256.
"""

import json
import os
import uuid
from datetime import datetime, timezone

import boto3
from pydantic import ValidationError

from scanner.gateway.downloader import ArtifactTooLargeError, DownloadError, fetch
from scanner.models.artifact import ArtifactRecord, ArtifactRequest, ArtifactStatus
from scanner.storage.dynamodb import put_artifact, update_artifact_status
from scanner.storage.s3 import upload_to_quarantine


def _sfn_client():
    return boto3.client("stepfunctions")


def _start_pipeline(artifact_id: str) -> None:
    """Start the Step Functions scanner state machine for this artifact."""
    sfn_arn = os.environ["PIPELINE_STATE_MACHINE_ARN"]
    _sfn_client().start_execution(
        stateMachineArn=sfn_arn,
        name=f"{artifact_id}-{uuid.uuid4().hex[:8]}",
        input=json.dumps({"artifact_id": artifact_id}),
    )


def _response(status_code: int, body: dict) -> dict:
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def handler(event: dict, context) -> dict:
    # Parse and validate request body
    try:
        raw_body = event.get("body") or "{}"
        if isinstance(raw_body, str):
            raw_body = json.loads(raw_body)
        request = ArtifactRequest.model_validate(raw_body)
    except (json.JSONDecodeError, ValidationError) as e:
        return _response(400, {"error": f"Invalid request: {e}"})

    artifact_id = f"art-{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc)

    # Create the initial artifact record
    record = ArtifactRecord(
        artifact_id=artifact_id,
        artifact_type=request.artifact_type,
        source_url=request.source_url,
        requested_by=request.requested_by,
        status=ArtifactStatus.DOWNLOADING,
        created_at=now,
        updated_at=now,
    )

    try:
        put_artifact(record)
    except Exception as e:
        return _response(500, {"error": f"Failed to create artifact record: {e}"})

    # Download artifact to quarantine
    try:
        data = fetch(request.source_url)
    except ArtifactTooLargeError as e:
        update_artifact_status(artifact_id, ArtifactStatus.FAILED)
        return _response(400, {"error": str(e)})
    except DownloadError as e:
        update_artifact_status(artifact_id, ArtifactStatus.FAILED)
        return _response(502, {"error": str(e)})

    # Upload to quarantine S3 and record the hash
    try:
        quarantine_s3_key, sha256 = upload_to_quarantine(artifact_id, request.source_url, data)
    except Exception as e:
        update_artifact_status(artifact_id, ArtifactStatus.FAILED)
        return _response(500, {"error": f"Failed to store artifact: {e}"})

    # Update record with quarantine location and hash, transition to QUEUED
    update_artifact_status(
        artifact_id,
        ArtifactStatus.QUEUED,
        sha256=sha256,
        quarantine_key=quarantine_s3_key,
    )

    # Kick off the scanner pipeline — this is the trigger that was missing
    try:
        _start_pipeline(artifact_id)
    except Exception as e:
        update_artifact_status(artifact_id, ArtifactStatus.FAILED)
        return _response(500, {"error": f"Failed to start scan pipeline: {e}"})

    return _response(201, {
        "artifact_id": artifact_id,
        "status": ArtifactStatus.QUEUED.value,
        "sha256": sha256,
    })
