"""Artifact scanner routes (HTTP wiring over the existing scanner gateway).

The scanner remains a separate concern; this module only adapts its Lambda-style
handlers to HTTP.  Two fixes over the previous wiring:

1. Correct handler reference.  ``scanner/gateway/__init__.py`` rebinds the name
   ``handler`` to the *function* ``scanner.gateway.handler.handler``, so
   ``from scanner.gateway import handler`` yields the function, not the module,
   and ``handler.handler(...)`` raised AttributeError.  We import the handler
   functions directly from their submodules to avoid the shadowing entirely.

2. Explicit AWS-unavailability.  The gateway persists to DynamoDB/S3 and starts
   Step Functions.  When that AWS backend is not configured (local dev), the
   very first storage call raises (missing env / no credentials / no region /
   connection error).  We translate that into a clear 503 instead of letting it
   bubble up as an opaque 500.  Scanner results are never faked.
"""

import asyncio
import json
from functools import partial

from botocore.exceptions import BotoCoreError, ClientError
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from api.middleware.auth import require_api_key
from scanner.gateway.handler import handler as submit_scan_handler
from scanner.gateway.status import handler as artifact_status_handler

router = APIRouter(dependencies=[Depends(require_api_key)])

_AWS_UNAVAILABLE_ERRORS = (KeyError, BotoCoreError, ClientError)


def _unavailable(detail: str) -> JSONResponse:
    return JSONResponse(status_code=503, content={"error": "Scanner service unavailable", "detail": detail})


def _relay(result: dict) -> JSONResponse:
    return JSONResponse(status_code=result["statusCode"], content=json.loads(result["body"]))


async def _run(fn, *args):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, partial(fn, *args))


@router.post("/scan", status_code=201)
async def submit_scan(body: dict):
    try:
        result = await _run(submit_scan_handler, {"body": body}, None)
    except _AWS_UNAVAILABLE_ERRORS as exc:
        return _unavailable(f"AWS scanner backend unavailable: {type(exc).__name__}: {exc}")
    return _relay(result)


@router.get("/{artifact_id}")
async def get_artifact(artifact_id: str):
    try:
        result = await _run(artifact_status_handler, {"artifact_id": artifact_id}, None)
    except _AWS_UNAVAILABLE_ERRORS as exc:
        return _unavailable(f"AWS scanner backend unavailable: {type(exc).__name__}: {exc}")
    return _relay(result)
