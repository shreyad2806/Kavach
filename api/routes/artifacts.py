import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from api.middleware.auth import require_api_key
from scanner.gateway import handler as scan_handler
from scanner.gateway import status as status_handler

router = APIRouter(dependencies=[Depends(require_api_key)])


@router.post("/scan", status_code=201)
async def submit_scan(body: dict):
    result = scan_handler.handler({"body": body}, None)
    return JSONResponse(
        status_code=result["statusCode"],
        content=json.loads(result["body"]),
    )


@router.get("/{artifact_id}")
async def get_artifact(artifact_id: str):
    result = status_handler.handler({"artifact_id": artifact_id}, None)
    return JSONResponse(
        status_code=result["statusCode"],
        content=json.loads(result["body"]),
    )
