from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException

from api.middleware.auth import require_api_key
from shield.capabilities.registry import ACTION_CAPABILITY_MAP
from shield.policy.cedar.engine import _POLICIES_PATH

router = APIRouter(dependencies=[Depends(require_api_key)])


@router.get("/")
async def list_policies():
    """Return the Cedar policy set and the action→capability map."""
    cedar_text = ""
    if _POLICIES_PATH.exists():
        cedar_text = _POLICIES_PATH.read_text(encoding="utf-8")

    capability_map = {
        action.value: capability.value
        for action, capability in ACTION_CAPABILITY_MAP.items()
    }

    return {
        "cedar_policies": cedar_text,
        "action_capability_map": capability_map,
    }
