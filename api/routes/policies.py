"""Cedar policy introspection — strictly read-only.

The Cedar policy set is loaded from disk by the policy engine.  There is no
route in this application that can create, edit, or reload a policy: an HTTP
request must never be able to change what the authorization engine permits.
"""

import re

from fastapi import APIRouter, Depends

from api.middleware.auth import require_api_key
from shield.capabilities.registry import ACTION_CAPABILITY_MAP
from shield.policy.cedar.engine import _POLICIES_PATH

router = APIRouter(dependencies=[Depends(require_api_key)])

# `permit ( principal == Agent::"x", action == Action::"y", resource == Resource::"z" );`
_POLICY_RE = re.compile(
    r"(permit|forbid)\s*\(\s*"
    r"principal\s*==\s*([^,]+?)\s*,\s*"
    r"action\s*==\s*([^,]+?)\s*,\s*"
    r"resource\s*==\s*([^)]+?)\s*\)",
    re.IGNORECASE,
)


def _parse_policies(cedar_text: str) -> list[dict]:
    return [
        {
            "effect": match.group(1).lower(),
            "principal": match.group(2).strip(),
            "action": match.group(3).strip(),
            "resource": match.group(4).strip(),
        }
        for match in _POLICY_RE.finditer(cedar_text)
    ]


@router.get("/")
async def list_policies():
    cedar_text = ""
    if _POLICIES_PATH.exists():
        cedar_text = _POLICIES_PATH.read_text(encoding="utf-8")

    policies = _parse_policies(cedar_text)

    return {
        "engine": "cedar",
        "mutable": False,
        "count": len(policies),
        "policies": policies,
        "cedar_policies": cedar_text,
        "action_capability_map": {
            action.value: capability.value
            for action, capability in ACTION_CAPABILITY_MAP.items()
        },
        "note": "Read-only. Cedar policies cannot be modified via HTTP.",
    }
