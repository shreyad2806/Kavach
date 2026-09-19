"""Read-only Cedar policy projection.

Exposes the ACTUAL Cedar policy set loaded by the Shield CedarAdapter.  This is
strictly read-only — policy mutation is intentionally NOT implemented (the
frontend has no policy-write contract and the task forbids mutation).

The rules are parsed straight from the same ``policies.cedar`` file the engine
authorizes against, so the response can never drift from enforced policy.
"""

import re

from fastapi import APIRouter

from shield.policy.cedar.engine import _POLICIES_PATH

router = APIRouter()

_POLICY_RE = re.compile(
    r"(?P<effect>permit|forbid)\s*\(\s*"
    r"principal\s*==\s*Agent::\"(?P<principal>[^\"]+)\"\s*,\s*"
    r"action\s*==\s*Action::\"(?P<action>[^\"]+)\"\s*,\s*"
    r"resource\s*==\s*Resource::\"(?P<resource>[^\"]+)\"",
    re.MULTILINE,
)


def _parse_policies(source: str) -> list[dict]:
    return [
        {
            "effect": match.group("effect"),
            "principal": match.group("principal"),
            "action": match.group("action"),
            "resource": match.group("resource"),
        }
        for match in _POLICY_RE.finditer(source)
    ]


@router.get("")
async def list_policies() -> dict:
    source = _POLICIES_PATH.read_text(encoding="utf-8")
    policies = _parse_policies(source)
    return {
        "engine": "cedar",
        "mutable": False,
        "count": len(policies),
        "policies": policies,
    }
