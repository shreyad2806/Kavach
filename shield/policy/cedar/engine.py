"""
Cedar Policy Engine Adapter for Kavach Shield.

This module provides a thin adapter around cedarpy to evaluate Cedar policies.
The Cedar engine is authoritative for authorization decisions — this module
never calculates its own decision.

Architecture:
    ActionRequest
        ↓
    CedarAdapter.evaluate()
        ↓
    cedarpy.is_authorized()
        ↓
    Cedar policies (.cedar)
        ↓
    ALLOW / DENY
"""

from pathlib import Path
from typing import Optional

from cedarpy import (
    AuthzResult,
    Decision,
    PolicySet,
    Schema,
    is_authorized,
    validate_policies,
)

from shield.gateway.models import ActionRequest, AuthorizationDecision


# Paths to Cedar policy and schema files (relative to this module)
_POLICIES_PATH = Path(__file__).parent / "policies.cedar"
_SCHEMA_PATH = Path(__file__).parent / "schema.cedarschema"


class CedarAdapter:
    """
    Thin adapter around cedarpy for Cedar policy evaluation.

    Loads the static policy set once and reuses it across all authorization
    requests. Never calculates its own authorization decision — the Cedar
    engine is the sole authority.
    """

    def __init__(self, use_schema: bool = False) -> None:
        """Load policies once at initialization. Schema is optional."""
        self._policies = self._load_policies()
        self._schema = self._load_schema() if use_schema else None

    def _load_policies(self) -> PolicySet:
        """Load and parse the static Cedar policy set from file."""
        policy_str = _POLICIES_PATH.read_text(encoding="utf-8")
        return PolicySet.from_str(policy_str)

    def _load_schema(self) -> Schema:
        """Load and parse the Cedar schema from file."""
        try:
            schema_str = _SCHEMA_PATH.read_text(encoding="utf-8")
            return Schema.from_json_str(schema_str)
        except (FileNotFoundError, ValueError) as e:
            # Schema file not found or invalid - return None and work without schema
            return None

    def validate_policies(self) -> bool:
        """
        Validate that the loaded policies are syntactically correct.

        Returns True if validation passes, raises ValueError otherwise.
        """
        policy_str = _POLICIES_PATH.read_text(encoding="utf-8")
        # validate_policies requires a schema; if we don't have one, skip validation
        if self._schema is None:
            # Without schema, we can only check syntax by trying to parse
            try:
                PolicySet.from_str(policy_str)
                return True
            except Exception as e:
                raise ValueError(f"Cedar policy syntax error: {e}")
        result = validate_policies(policy_str, self._schema)
        if result.validation_passed:
            return True
        raise ValueError(
            f"Cedar policy validation failed: {result.errors}"
        )

    def evaluate(self, request: ActionRequest) -> AuthorizationDecision:
        """
        Evaluate an ActionRequest against Cedar policies.

        Maps ActionRequest fields to Cedar:
            - principal = Agent::"<source_agent>"
            - action = Action::"<action>"
            - resource = Resource::"<resource>"
            - context = {}

        Does NOT use:
            - claimed_authority (separate security concept)
            - capability (separate security concept)
            - provenance (separate security concept)

        Returns AuthorizationDecision.ALLOW or AuthorizationDecision.DENY.
        """
        cedar_request = self._map_to_cedar_request(request)

        result: AuthzResult = is_authorized(
            request=cedar_request,
            policies=self._policies,
            entities=[],
            schema=self._schema,
        )

        return self._map_decision(result.decision)

    @staticmethod
    def _map_to_cedar_request(request: ActionRequest) -> dict:
        """Map an ActionRequest to a Cedar authorization request dict."""
        return {
            "principal": f"Agent::\"{request.source_agent.value}\"",
            "action": f"Action::\"{request.action.value}\"",
            "resource": f"Resource::\"{request.resource.value}\"",
            "context": {},
        }

    @staticmethod
    def _map_decision(decision: Decision) -> AuthorizationDecision:
        """Map a Cedar Decision to an AuthorizationDecision."""
        if decision == Decision.Allow:
            return AuthorizationDecision.ALLOW
        return AuthorizationDecision.DENY
