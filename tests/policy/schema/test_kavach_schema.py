"""
Cedar schema tests for Kavach Shield.

These tests verify that the canonical Cedar JSON schema is valid, contains
the correct entity types and actions, and properly validates Phase 7 policies.
"""

import json
from pathlib import Path

import pytest
from cedarpy import Schema, validate_policies

# Schema path
SCHEMA_PATH = Path("shield/policy/schemas/kavach.cedarschema.json")
POLICIES_PATH = Path("shield/policy/cedar/policies.cedar")

# Expected actions from Phase 1
EXPECTED_ACTIONS = [
    "research.search",
    "research.read",
    "coding.read",
    "coding.write",
    "coding.test",
    "deployment.preview",
    "deployment.deploy",
    "deployment.production",
    "verification.test",
    "orchestrator.delegate",
    "orchestrator.coordinate",
]

# Expected entity types
EXPECTED_ENTITY_TYPES = ["Agent", "Resource"]


# ============================================================================
# TEST 1 — Schema file exists
# ============================================================================

def test_1_schema_file_exists():
    """Verify the schema file exists at the expected path."""
    assert SCHEMA_PATH.exists(), f"Schema file not found: {SCHEMA_PATH}"


# ============================================================================
# TEST 2 — Valid JSON
# ============================================================================

def test_2_valid_json():
    """Load the schema with Python json and verify it parses successfully."""
    with open(SCHEMA_PATH, "r") as f:
        schema_dict = json.load(f)
    assert isinstance(schema_dict, dict), "Schema must be a JSON object"


# ============================================================================
# TEST 3 — Entity types
# ============================================================================

def test_3_entity_types():
    """Verify the schema contains exactly the intended core entity types."""
    with open(SCHEMA_PATH, "r") as f:
        schema_dict = json.load(f)

    # Get the namespace definition (empty string key = default namespace)
    namespace_def = schema_dict.get("", {})
    entity_types = list(namespace_def.get("entityTypes", {}).keys())

    for expected_type in EXPECTED_ENTITY_TYPES:
        assert expected_type in entity_types, f"Missing entity type: {expected_type}"

    # No Action entity type (Cedar treats Action as the action entity type)
    assert "Action" not in entity_types, "Action should not be in entityTypes"


# ============================================================================
# TEST 4 — All supported actions exist
# ============================================================================

def test_4_all_supported_actions_exist():
    """Verify exactly the 10 expected actions exist in the schema."""
    with open(SCHEMA_PATH, "r") as f:
        schema_dict = json.load(f)

    namespace_def = schema_dict.get("", {})
    actions = list(namespace_def.get("actions", {}).keys())

    for expected_action in EXPECTED_ACTIONS:
        assert expected_action in actions, f"Missing action: {expected_action}"

    # No unexpected actions
    assert len(actions) == len(EXPECTED_ACTIONS), (
        f"Expected {len(EXPECTED_ACTIONS)} actions, got {len(actions)}. "
        f"Unexpected actions: {set(actions) - set(EXPECTED_ACTIONS)}"
    )


# ============================================================================
# TEST 5 — Action applicability
# ============================================================================

def test_5_action_applicability():
    """For every declared action, verify principalTypes contains Agent and resourceTypes contains Resource."""
    with open(SCHEMA_PATH, "r") as f:
        schema_dict = json.load(f)

    namespace_def = schema_dict.get("", {})
    actions = namespace_def.get("actions", {})

    for action_name, action_def in actions.items():
        applies_to = action_def.get("appliesTo", {})

        principal_types = applies_to.get("principalTypes", [])
        assert "Agent" in principal_types, (
            f"Action {action_name}: principalTypes must contain Agent"
        )

        resource_types = applies_to.get("resourceTypes", [])
        assert "Resource" in resource_types, (
            f"Action {action_name}: resourceTypes must contain Resource"
        )


# ============================================================================
# TEST 6 — Actual Cedar schema validation
# ============================================================================

def test_6_cedar_schema_validation():
    """Use cedarpy to validate the existing Phase 7 policy set against the new schema."""
    with open(SCHEMA_PATH, "r") as f:
        schema_json = f.read()

    schema = Schema.from_json_str(schema_json)

    with open(POLICIES_PATH, "r") as f:
        policies_str = f.read()

    result = validate_policies(policies_str, schema)
    assert result.validation_passed, (
        f"Phase 7 policies failed validation: {result.errors}"
    )


# ============================================================================
# TEST 7 — Invalid action is rejected
# ============================================================================

def test_7_invalid_action_rejected():
    """Verify an undeclared action causes schema validation failure."""
    with open(SCHEMA_PATH, "r") as f:
        schema_json = f.read()

    schema = Schema.from_json_str(schema_json)

    invalid_policy = (
        'permit (principal == Agent::"test", '
        'action == Action::"not-a-real-action", '
        'resource == Resource::"test");'
    )

    result = validate_policies(invalid_policy, schema)
    assert not result.validation_passed, (
        "Invalid action policy should have been rejected by schema validation"
    )


# ============================================================================
# TEST 8 — deployment.deploy declared but not permitted
# ============================================================================

def test_8_deployment_deploy_declared_not_permitted():
    """
    Verify:
    - deployment.deploy exists in the schema
    - there is no Phase 7 permit policy granting research-01 deployment.deploy

    This confirms schema declaration and authorization policy remain separate.
    """
    with open(SCHEMA_PATH, "r") as f:
        schema_dict = json.load(f)

    namespace_def = schema_dict.get("", {})
    actions = namespace_def.get("actions", {})

    # deployment.deploy must be declared
    assert "deployment.deploy" in actions, "deployment.deploy must be in schema"

    # Read policies and check no research-01 deployment.deploy permit exists
    with open(POLICIES_PATH, "r") as f:
        policies_content = f.read()

    # Check that there's no permit for research-01 with deployment.deploy
    assert 'research-01' not in policies_content or 'deployment.deploy' not in policies_content.split('research-01')[1].split(';')[0] if 'research-01' in policies_content else True, (
        "Phase 7 should not have a permit policy for research-01 with deployment.deploy"
    )
