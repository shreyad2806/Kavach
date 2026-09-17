#!/usr/bin/env python3
"""
Exports Pydantic JSON schemas for Kavach's major public contracts.
Target directory: architecture/contracts/
"""

import json
import sys
from pathlib import Path

# Ensure project root is on sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from kavach.gateway import ActionRequest, AuthorizationResult
from kavach.identity import AgentIdentity
from kavach.telemetry import SecurityEvent


def export_schemas() -> None:
    contracts_dir = ROOT_DIR / "architecture" / "contracts"
    contracts_dir.mkdir(parents=True, exist_ok=True)

    models = {
        "AgentIdentity": AgentIdentity,
        "ActionRequest": ActionRequest,
        "AuthorizationResult": AuthorizationResult,
        "SecurityEvent": SecurityEvent,
    }

    print(f"Exporting contract JSON schemas to {contracts_dir}...")
    for name, model_cls in models.items():
        schema_path = contracts_dir / f"{name}.json"
        schema_data = model_cls.model_json_schema()
        with open(schema_path, "w", encoding="utf-8") as f:
            json.dump(schema_data, f, indent=2)
            f.write("\n")
        print(f"  [OK] Exported {schema_path.name}")

    print("All contract schemas successfully exported.")


if __name__ == "__main__":
    export_schemas()
