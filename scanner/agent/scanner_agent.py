"""
Scanner Agent — Strands Agents SDK integration.

The agent reads completed scan results and produces a human-readable
security report for the operator. It is purely advisory.

The verdict has already been determined deterministically by the pipeline.
The agent explains it — it does not change it.

Usage:
    from scanner.agent.scanner_agent import explain_scan
    report = explain_scan("art-abc123")
    print(report)
"""

import os

from strands import Agent
from strands.models import BedrockModel

from scanner.agent.prompts import SYSTEM_PROMPT
from scanner.agent.tools import get_artifact_info, get_scan_findings, get_scan_verdict


def _build_agent() -> Agent:
    model = BedrockModel(
        model_id=os.environ.get("BEDROCK_MODEL_ID", "anthropic.claude-3-5-haiku-20241022-v1:0"),
        region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
    )
    return Agent(
        model=model,
        system_prompt=SYSTEM_PROMPT,
        tools=[get_artifact_info, get_scan_findings, get_scan_verdict],
    )


def explain_scan(artifact_id: str) -> str:
    """
    Run the scanner agent against a completed scan.
    Returns a plain-English security report string.

    The agent:
      1. Fetches artifact metadata via get_artifact_info()
      2. Fetches findings via get_scan_findings()
      3. Fetches the verdict via get_scan_verdict()
      4. Produces a human-readable explanation

    The agent cannot modify the verdict or any security state.
    """
    agent = _build_agent()
    prompt = (
        f"Please analyse the scan results for artifact '{artifact_id}' "
        f"and provide a security report for the operator. "
        f"Use the available tools to retrieve the findings and verdict."
    )
    result = agent(prompt)
    return str(result)
