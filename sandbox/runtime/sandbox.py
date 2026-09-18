import os
from typing import Any, Callable

from agents.common.schemas import SecurityEvent, ToolRequest, ToolResponse
from agents.common.identity import AgentIdentity
from sandbox.runtime.event_logger import EventLogger
from sandbox.runtime.tool_executor import ToolExecutor

class ProcessExecutionDeniedError(Exception):
    pass

class ToolAccessDeniedError(Exception):
    pass

class CredentialAccessDeniedError(Exception):
    pass

class Sandbox:
    """
    Main runtime boundary enforcing Tool, Process, and Credential isolation.
    Acts as a wrapper around the local ToolExecutor.
    """

    def __init__(self, event_logger: EventLogger | None = None) -> None:
        self.event_logger = event_logger or EventLogger()
        self.executor = ToolExecutor(self.event_logger)
        self.agent_identities: dict[str, AgentIdentity] = {}

    def register_agent(self, identity: AgentIdentity) -> None:
        """Register an agent's identity to track its allowed capabilities."""
        self.agent_identities[identity.agent_id] = identity

    def register_tool(self, operation: str, tool: Callable[..., Any]) -> None:
        """Register a tool implementation into the underlying executor."""
        self.executor.register(operation, tool)

    def _verify_credentials_scrubbed(self, agent_id: str) -> None:
        """Ensure no AWS or sensitive credentials are in the environment."""
        for key in os.environ:
            if "AWS" in key.upper() or "SECRET" in key.upper() or "TOKEN" in key.upper():
                event = SecurityEvent(
                    agent_id=agent_id,
                    event_type="CREDENTIAL_ACCESS_DENIED",
                    operation="env_access",
                    target=key,
                    success=False
                )
                self.event_logger.log(event)
                raise CredentialAccessDeniedError("Sensitive credentials found in environment.")

    def _verify_process_isolation(self, agent_id: str, request: ToolRequest) -> None:
        """Block arbitrary process execution attempts (shell, subprocess, os.system)."""
        blocked_operations = {"subprocess", "shell", "cmd", "powershell", "os.system"}
        if any(b in request.operation.lower() for b in blocked_operations):
            event = SecurityEvent(
                agent_id=agent_id,
                event_type="PROCESS_EXECUTION_DENIED",
                operation=request.operation,
                target=request.target,
                success=False
            )
            self.event_logger.log(event)
            raise ProcessExecutionDeniedError(f"Arbitrary process execution denied for '{request.operation}'.")

    def execute(self, request: ToolRequest) -> ToolResponse:
        """Execute a tool after verifying boundaries."""
        agent_id = request.agent_id

        # 1. Credential isolation check
        self._verify_credentials_scrubbed(agent_id)

        # 2. Process isolation check
        self._verify_process_isolation(agent_id, request)

        # 3. Tool isolation check
        identity = self.agent_identities.get(agent_id)
        if not identity:
            # If agent not registered, deny by default
            event = SecurityEvent(
                agent_id=agent_id,
                event_type="TOOL_ACCESS_DENIED",
                operation=request.operation,
                target=request.target,
                success=False,
                metadata={"reason": "Agent not registered"}
            )
            self.event_logger.log(event)
            return ToolResponse(request.request_id, False, error="Agent not registered in sandbox.")

        if request.operation not in identity.capabilities:
            event = SecurityEvent(
                agent_id=agent_id,
                event_type="TOOL_ACCESS_DENIED",
                operation=request.operation,
                target=request.target,
                success=False,
                metadata={"reason": "Capability not allowed"}
            )
            self.event_logger.log(event)
            return ToolResponse(request.request_id, False, error=f"Tool access denied for operation: {request.operation}")

        # Proceed with execution
        return self.executor.execute(request)
