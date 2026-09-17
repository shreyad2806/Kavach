from collections.abc import Callable
from typing import Any

from agents.common.schemas import SecurityEvent, ToolRequest, ToolResponse
from sandbox.runtime.event_logger import EventLogger


class ToolExecutor:
    """
    Executes tools requested by agents.

    This local executor intentionally contains no authorization logic.
    KAVACH will later sit in front of this component and decide whether
    a ToolRequest is allowed to execute.
    """

    def __init__(self, event_logger: EventLogger) -> None:
        self.event_logger = event_logger
        self._tools: dict[str, Callable[..., Any]] = {}

    def register(
        self,
        operation: str,
        tool: Callable[..., Any],
    ) -> None:
        """Register a tool implementation."""
        self._tools[operation] = tool

    def execute(self, request: ToolRequest) -> ToolResponse:
        """Execute a registered tool."""
        tool = self._tools.get(request.operation)

        if tool is None:
            response = ToolResponse(
                request_id=request.request_id,
                success=False,
                error=f"Unknown operation: {request.operation}",
            )

            self._log_event(request, success=False)
            return response

        try:
            result = tool(**request.arguments)

            response = ToolResponse(
                request_id=request.request_id,
                success=True,
                result=result,
            )

            self._log_event(request, success=True)
            return response

        except Exception as exc:
            response = ToolResponse(
                request_id=request.request_id,
                success=False,
                error=str(exc),
            )

            self._log_event(request, success=False)
            return response

    def _log_event(
        self,
        request: ToolRequest,
        success: bool,
    ) -> None:
        event = SecurityEvent(
    agent_id=request.agent_id,
    event_type="TOOL_CALL",
    operation=request.operation,
    target=request.target,
    success=success,
    )

        self.event_logger.log(event)