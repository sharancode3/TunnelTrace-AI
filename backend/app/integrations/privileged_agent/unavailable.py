"""Default implementation of PrivilegedAgentClient reflecting Stage-1 unconfigured boundary."""

from typing import Any

from app.integrations.privileged_agent.base import (
    AgentStatus,
    AgentStatusResponse,
    PrivilegedAgentClient,
    PrivilegedAgentUnavailableError,
)


class UnavailablePrivilegedAgentClient(PrivilegedAgentClient):
    """Placeholder client representing an unconfigured or disabled Class B privileged agent."""

    def __init__(
        self,
        enabled: bool = False,
        endpoint: str = "",
        reason: str = "Class B Privileged Network Agent is not configured in Stage 1 architecture.",
    ) -> None:
        self.enabled = enabled
        self.endpoint = endpoint
        self.reason = reason

    async def get_status(self) -> AgentStatusResponse:
        """Return truthful unconfigured status without throwing unexpected errors."""
        status = AgentStatus.UNAVAILABLE if self.enabled else AgentStatus.NOT_CONFIGURED
        return AgentStatusResponse(
            status=status,
            available=False,
            configured=self.enabled,
            endpoint=self.endpoint,
            message=self.reason,
        )

    async def ping(self) -> bool:
        """Ping returns False as the agent is intentionally not active in Stage 1."""
        return False

    async def execute_action(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        """Reject execution as Class B is not available in Stage 1."""
        raise PrivilegedAgentUnavailableError(
            f"Cannot execute '{action}': Class B Privileged Network Agent is not available in Stage 1."
        )
