"""Interface abstraction for the Execution Class B Privileged Network Agent."""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AgentStatus(str, Enum):
    """Operational status of the Privileged Network Agent."""

    UP = "UP"
    DOWN = "DOWN"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    UNAVAILABLE = "UNAVAILABLE"


class AgentStatusResponse(BaseModel):
    """Structured response representing the state of the Privileged Network Agent."""

    status: AgentStatus = Field(..., description="Operational status enum")
    available: bool = Field(False, description="Whether the agent is currently available")
    configured: bool = Field(False, description="Whether the agent is configured in settings")
    endpoint: str = Field("", description="Configured endpoint address")
    message: str = Field("", description="Diagnostic message or boundary description")


class PrivilegedAgentUnavailableError(RuntimeError):
    """Raised when an action is dispatched to an unavailable or unconfigured Class B agent."""

    pass


class PrivilegedAgentClient(ABC):
    """Abstract client interface for interacting with the Class B privileged network daemon.

    All network modifications, strongSwan configurations, and live packet sniffing are strictly
    isolated to Class B. Class A services interact solely through typed, non-shell methods.
    """

    @abstractmethod
    async def get_status(self) -> AgentStatusResponse:
        """Check availability and capabilities of the privileged network agent."""
        pass

    @abstractmethod
    async def ping(self) -> bool:
        """Ping the privileged agent daemon."""
        pass

    @abstractmethod
    async def execute_action(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        """Execute a typed, allowlisted privileged action."""
        pass
