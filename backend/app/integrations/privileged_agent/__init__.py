"""Privileged Network Agent integration abstractions and status models."""

from app.core.config import get_settings
from app.integrations.privileged_agent.base import (
    AgentStatus,
    AgentStatusResponse,
    PrivilegedAgentClient,
    PrivilegedAgentUnavailableError,
)
from app.integrations.privileged_agent.local import LocalPrivilegedAgentClient
from app.integrations.privileged_agent.unavailable import UnavailablePrivilegedAgentClient

_agent_client: PrivilegedAgentClient | None = None


def get_privileged_agent_client() -> PrivilegedAgentClient:
    """Retrieve the configured PrivilegedAgentClient."""
    global _agent_client
    if _agent_client is None:
        settings = get_settings()
        if settings.netagent_enabled:
            _agent_client = LocalPrivilegedAgentClient(
                enabled=True,
                endpoint=settings.netagent_endpoint or "local://unix-ns",
            )
        else:
            _agent_client = UnavailablePrivilegedAgentClient(
                enabled=False,
                endpoint=settings.netagent_endpoint,
            )
    return _agent_client



def set_privileged_agent_client(client: PrivilegedAgentClient | None) -> None:
    """Explicitly set or override the active PrivilegedAgentClient."""
    global _agent_client
    _agent_client = client


def reset_privileged_agent_client() -> None:
    """Reset the singleton client instance (useful for test isolation)."""
    global _agent_client
    _agent_client = None


__all__ = [
    "AgentStatus",
    "AgentStatusResponse",
    "PrivilegedAgentClient",
    "PrivilegedAgentUnavailableError",
    "UnavailablePrivilegedAgentClient",
    "LocalPrivilegedAgentClient",
    "get_privileged_agent_client",
    "set_privileged_agent_client",
    "reset_privileged_agent_client",
]
