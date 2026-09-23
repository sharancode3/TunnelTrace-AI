"""Unit tests for the Class B Privileged Network Agent interface boundary."""

import pytest

from app.integrations.privileged_agent import (
    PrivilegedAgentUnavailableError,
    UnavailablePrivilegedAgentClient,
)


@pytest.mark.asyncio
async def test_privileged_agent_boundary_not_configured():
    """Verify the Stage-1 boundary returns NOT_CONFIGURED honestly and without hallucination."""
    client = UnavailablePrivilegedAgentClient(reason="Class B is deferred to Stage 2.")
    status = await client.get_status()

    assert not status.available
    assert not status.configured
    assert status.status == "NOT_CONFIGURED"
    assert "Stage 2" in status.message


@pytest.mark.asyncio
async def test_privileged_agent_command_execution_rejected():
    """Ensure privileged execution requests raise clear, unhandled unavailable errors."""
    client = UnavailablePrivilegedAgentClient()

    with pytest.raises(PrivilegedAgentUnavailableError) as exc_info:
        await client.execute_action("configure_ipsec", {})

    assert "Class B Privileged Network Agent is not available" in str(exc_info.value)
