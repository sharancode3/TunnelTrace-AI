"""Unit tests for Remediation Safety, Concurrency Locking, and Privilege Boundaries."""

from __future__ import annotations

import asyncio
from pathlib import Path
import pytest

from app.integrations.privileged_agent.local import LocalPrivilegedAgentClient
from lab.agent.cleanup.tracker import LabResourceTracker, LabConcurrencyError


@pytest.mark.asyncio
async def test_privileged_agent_allowlist_enforcement():
    """Verify that arbitrary shell or unallowlisted actions are strictly rejected."""
    client = LocalPrivilegedAgentClient(enabled=True)

    # 1. Unallowlisted action
    with pytest.raises(ValueError, match="not in the privileged allowlist"):
        await client.execute_action("RUN_ARBITRARY_COMMAND", {"cmd": "rm -rf /"})

    with pytest.raises(ValueError, match="not in the privileged allowlist"):
        await client.execute_action("EXEC_SHELL", {"shell": "cat /etc/shadow"})


@pytest.mark.asyncio
async def test_path_traversal_rejection_in_backup_and_apply():
    """Verify that file writes or reads targeting outside managed lab paths are blocked."""
    client = LocalPrivilegedAgentClient(enabled=True)

    # Backup outside lab directory
    with pytest.raises(PermissionError, match="outside managed lab"):
        await client.execute_action(
            "BACKUP_CONFIG",
            {
                "active_config_path": "/etc/shadow",
                "backup_dest_path": "/etc/shadow.bak",
            },
        )

    # Apply outside lab directory
    with pytest.raises(PermissionError, match="outside managed lab"):
        await client.execute_action(
            "APPLY_CONFIG",
            {
                "target_path": "C:\\Windows\\System32\\cmd.exe",
                "config_text": "connections {}",
            },
        )


def test_testbed_concurrency_lock_prevents_racing():
    """Verify exclusive concurrency locking prevents simultaneous mutating lab runs."""
    tracker1 = LabResourceTracker(run_id="run-1")
    tracker2 = LabResourceTracker(run_id="run-2")

    try:
        # Run 1 acquires lock
        tracker1.acquire_lock("run-1", timeout_sec=2.0)
        assert tracker1.lock_file.exists()

        # Run 2 must fail to acquire lock while held by Run 1
        with pytest.raises(LabConcurrencyError, match="Failed to acquire exclusive lab lock"):
            tracker2.acquire_lock("run-2", timeout_sec=0.5)

    finally:
        tracker1.release_lock()
        assert not tracker1.lock_file.exists()
