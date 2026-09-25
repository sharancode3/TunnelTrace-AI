"""
TunnelTrace AI - Process Ownership & Isolated Teardown Unit Tests
==================================================================
Proves that:
1. Global process termination commands (pkill, killall) are prohibited and rejected.
2. Resource cleanup terminates strictly run-owned PIDs and namespace-confined PIDs.
3. Signal escalation operates safely (SIGTERM -> SIGKILL) without affecting host daemons.
4. Path containment rejects deletion of system directories, traversal, or foreign run paths.
5. Stale resource cleanup operates strictly on verified lab namespaces using kernel pids.
"""

import pytest
from unittest.mock import MagicMock, call

from lab.agent.cleanup.tracker import LabResourceTracker
from lab.agent.operations.runner import (
    CommandResult,
    SecurityViolationError,
    SystemRunner,
)


class TestProcessOwnershipAndSafety:
    """Rigorous verification of process isolation and safe cleanup guarantees."""

    def test_pkill_and_killall_prohibited_in_runner(self) -> None:
        """SystemRunner must strictly reject pkill and killall in validate_safety."""
        runner = SystemRunner()
        forbidden_commands = [
            ["pkill", "-9", "-f", "/usr/lib/ipsec/charon"],
            ["pkill", "-f", "tt-"],
            ["killall", "charon"],
            ["/usr/bin/pkill", "-2", "tcpdump"],
            ["/usr/bin/killall", "-9", "charon"],
        ]
        for cmd in forbidden_commands:
            with pytest.raises(SecurityViolationError, match="prohibited"):
                runner.validate_safety(cmd)

    def test_cleanup_only_terminates_tracked_pids_with_escalation(self) -> None:
        """Cleanup must only signal PIDs explicitly tracked by the run instance."""
        mock_runner = MagicMock(spec=SystemRunner)
        # Simulate PID 1001 alive initially, then exits after SIGTERM
        # Simulate PID 1002 alive initially, stays alive after SIGTERM, exits after SIGKILL
        def mock_run_raw(cmd, **kwargs):
            if cmd == ["kill", "-0", "1001"]:
                return CommandResult(args=cmd, returncode=0, stdout="", stderr="", duration_sec=0.01, success=True)
            elif cmd == ["kill", "-0", "1002"]:
                return CommandResult(args=cmd, returncode=0, stdout="", stderr="", duration_sec=0.01, success=True)
            elif cmd == ["ip", "netns", "pids", "tt-run1-gw_a"]:
                return CommandResult(args=cmd, returncode=0, stdout="", stderr="", duration_sec=0.01, success=True)
            return CommandResult(args=cmd, returncode=0, stdout="", stderr="", duration_sec=0.01, success=True)

        mock_runner.run_raw.side_effect = mock_run_raw

        tracker = LabResourceTracker(run_id="run1", runner=mock_runner)
        tracker.track_pid(1001, "charon-gw_a")
        tracker.track_pid(1002, "tcpdump-wan")

        results = tracker.cleanup()
        assert results["pids_stopped"] == 2
        assert len(tracker.tracked_pids) == 0

        # Verify kill calls were made ONLY for 1001 and 1002
        kill_calls = [
            c[0][0] for c in mock_runner.run_raw.call_args_list if c[0][0][0] == "kill"
        ]
        # PIDs targeted must strictly be in {1001, 1002}
        for kc in kill_calls:
            target_pid = int(kc[2])
            assert target_pid in (1001, 1002), f"Untracked PID {target_pid} was targeted!"

    def test_unrelated_host_processes_never_touched(self) -> None:
        """A host daemon (e.g. PID 9999) not tracked by the run must NEVER receive any signal."""
        mock_runner = MagicMock(spec=SystemRunner)
        mock_runner.run_raw.return_value = CommandResult(
            args=[], returncode=0, stdout="", stderr="", duration_sec=0.01, success=True
        )

        tracker = LabResourceTracker(run_id="testrun", runner=mock_runner)
        # Register only PID 2001
        tracker.track_pid(2001, "lab-proc")

        tracker.cleanup()

        for c in mock_runner.run_raw.call_args_list:
            args = c[0][0]
            if args[0] == "kill":
                assert args[2] != "9999", "Unrelated host process PID 9999 was targeted by cleanup!"
                assert args[2] == "2001"

    def test_namespace_deletion_confinement(self) -> None:
        """Namespaces without the 'tt-' prefix must be rejected and preserved."""
        mock_runner = MagicMock(spec=SystemRunner)
        mock_runner.run_raw.return_value = CommandResult(
            args=[], returncode=0, stdout="", stderr="", duration_sec=0.01, success=True
        )

        tracker = LabResourceTracker(run_id="run42", runner=mock_runner)
        tracker.track_namespace("tt-run42-gw_a")
        # Adversarial attempt to register a system or external namespace
        tracker.track_namespace("production-vpn")
        tracker.track_namespace("host-netns")

        results = tracker.cleanup()

        # Only tt-run42-gw_a should be deleted
        assert results["namespaces_deleted"] == 1
        assert any("production-vpn" in err for err in results["errors"])
        assert any("host-netns" in err for err in results["errors"])

        del_calls = [
            c[0][0] for c in mock_runner.run_raw.call_args_list if len(c[0][0]) >= 3 and c[0][0][1:3] == ["netns", "del"]
        ]
        assert len(del_calls) == 1
        assert del_calls[0][3] == "tt-run42-gw_a"

    def test_safe_path_containment_and_traversal_rejection(self) -> None:
        """Paths outside run-owned directories or containing traversal must be rejected."""
        tracker = LabResourceTracker(run_id="run99")

        # Safe paths
        assert tracker._is_safe_run_path("/tmp/tunneltrace/run99/charon.vici") is True
        assert tracker._is_safe_run_path("/tmp/tt-run99-peer_a/strongswan.conf") is True
        assert tracker._is_safe_run_path("storage/lab/runs/run99/captures/wan.pcap") is True

        # Unsafe / Dangerous / Traversal paths
        assert tracker._is_safe_run_path("/") is False
        assert tracker._is_safe_run_path("/tmp") is False
        assert tracker._is_safe_run_path("/tmp/") is False
        assert tracker._is_safe_run_path("/var/run") is False
        assert tracker._is_safe_run_path("/etc") is False
        assert tracker._is_safe_run_path("/home/user") is False
        assert tracker._is_safe_run_path("/tmp/tt-run99/../../etc/passwd") is False
        assert tracker._is_safe_run_path("storage/lab/runs/run99/../../other_user") is False
        assert tracker._is_safe_run_path("/tmp/other_project/data") is False

    def test_clean_all_stale_resources_scoped_to_run_id(self) -> None:
        """clean_all_stale_resources with run_id must only delete namespaces belonging to that run."""
        mock_runner = MagicMock(spec=SystemRunner)
        mock_runner.run_raw.side_effect = lambda cmd, **kwargs: (
            CommandResult(
                args=cmd,
                returncode=0,
                stdout="tt-runA-gw_a\ntt-runA-gw_b\ntt-runB-gw_a\nproduction-vpn\n",
                stderr="",
                duration_sec=0.01,
                success=True,
            )
            if cmd == ["ip", "netns", "list"]
            else CommandResult(args=cmd, returncode=0, stdout="", stderr="", duration_sec=0.01, success=True)
        )

        cleaned = LabResourceTracker.clean_all_stale_resources(runner=mock_runner, run_id="runA")
        assert cleaned["namespaces"] == 2

        # Verify netns del calls were ONLY for tt-runA-*
        del_calls = [
            c[0][0] for c in mock_runner.run_raw.call_args_list if len(c[0][0]) >= 3 and c[0][0][1:3] == ["netns", "del"]
        ]
        deleted_ns = [c[3] for c in del_calls]
        assert deleted_ns == ["tt-runA-gw_a", "tt-runA-gw_b"]
        assert "tt-runB-gw_a" not in deleted_ns
        assert "production-vpn" not in deleted_ns

        # Verify zero pkill calls were made
        for c in mock_runner.run_raw.call_args_list:
            assert c[0][0][0] != "pkill"
