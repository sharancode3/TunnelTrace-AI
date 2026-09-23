"""
TunnelTrace AI - Resource Tracking, Concurrency Locking, and Idempotent Cleanup
==============================================================================
Guarantees strict resource accounting for all created Linux namespaces, veth interfaces,
child processes, and runtime temporary paths. Prevents concurrent lab executions via
a filesystem mutex lock, and cleans up cleanly upon completion or abort.
"""

from typing import Optional, Dict, List, Set, Tuple, Any
import logging
import os
import signal
import sys
import time
from pathlib import Path

from lab.agent.operations.runner import SystemRunner

logger = logging.getLogger(__name__)


class LabConcurrencyError(RuntimeError):
    """Raised when another lab execution currently holds the exclusive runtime lock."""
    pass


class LabResourceTracker:
    """Tracks all namespaces, virtual interfaces, processes, and temporary artifacts for a lab run."""

    def __init__(
        self,
        run_id: Optional[str] = None,
        runner: Optional[SystemRunner] = None,
        lock_dir: Optional[Path] = None
    ) -> None:
        self.run_id = run_id or "default"
        self.runner = runner or SystemRunner()
        self.prefix = f"tt-{self.run_id}"

        # Tracked resources
        self.namespaces: Set[str] = set()
        self.interfaces: Set[str] = set()
        self.veth_pairs: List[Tuple[str, str]] = []  # (end1, end2)
        self.tracked_pids: List[Tuple[int, str]] = []  # (pid, name)
        self.temp_paths: List[str] = []  # paths on linux /tmp
        self.qdiscs: List[Tuple[str, str]] = []  # (ns, iface)

        # File-based concurrency lock
        base_lock_dir = lock_dir or Path(__file__).resolve().parent.parent.parent / "runtime"
        base_lock_dir.mkdir(parents=True, exist_ok=True)
        self.lock_file = base_lock_dir / "lab.lock"
        self._acquired_lock = False

    @property
    def tracked_namespaces(self) -> List[str]:
        return sorted(list(self.namespaces))

    @property
    def tracked_interfaces(self) -> List[str]:
        return sorted(list(self.interfaces))

    def acquire_lock(self, run_id: Optional[str] = None, timeout_sec: float = 5.0) -> None:
        """Acquire exclusive lab execution lock to prevent overlapping runs."""
        if run_id:
            self.run_id = run_id
            self.prefix = f"tt-{run_id}"

        start_time = time.time()
        while time.time() - start_time < timeout_sec:
            if not self.lock_file.exists():
                try:
                    self.lock_file.write_text(
                        f"PID={os.getpid()}\nRUN_ID={self.run_id}\nTIMESTAMP={time.time()}\n",
                        encoding="utf-8",
                    )
                    self._acquired_lock = True
                    logger.debug(f"Acquired exclusive lab lock for run '{self.run_id}'")
                    return
                except OSError:
                    pass

            # Check if existing lock is stale (older than 10 minutes)
            try:
                content = self.lock_file.read_text(encoding="utf-8")
                lines = dict(line.split("=", 1) for line in content.splitlines() if "=" in line)
                lock_time = float(lines.get("TIMESTAMP", 0))
                if time.time() - lock_time > 600:
                    logger.warning("Detected stale lab lock (> 600s). Forcing recovery.")
                    self.lock_file.unlink(missing_ok=True)
                    continue
            except Exception:
                pass

            time.sleep(0.5)

        raise LabConcurrencyError(
            f"Failed to acquire exclusive lab lock after {timeout_sec}s. Another lab execution is currently active."
        )

    def release_lock(self) -> None:
        """Release the lab execution lock."""
        if self._acquired_lock and self.lock_file.exists():
            try:
                self.lock_file.unlink(missing_ok=True)
                self._acquired_lock = False
                logger.debug(f"Released lab lock for run '{self.run_id}'")
            except OSError as exc:
                logger.warning(f"Failed to cleanly release lock file: {exc}")

    def track_namespace(self, ns_name: str) -> str:
        """Register and return an owned namespace name."""
        self.namespaces.add(ns_name)
        return ns_name

    register_namespace = track_namespace

    def track_interface(self, iface_name: str) -> str:
        """Register a created interface name."""
        self.interfaces.add(iface_name)
        return iface_name

    def track_pid(self, pid: int, name: str) -> None:
        """Register a background process PID for managed lifecycle."""
        self.tracked_pids.append((pid, name))

    register_pid = track_pid

    def track_path(self, path: str) -> None:
        """Register temporary files or socket directories for deletion on cleanup."""
        self.temp_paths.append(path)

    register_temp_path = track_path

    def track_veth_pair(self, iface_a: str, iface_b: str) -> None:
        """Register a created veth link."""
        self.veth_pairs.append((iface_a, iface_b))
        self.interfaces.add(iface_a)
        self.interfaces.add(iface_b)

    register_veth_pair = track_veth_pair

    def track_qdisc(self, interface: str, namespace: Optional[str] = None) -> None:
        """Register an interface with an applied tc qdisc."""
        self.qdiscs.append((namespace or "", interface))

    register_qdisc = track_qdisc

    def cleanup(self) -> Dict[str, Any]:
        """Perform comprehensive, idempotent teardown of all tracked resources."""
        results: Dict[str, Any] = {
            "pids_stopped": 0,
            "namespaces_deleted": 0,
            "temp_cleaned": 0,
            "errors": [],
        }

        # 1. Stop background processes (tcpdump, charon)
        for pid, name in self.tracked_pids:
            try:
                logger.debug(f"Stopping tracked process '{name}' (PID {pid})")
                self.runner.run_raw(["kill", "-TERM", str(pid)], check=False)
                results["pids_stopped"] += 1
            except Exception as exc:
                results["errors"].append(f"kill {pid}: {exc}")

        # 2. Clear applied qdiscs
        for ns, iface in self.qdiscs:
            try:
                args = ["qdisc", "del", "dev", iface, "root"]
                self.runner.run_tc(args, netns=ns if ns else None, check=False)
            except Exception:
                pass

        # 3. Delete tracked namespaces (automatically destroys interfaces inside them)
        for ns in list(self.namespaces):
            try:
                logger.debug(f"Deleting namespace: {ns}")
                self.runner.run_raw(["ip", "netns", "del", ns], check=False)
                results["namespaces_deleted"] += 1
            except Exception as exc:
                results["errors"].append(f"netns del {ns}: {exc}")
        self.namespaces.clear()

        # 4. Clean temporary runtime paths inside Linux
        for p in self.temp_paths:
            try:
                self.runner.run_raw(["rm", "-rf", p], check=False)
                results["temp_cleaned"] += 1
            except Exception as exc:
                results["errors"].append(f"rm {p}: {exc}")
        self.temp_paths.clear()

        # 5. Release execution lock
        self.release_lock()

        return results

    clean_current_run = cleanup

    @classmethod
    def clean_all_stale_resources(cls, runner: Optional[SystemRunner] = None) -> Dict[str, int]:
        """Safety utility to scan for and purge any dangling 'tt-*' namespaces from crashed runs."""
        exec_runner = runner or SystemRunner()
        cleaned = {"namespaces": 0, "pids": 0}

        try:
            res = exec_runner.run_raw(["ip", "netns", "list"], check=False)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    ns = line.split()[0].strip() if line.split() else ""
                    if ns.startswith("tt-"):
                        logger.warning(f"Purging stale lab namespace: {ns}")
                        exec_runner.run_raw(["ip", "netns", "del", ns], check=False)
                        cleaned["namespaces"] += 1
        except Exception as exc:
            logger.error(f"Error querying stale namespaces: {exc}")

        # Kill any lingering charon or tcpdump processes with 'tt-' in arguments
        try:
            pkill_res = exec_runner.run_raw(["pkill", "-f", "tt-"], check=False)
            if pkill_res.returncode == 0:
                cleaned["pids"] += 1
        except Exception:
            pass

        return cleaned
