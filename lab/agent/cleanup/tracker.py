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

    def _is_safe_run_path(self, path: str) -> bool:
        """
        Strict path containment audit: ensures paths targeted for deletion
        belong strictly to this run and are confined to approved temporary/storage directories.
        """
        if not path or not isinstance(path, str):
            return False
        norm = os.path.normpath(path).replace("\\", "/")
        # Reject root, parent directory traversal, and top-level system directories
        parts = norm.split("/")
        if ".." in parts:
            return False
        forbidden_roots = {"", "/", "/tmp", "/var", "/var/run", "/etc", "/usr", "/home", "/root", "storage", "storage/lab"}
        if norm in forbidden_roots or norm.rstrip("/") in forbidden_roots:
            return False
        # Must be under /tmp or storage/lab/runs/ and tied to tt- or run_id
        is_under_tmp = norm.startswith("/tmp/tt-") or norm.startswith("/tmp/tunneltrace/")
        is_under_storage = "storage/lab/runs/" in norm
        has_run_id = bool(self.run_id and self.run_id in norm)

        return (is_under_tmp or is_under_storage) and (has_run_id or "tt-" in norm)

    def cleanup(self) -> Dict[str, Any]:
        """
        Perform comprehensive, idempotent teardown of all tracked resources.
        Enforces exact per-run process ownership and safe signal escalation.
        """
        results: Dict[str, Any] = {
            "pids_stopped": 0,
            "namespaces_deleted": 0,
            "temp_cleaned": 0,
            "errors": [],
        }

        # 1. Stop background processes (charon, tcpdump) tracked for this run via safe signal escalation
        for pid, name in list(self.tracked_pids):
            try:
                alive = self.runner.run_raw(["kill", "-0", str(pid)], check=False)
                if alive.returncode == 0:
                    logger.debug(f"Sending SIGTERM to run-owned process '{name}' (PID {pid})")
                    self.runner.run_raw(["kill", "-TERM", str(pid)], check=False)
                    time.sleep(0.2)
                    still_alive = self.runner.run_raw(["kill", "-0", str(pid)], check=False)
                    if still_alive.returncode == 0:
                        logger.warning(f"Process '{name}' (PID {pid}) alive after SIGTERM; escalating to SIGKILL")
                        self.runner.run_raw(["kill", "-KILL", str(pid)], check=False)
                    results["pids_stopped"] += 1
            except Exception as exc:
                results["errors"].append(f"kill {pid}: {exc}")
        self.tracked_pids.clear()

        # 2. Clear applied qdiscs
        for ns, iface in self.qdiscs:
            try:
                args = ["qdisc", "del", "dev", iface, "root"]
                self.runner.run_tc(args, netns=ns if ns else None, check=False)
            except Exception:
                pass
        self.qdiscs.clear()

        # 3. Terminate processes inside run namespaces, then delete namespaces
        for ns in list(self.namespaces):
            if not ns.startswith("tt-"):
                results["errors"].append(f"Refusing to delete namespace '{ns}': non-lab prefix")
                continue

            # First terminate any process running inside this specific namespace
            try:
                pids_res = self.runner.run_raw(["ip", "netns", "pids", ns], check=False)
                if pids_res.returncode == 0 and pids_res.stdout.strip():
                    for p_str in pids_res.stdout.split():
                        if p_str.isdigit():
                            ns_pid = int(p_str)
                            self.runner.run_raw(["kill", "-TERM", str(ns_pid)], check=False)
                            time.sleep(0.1)
                            if self.runner.run_raw(["kill", "-0", str(ns_pid)], check=False).returncode == 0:
                                self.runner.run_raw(["kill", "-KILL", str(ns_pid)], check=False)
                            results["pids_stopped"] += 1
            except Exception as exc:
                results["errors"].append(f"netns pids kill {ns}: {exc}")

            try:
                logger.debug(f"Deleting run-owned namespace: {ns}")
                self.runner.run_raw(["ip", "netns", "del", ns], check=False)
                results["namespaces_deleted"] += 1
            except Exception as exc:
                results["errors"].append(f"netns del {ns}: {exc}")
        self.namespaces.clear()

        # 4. Clean temporary runtime paths inside run-owned directory
        for p in list(self.temp_paths):
            if not self._is_safe_run_path(p):
                logger.error(f"Refusing to delete unsafe or unconfined path '{p}'")
                results["errors"].append(f"unsafe path rejected: {p}")
                continue
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
    def clean_all_stale_resources(
        cls,
        runner: Optional[SystemRunner] = None,
        run_id: Optional[str] = None
    ) -> Dict[str, int]:
        """
        Safely scans for and purges dangling 'tt-*' namespaces from crashed runs.
        Terminates ONLY processes running inside those verified lab namespaces using
        kernel network namespace discovery (ip netns pids). Never invokes global pkill.
        """
        exec_runner = runner or SystemRunner()
        cleaned = {"namespaces": 0, "pids": 0}
        target_prefix = f"tt-{run_id}-" if run_id else "tt-"

        try:
            res = exec_runner.run_raw(["ip", "netns", "list"], check=False)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    ns = line.split()[0].strip() if line.split() else ""
                    if ns.startswith(target_prefix):
                        # Terminate ONLY processes strictly inside this network namespace
                        try:
                            pids_res = exec_runner.run_raw(["ip", "netns", "pids", ns], check=False)
                            if pids_res.returncode == 0 and pids_res.stdout.strip():
                                for p_str in pids_res.stdout.split():
                                    if p_str.isdigit():
                                        ns_pid = int(p_str)
                                        exec_runner.run_raw(["kill", "-TERM", str(ns_pid)], check=False)
                                        time.sleep(0.1)
                                        if exec_runner.run_raw(["kill", "-0", str(ns_pid)], check=False).returncode == 0:
                                            exec_runner.run_raw(["kill", "-KILL", str(ns_pid)], check=False)
                                        cleaned["pids"] += 1
                        except Exception as exc:
                            logger.debug(f"Error terminating processes in stale namespace '{ns}': {exc}")

                        logger.warning(f"Purging verified stale lab namespace: {ns}")
                        exec_runner.run_raw(["ip", "netns", "del", ns], check=False)
                        cleaned["namespaces"] += 1
        except Exception as exc:
            logger.error(f"Error querying stale namespaces: {exc}")

        return cleaned

