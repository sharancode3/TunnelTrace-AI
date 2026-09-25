"""
TunnelTrace AI - Lab Packet Capture Manager
===========================================
Manages isolated, authorized tcpdump packet capture processes on lab interfaces.
Flushes buffers with SIGINT, calculates SHA-256 digests, and validates PCAP headers.
Never captures physical host interfaces.
"""

import hashlib
import os
import re
import shlex
import signal
import subprocess
import time
from typing import Any, Dict, List, Optional
from lab.agent.cleanup.tracker import LabResourceTracker
from lab.agent.operations.runner import SecurityViolationError, SystemRunner


class CaptureManager:
    """Manages packet capture on isolated lab interfaces."""

    # Default BPF filter capturing IKE (500), NAT-T (4500), ESP (proto 50), and AH (proto 51)
    WAN_IPSEC_FILTER = "udp port 500 or udp port 4500 or esp or ah"
    
    # Plaintext filter captures all ICMP/TCP/UDP traffic inside private subnets
    PLAINTEXT_FILTER = "icmp or icmp6 or tcp or udp"

    def __init__(self, runner: SystemRunner, tracker: Optional[LabResourceTracker] = None) -> None:
        self.runner = runner
        self.tracker = tracker
        self.active_captures: Dict[str, Dict[str, Any]] = {}

    def start_capture(
        self,
        capture_id: str,
        interface: str,
        output_pcap_path: str,
        netns: Optional[str] = None,
        bpf_filter: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Starts a background tcpdump process inside a namespace (or root lab netns).
        Uses -U (packet-buffered) to ensure packets are flushed immediately.
        """
        self.runner.validate_safety(interface)

        # Sanitize capture_id to prevent path injection in pid_file
        clean_cap_id = re.sub(r"[^a-zA-Z0-9_\-]", "", capture_id)
        if not clean_cap_id or clean_cap_id != capture_id:
            raise ValueError(f"Invalid capture_id '{capture_id}': Must be alphanumeric or hyphens/underscores.")

        # Ensure directory exists in Linux environment
        output_dir = os.path.dirname(output_pcap_path)
        if self.runner.is_wsl:
            runtime_dir = self.runner._to_wsl_path(output_dir) if not output_dir.startswith("/") else output_dir
            self.runner.run_raw(["mkdir", "-p", runtime_dir])
            wsl_pcap_path = self.runner._to_wsl_path(output_pcap_path) if not output_pcap_path.startswith("/") else output_pcap_path
        else:
            runtime_dir = output_dir
            os.makedirs(runtime_dir, exist_ok=True)
            wsl_pcap_path = output_pcap_path

        # Build tcpdump command line
        # Flags: -i <dev> -s 0 (full pkt) -U (packet-buffered flush) -w <file>
        cmd: List[str] = []
        if netns:
            if not re.match(r"^[a-zA-Z0-9_\-]+$", netns):
                raise SecurityViolationError(f"Invalid netns name: '{netns}'")
            cmd.extend([self.runner.ip_bin, "netns", "exec", netns])
        cmd.extend([self.runner.tcpdump_bin, "-i", interface, "-s", "0", "-U", "-w", wsl_pcap_path])

        if bpf_filter:
            # Check for shell metacharacters
            for forbidden in (";", "&", "|", "`", "$", "(", ")", ">", "<", "\n", "\r", "\t", "\\"):
                if forbidden in bpf_filter:
                    raise SecurityViolationError(f"bpf_filter contains forbidden shell character: {forbidden!r}")
            clean_bpf = bpf_filter.strip()
            if not re.match(r"^[a-zA-Z0-9\s_\-\.:/]+$", clean_bpf):
                raise SecurityViolationError(f"bpf_filter contains invalid characters: '{clean_bpf}'")
            # tcpdump accepts BPF filter expressions as trailing positional args
            cmd.extend(clean_bpf.split())

        # Validate entire command array through safety engine
        self.runner.validate_safety(cmd)

        pid_file = f"{runtime_dir}/tcpdump_{clean_cap_id}.pid"
        quoted_args = " ".join(shlex.quote(c) for c in cmd)
        wrapped_cmd = ["/bin/sh", "-c", f"echo $$ > '{shlex.quote(pid_file)}' && exec {quoted_args}"]

        # Wrap with wsl if on Windows
        if self.runner.is_wsl:
            full_cmd = ["wsl", "-u", "root", "-e"] + wrapped_cmd
        else:
            full_cmd = wrapped_cmd

        # Spawn background process
        proc = subprocess.Popen(
            full_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Allow tcpdump a moment to attach to the interface
        time.sleep(0.5)
        if proc.poll() is not None:
            stdout, stderr = proc.communicate()
            raise RuntimeError(f"tcpdump failed to start on {interface} (netns: {netns}): {stderr.strip()} {stdout.strip()}")

        linux_pid: Optional[int] = None
        try:
            pid_read = self.runner.run_raw(["cat", pid_file], check=False)
            if pid_read.success and pid_read.stdout.strip().isdigit():
                linux_pid = int(pid_read.stdout.strip())
        except Exception:
            pass

        capture_info = {
            "capture_id": capture_id,
            "process": proc,
            "pid": proc.pid,
            "linux_pid": linux_pid,
            "pid_file": pid_file,
            "interface": interface,
            "netns": netns,
            "output_path": output_pcap_path,
            "wsl_path": wsl_pcap_path,
            "bpf_filter": bpf_filter,
            "started_at": time.time()
        }
        self.active_captures[capture_id] = capture_info

        if self.tracker:
            self.tracker.track_pid(proc.pid, f"tcpdump-proc-{capture_id}")
            if linux_pid:
                self.tracker.track_pid(linux_pid, f"tcpdump-linux-{capture_id}")

        return {
            "status": "CAPTURING",
            "capture_id": capture_id,
            "interface": interface,
            "netns": netns,
            "pid": proc.pid,
            "linux_pid": linux_pid,
            "pcap_path": output_pcap_path
        }

    def stop_capture(self, capture_id: str) -> Dict[str, Any]:
        """
        Gracefully stops tcpdump using SIGINT to guarantee buffer flush and pcap closing.
        Terminates the exact tracked PID without broad process matching.
        Computes SHA-256 hash and packet count.
        """
        if capture_id not in self.active_captures:
            raise KeyError(f"Capture ID '{capture_id}' not found in active captures")

        cap = self.active_captures.pop(capture_id)
        proc: subprocess.Popen = cap["process"]
        wsl_pcap = cap["wsl_path"]
        output_path = cap["output_path"]
        linux_pid = cap.get("linux_pid")
        pid_file = cap.get("pid_file")

        # Send SIGINT to tcpdump so it finalizes the pcap header
        try:
            if self.runner.is_wsl and linux_pid:
                # Terminate the exact verified Linux PID
                self.runner.run_raw(["kill", "-2", str(linux_pid)], check=False)
                time.sleep(0.5)
                # Check alive and escalate to SIGTERM / SIGKILL if needed
                alive = self.runner.run_raw(["kill", "-0", str(linux_pid)], check=False)
                if alive.returncode == 0:
                    logger.warning(f"tcpdump PID {linux_pid} still alive after SIGINT; escalating to SIGTERM")
                    self.runner.run_raw(["kill", "-15", str(linux_pid)], check=False)
                    time.sleep(0.3)
                    if self.runner.run_raw(["kill", "-0", str(linux_pid)], check=False).returncode == 0:
                        self.runner.run_raw(["kill", "-9", str(linux_pid)], check=False)
            elif not self.runner.is_wsl:
                proc.send_signal(signal.SIGINT)

            proc.wait(timeout=3)
        except Exception:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                proc.kill()

        if pid_file:
            try:
                self.runner.run_raw(["rm", "-f", pid_file], check=False)
            except Exception:
                pass

        time.sleep(0.3)

        # Inspect captured file
        pcap_stats = self._inspect_pcap(wsl_pcap)

        return {
            "status": "STOPPED",
            "capture_id": capture_id,
            "interface": cap["interface"],
            "netns": cap["netns"],
            "output_path": output_path,
            "wsl_path": wsl_pcap,
            "duration_sec": round(time.time() - cap["started_at"], 2),
            **pcap_stats
        }

    def stop_all(self) -> List[Dict[str, Any]]:
        """Stops all active capture sessions."""
        results = []
        for cap_id in list(self.active_captures.keys()):
            results.append(self.stop_capture(cap_id))
        return results

    def _inspect_pcap(self, pcap_path: str) -> Dict[str, Any]:
        """Reads PCAP metadata, packet count, and computes SHA-256."""
        # Check size and sha256 via Linux runner
        size_res = self.runner.run_raw(["stat", "-c", "%s", pcap_path], check=False)
        file_size = int(size_res.stdout.strip()) if size_res.returncode == 0 and size_res.stdout.strip().isdigit() else 0

        sha_res = self.runner.run_raw(["sha256sum", pcap_path], check=False)
        sha256 = sha_res.stdout.split()[0].strip() if sha_res.returncode == 0 and sha_res.stdout.strip() else None

        # Count packets using tcpdump -r without shell pipes
        pkt_count = 0
        if file_size > 24:  # Standard PCAP header is 24 bytes
            cnt_res = self.runner.run_raw([self.runner.tcpdump_bin, "-r", pcap_path, "-n", "-q"], check=False)
            if cnt_res.returncode == 0:
                pkt_count = len([line for line in cnt_res.stdout.splitlines() if line.strip()])

        return {
            "file_size_bytes": file_size,
            "packet_count": pkt_count,
            "sha256": sha256 or "",
            "is_valid_pcap": file_size >= 24,
        }

