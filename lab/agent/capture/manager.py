"""
TunnelTrace AI - Lab Packet Capture Manager
===========================================
Manages isolated, authorized tcpdump packet capture processes on lab interfaces.
Flushes buffers with SIGINT, calculates SHA-256 digests, and validates PCAP headers.
Never captures physical host interfaces.
"""

from typing import Optional, Dict, Any, List
import os
import subprocess
import time
import signal
import hashlib
from lab.agent.operations.runner import SystemRunner
from lab.agent.cleanup.tracker import LabResourceTracker


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

        # Ensure directory exists in Linux environment
        output_dir = os.path.dirname(output_pcap_path)
        if self.runner.is_wsl:
            wsl_dir = self.runner._to_wsl_path(output_dir) if not output_dir.startswith("/") else output_dir
            self.runner.run_raw(["mkdir", "-p", wsl_dir])
            wsl_pcap_path = self.runner._to_wsl_path(output_pcap_path) if not output_pcap_path.startswith("/") else output_pcap_path
        else:
            os.makedirs(output_dir, exist_ok=True)
            wsl_pcap_path = output_pcap_path

        # Build tcpdump command line
        # Flags: -i <dev> -s 0 (full pkt) -U (packet-buffered flush) -w <file>
        cmd: List[str] = []
        if netns:
            cmd.extend([self.runner.ip_bin, "netns", "exec", netns])
        cmd.extend([self.runner.tcpdump_bin, "-i", interface, "-s", "0", "-U", "-w", wsl_pcap_path])

        if bpf_filter:
            # tcpdump accepts BPF filter expressions as trailing positional args
            cmd.extend(bpf_filter.split())

        # Wrap with wsl if on Windows
        if self.runner.is_wsl:
            full_cmd = ["wsl", "-u", "root", "-e"] + cmd
        else:
            full_cmd = cmd

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

        capture_info = {
            "capture_id": capture_id,
            "process": proc,
            "pid": proc.pid,
            "interface": interface,
            "netns": netns,
            "output_path": output_pcap_path,
            "wsl_path": wsl_pcap_path,
            "bpf_filter": bpf_filter,
            "started_at": time.time()
        }
        self.active_captures[capture_id] = capture_info

        if self.tracker:
            self.tracker.track_pid(proc.pid, f"tcpdump-{capture_id}")

        return {
            "status": "CAPTURING",
            "capture_id": capture_id,
            "interface": interface,
            "netns": netns,
            "pid": proc.pid,
            "pcap_path": output_pcap_path
        }

    def stop_capture(self, capture_id: str) -> Dict[str, Any]:
        """
        Gracefully stops tcpdump using SIGINT to guarantee buffer flush and pcap closing.
        Computes SHA-256 hash and packet count.
        """
        if capture_id not in self.active_captures:
            raise KeyError(f"Capture ID '{capture_id}' not found in active captures")

        cap = self.active_captures.pop(capture_id)
        proc: subprocess.Popen = cap["process"]
        wsl_pcap = cap["wsl_path"]
        output_path = cap["output_path"]

        # Send SIGINT to tcpdump so it finalizes the pcap header
        try:
            if self.runner.is_wsl:
                # In WSL, terminate the PID directly inside Linux namespace/host
                # proc.pid is the Windows wsl.exe process, find the linux tcpdump pid
                self.runner.run_raw(["pkill", "-2", "-f", f"tcpdump.*{cap['interface']}"])
                time.sleep(0.5)
            else:
                proc.send_signal(signal.SIGINT)
            
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                proc.kill()

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

