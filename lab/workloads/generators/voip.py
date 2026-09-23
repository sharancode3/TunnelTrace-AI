"""VoIP workload generator: simulates bidirectional UDP RTP voice streaming (e.g. G.711 20ms)."""

from __future__ import annotations

import logging
import random
import time

from lab.workloads.base import WorkloadGenerator
from lab.workloads.models import WorkloadClass, WorkloadExecutionResult

logger = logging.getLogger(__name__)


class VoIPGenerator(WorkloadGenerator):
    """Generates periodic UDP RTP audio streaming traffic (e.g. G.711 / Opus 20ms packetization)."""

    @property
    def workload_class(self) -> WorkloadClass:
        return WorkloadClass.VOIP

    def start_server(self, server_netns: str, bind_ip: str, port: int) -> None:
        """Start UDP RTP echo sink server in server namespace."""
        server_script = (
            "import socket, select\n"
            "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            f"sock.bind(('{bind_ip}', {port}))\n"
            "while True:\n"
            "    data, addr = sock.recvfrom(2048)\n"
            "    if data == b'SHUTDOWN': break\n"
            "    sock.sendto(data, addr)\n"
        )
        cmd = ["python3", "-c", server_script]
        self.server_proc = self.runner.run_background(cmd, netns=server_netns)
        self.server_pid = self.server_proc.pid
        logger.info("VoIP RTP sink started in %s (PID %d) on %s:%d", server_netns, self.server_pid, bind_ip, port)
        time.sleep(0.5)

    def run_client(
        self,
        client_netns: str,
        target_ip: str,
        target_port: int,
        duration_seconds: float,
        seed: int,
    ) -> WorkloadExecutionResult:
        """Stream RTP voice packets at 20ms intervals."""
        start_time = time.time()
        rng = random.Random(seed)
        num_packets = self.profile.parameters.get("packet_count", rng.randint(25, 50))

        client_script = (
            "import socket, time, struct\n"
            "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "sock.settimeout(0.5)\n"
            f"target = ('{target_ip}', {target_port})\n"
            f"num_pkts = {num_packets}\n"
            "sent = 0\n"
            "received = 0\n"
            "for seq in range(num_pkts):\n"
            "    # 12-byte synthetic RTP header: V=2, P=0, X=0, CC=0, M=0, PT=0 (PCMU), seq, ts, ssrc\n"
            "    rtp_hdr = struct.pack('!BBHII', 0x80, 0x00, seq, seq * 160, 0x12345678)\n"
            "    payload = b'\\xd5' * 160  # 160 bytes synthetic G.711 silence/audio\n"
            "    packet = rtp_hdr + payload\n"
            "    sock.sendto(packet, target)\n"
            "    sent += 1\n"
            "    try:\n"
            "        data, _ = sock.recvfrom(1024)\n"
            "        if len(data) == len(packet):\n"
            "            received += 1\n"
            "    except Exception:\n"
            "        pass\n"
            "    time.sleep(0.02)  # 20ms frame cadence\n"
            "print(f'RTP_DONE:{sent}:{received}')\n"
        )

        res = self.runner.run_raw(["python3", "-c", client_script], netns=client_netns, check=False)
        end_time = time.time()
        sent, received = 0, 0
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if line.startswith("RTP_DONE:"):
                    parts = line.split(":")
                    sent = int(parts[1])
                    received = int(parts[2])

        is_success = (sent >= 10) and (received >= 5) and (res.returncode == 0)
        return WorkloadExecutionResult(
            profile_id=self.profile.profile_id,
            workload_class=self.workload_class,
            success=is_success,
            packets_sent=sent,
            packets_received=received,
            bytes_sent=sent * 172,
            bytes_received=received * 172,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=end_time - start_time,
            server_pid=self.server_pid,
            telemetry={"rtp_packets_sent": sent, "rtp_packets_received": received, "frame_interval_ms": 20},
        )
