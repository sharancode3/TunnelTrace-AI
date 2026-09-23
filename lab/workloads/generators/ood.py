"""OOD Holdout workload generator: unmodeled custom binary telemetry for open-set evaluation."""

from __future__ import annotations

import logging
import random
import time

from lab.workloads.base import WorkloadGenerator
from lab.workloads.models import WorkloadClass, WorkloadExecutionResult

logger = logging.getLogger(__name__)


class OODHoldoutGenerator(WorkloadGenerator):
    """Generates unmodeled proprietary binary sensor telemetry for OOD holdout evaluation."""

    @property
    def workload_class(self) -> WorkloadClass:
        return WorkloadClass.OOD_HOLDOUT

    def start_server(self, server_netns: str, bind_ip: str, port: int) -> None:
        """Start UDP telemetry sink in server namespace."""
        server_script = (
            "import socket\n"
            "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            f"sock.bind(('{bind_ip}', {port}))\n"
            "while True:\n"
            "    data, addr = sock.recvfrom(1024)\n"
            "    if data == b'SHUTDOWN': break\n"
            "    sock.sendto(b'ACK_TELEMETRY', addr)\n"
        )
        cmd = ["python3", "-c", server_script]
        self.server_proc = self.runner.run_background(cmd, netns=server_netns)
        self.server_pid = self.server_proc.pid
        logger.info("OOD Telemetry sink started in %s (PID %d) on %s:%d", server_netns, self.server_pid, bind_ip, port)
        time.sleep(0.5)

    def run_client(
        self,
        client_netns: str,
        target_ip: str,
        target_port: int,
        duration_seconds: float,
        seed: int,
    ) -> WorkloadExecutionResult:
        """Transmit binary telemetry bursts with custom framing."""
        start_time = time.time()
        rng = random.Random(seed)
        burst_count = self.profile.parameters.get("burst_count", rng.randint(5, 12))

        client_script = (
            "import socket, struct, time, zlib\n"
            "sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "sock.settimeout(0.5)\n"
            f"target = ('{target_ip}', {target_port})\n"
            f"bursts = {burst_count}\n"
            "sent, acked = 0, 0\n"
            "for i in range(bursts):\n"
            "    # Custom proprietary binary framing: Magic(4B) + SensorID(2B) + Timestamp(4B) + Value(4B) + CRC(4B)\n"
            "    raw_payload = struct.pack('!IHIf', 0xDEADBEEF, i + 100, int(time.time()), 23.5 + i)\n"
            "    crc = zlib.crc32(raw_payload)\n"
            "    packet = raw_payload + struct.pack('!I', crc)\n"
            "    sock.sendto(packet, target)\n"
            "    sent += 1\n"
            "    try:\n"
            "        data, _ = sock.recvfrom(128)\n"
            "        if data == b'ACK_TELEMETRY':\n"
            "            acked += 1\n"
            "    except Exception:\n"
            "        pass\n"
            "    time.sleep(0.08)\n"
            "print(f'OOD_DONE:{sent}:{acked}')\n"
        )

        res = self.runner.run_raw(["python3", "-c", client_script], netns=client_netns, check=False)
        end_time = time.time()
        sent, acked = 0, 0
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if line.startswith("OOD_DONE:"):
                    parts = line.split(":")
                    sent = int(parts[1])
                    acked = int(parts[2])

        is_success = (sent >= 2) and (acked >= 1) and (res.returncode == 0)
        return WorkloadExecutionResult(
            profile_id=self.profile.profile_id,
            workload_class=self.workload_class,
            success=is_success,
            packets_sent=sent,
            packets_received=acked,
            bytes_sent=sent * 22,
            bytes_received=acked * 13,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=end_time - start_time,
            server_pid=self.server_pid,
            telemetry={"telemetry_bursts": sent, "acks_received": acked},
        )
