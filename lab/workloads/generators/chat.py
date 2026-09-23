"""Chat / Messaging workload generator: simulates bursty low-volume messaging and keepalives."""

from __future__ import annotations

import logging
import random
import time

from lab.workloads.base import WorkloadGenerator
from lab.workloads.models import WorkloadClass, WorkloadExecutionResult

logger = logging.getLogger(__name__)


class ChatGenerator(WorkloadGenerator):
    """Generates bursty short message exchanges and idle keepalive heartbeats."""

    @property
    def workload_class(self) -> WorkloadClass:
        return WorkloadClass.CHAT_MESSAGING

    def start_server(self, server_netns: str, bind_ip: str, port: int) -> None:
        """Start TCP chat message echo server in server namespace."""
        server_script = (
            "import socket\n"
            "sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            f"sock.bind(('{bind_ip}', {port}))\n"
            "sock.listen(1)\n"
            "conn, _ = sock.accept()\n"
            "while True:\n"
            "    data = conn.recv(1024)\n"
            "    if not data or data == b'BYE': break\n"
            "    conn.sendall(b'ACK:' + data)\n"
            "conn.close()\n"
            "sock.close()\n"
        )
        cmd = ["python3", "-c", server_script]
        self.server_proc = self.runner.run_background(cmd, netns=server_netns)
        self.server_pid = self.server_proc.pid
        logger.info("Chat message server started in %s (PID %d) on %s:%d", server_netns, self.server_pid, bind_ip, port)
        time.sleep(0.5)

    def run_client(
        self,
        client_netns: str,
        target_ip: str,
        target_port: int,
        duration_seconds: float,
        seed: int,
    ) -> WorkloadExecutionResult:
        """Exchange short messages with typing delays and keepalives."""
        start_time = time.time()
        rng = random.Random(seed)
        num_messages = self.profile.parameters.get("message_count", rng.randint(4, 8))

        client_script = (
            "import socket, time\n"
            "sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "sock.settimeout(3.0)\n"
            f"sock.connect(('{target_ip}', {target_port}))\n"
            f"num_msgs = {num_messages}\n"
            "sent = 0\n"
            "acked = 0\n"
            "total_bytes = 0\n"
            "for i in range(num_msgs):\n"
            "    # Synthetic chat message payload (80-200 bytes)\n"
            "    msg = f'MSG_{i}:' + ('Hello this is a test chat message. ' * 3)\n"
            "    payload = msg.encode('utf-8')\n"
            "    sock.sendall(payload)\n"
            "    sent += 1\n"
            "    total_bytes += len(payload)\n"
            "    reply = sock.recv(1024)\n"
            "    if reply.startswith(b'ACK:'):\n"
            "        acked += 1\n"
            f"    time.sleep({rng.uniform(0.1, 0.3):.3f})\n"
            "sock.sendall(b'BYE')\n"
            "sock.close()\n"
            "print(f'CHAT_DONE:{sent}:{acked}:{total_bytes}')\n"
        )

        res = self.runner.run_raw(["python3", "-c", client_script], netns=client_netns, check=False)
        end_time = time.time()
        sent, acked, total_bytes = 0, 0, 0
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if line.startswith("CHAT_DONE:"):
                    parts = line.split(":")
                    sent = int(parts[1])
                    acked = int(parts[2])
                    total_bytes = int(parts[3])

        is_success = (sent >= 2) and (acked >= 2) and (res.returncode == 0)
        return WorkloadExecutionResult(
            profile_id=self.profile.profile_id,
            workload_class=self.workload_class,
            success=is_success,
            packets_sent=sent,
            packets_received=acked,
            bytes_sent=total_bytes,
            bytes_received=total_bytes + (acked * 4),
            start_time=start_time,
            end_time=end_time,
            duration_seconds=end_time - start_time,
            server_pid=self.server_pid,
            telemetry={"messages_sent": sent, "messages_acknowledged": acked},
        )
