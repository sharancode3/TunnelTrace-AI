"""Email workload generator: simulates synthetic SMTP/IMAP message transactions."""

from __future__ import annotations

import logging
import random
import time

from lab.workloads.base import WorkloadGenerator
from lab.workloads.models import WorkloadClass, WorkloadExecutionResult

logger = logging.getLogger(__name__)


class EmailGenerator(WorkloadGenerator):
    """Generates synthetic SMTP email transfer sessions with MIME framing."""

    @property
    def workload_class(self) -> WorkloadClass:
        return WorkloadClass.EMAIL

    def start_server(self, server_netns: str, bind_ip: str, port: int) -> None:
        """Start mock SMTP server accepting synthetic MIME messages in server namespace."""
        server_script = (
            "import socket\n"
            "sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            f"sock.bind(('{bind_ip}', {port}))\n"
            "sock.listen(1)\n"
            "conn, _ = sock.accept()\n"
            "conn.sendall(b'220 testbed.internal ESMTP Service Ready\\r\\n')\n"
            "in_data = False\n"
            "while True:\n"
            "    line = b''\n"
            "    while not line.endswith(b'\\r\\n'):\n"
            "        chunk = conn.recv(1)\n"
            "        if not chunk: break\n"
            "        line += chunk\n"
            "    if not line: break\n"
            "    if in_data:\n"
            "        if line == b'.\\r\\n':\n"
            "            in_data = False\n"
            "            conn.sendall(b'250 2.0.0 Ok: queued\\r\\n')\n"
            "        continue\n"
            "    if line.startswith(b'EHLO') or line.startswith(b'HELO'):\n"
            "        conn.sendall(b'250-testbed.internal\\r\\n250 OK\\r\\n')\n"
            "    elif line.startswith(b'MAIL FROM:'):\n"
            "        conn.sendall(b'250 2.1.0 Ok\\r\\n')\n"
            "    elif line.startswith(b'RCPT TO:'):\n"
            "        conn.sendall(b'250 2.1.5 Ok\\r\\n')\n"
            "    elif line.startswith(b'DATA'):\n"
            "        in_data = True\n"
            "        conn.sendall(b'354 End data with <CR><LF>.<CR><LF>\\r\\n')\n"
            "    elif line.startswith(b'QUIT'):\n"
            "        conn.sendall(b'221 2.0.0 Bye\\r\\n')\n"
            "        break\n"
            "conn.close()\n"
            "sock.close()\n"
        )
        cmd = ["python3", "-c", server_script]
        self.server_proc = self.runner.run_background(cmd, netns=server_netns)
        self.server_pid = self.server_proc.pid
        logger.info("Mock SMTP server started in %s (PID %d) on %s:%d", server_netns, self.server_pid, bind_ip, port)
        time.sleep(0.5)

    def run_client(
        self,
        client_netns: str,
        target_ip: str,
        target_port: int,
        duration_seconds: float,
        seed: int,
    ) -> WorkloadExecutionResult:
        """Transmit synthetic MIME email via SMTP."""
        start_time = time.time()
        rng = random.Random(seed)
        num_emails = self.profile.parameters.get("email_count", rng.randint(2, 4))

        client_script = (
            "import smtplib, time\n"
            f"target = '{target_ip}'\n"
            f"port = {target_port}\n"
            f"num_emails = {num_emails}\n"
            "sent = 0\n"
            "total_bytes = 0\n"
            "try:\n"
            "    server = smtplib.SMTP(target, port, timeout=5.0)\n"
            "    server.ehlo('client.internal')\n"
            "    for i in range(num_emails):\n"
            "        # Synthetic non-sensitive MIME content\n"
            "        sender = 'bench-user@tunneltrace.internal'\n"
            "        rcpt = 'sink-worker@tunneltrace.internal'\n"
            "        body = f'From: {sender}\\r\\nTo: {rcpt}\\r\\nSubject: Synthetic Email {i}\\r\\n\\r\\n' + ('Synthesized benchmark message body line.\\r\\n' * 20)\n"
            "        msg_bytes = body.encode('utf-8')\n"
            "        server.sendmail(sender, [rcpt], body)\n"
            "        sent += 1\n"
            "        total_bytes += len(msg_bytes)\n"
            "        time.sleep(0.1)\n"
            "    server.quit()\n"
            "except Exception as e:\n"
            "    pass\n"
            "print(f'EMAIL_DONE:{sent}:{total_bytes}')\n"
        )

        res = self.runner.run_raw(["python3", "-c", client_script], netns=client_netns, check=False)
        end_time = time.time()
        sent, total_bytes = 0, 0
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if line.startswith("EMAIL_DONE:"):
                    parts = line.split(":")
                    sent = int(parts[1])
                    total_bytes = int(parts[2])

        is_success = (sent >= 1) and (res.returncode == 0)
        return WorkloadExecutionResult(
            profile_id=self.profile.profile_id,
            workload_class=self.workload_class,
            success=is_success,
            packets_sent=sent * 5,
            packets_received=sent * 5,
            bytes_sent=total_bytes,
            bytes_received=sent * 200,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=end_time - start_time,
            server_pid=self.server_pid,
            telemetry={"emails_transmitted": sent, "mime_payload_bytes": total_bytes},
        )
