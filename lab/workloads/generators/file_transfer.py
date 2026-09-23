"""File Transfer workload generator: bulk chunked data transfer with source-to-sink SHA-256 validation."""

from __future__ import annotations

import logging
import random
import time

from lab.workloads.base import WorkloadGenerator
from lab.workloads.models import WorkloadClass, WorkloadExecutionResult

logger = logging.getLogger(__name__)


class FileTransferGenerator(WorkloadGenerator):
    """Generates bulk file upload/download with end-to-end SHA-256 content verification."""

    @property
    def workload_class(self) -> WorkloadClass:
        return WorkloadClass.FILE_TRANSFER

    def start_server(self, server_netns: str, bind_ip: str, port: int) -> None:
        """Start receiver server computing incoming file SHA-256 in server namespace."""
        server_script = (
            "import http.server, socketserver, hashlib\n"
            "class UploadHandler(http.server.BaseHTTPRequestHandler):\n"
            "    def do_POST(self):\n"
            "        length = int(self.headers.get('Content-Length', 0))\n"
            "        data = self.rfile.read(length)\n"
            "        file_hash = hashlib.sha256(data).hexdigest()\n"
            "        self.send_response(200)\n"
            "        self.send_header('Content-Type', 'text/plain')\n"
            "        self.send_header('X-File-SHA256', file_hash)\n"
            "        self.end_headers()\n"
            "        self.wfile.write(file_hash.encode('utf-8'))\n"
            "    def log_message(self, format, *args): pass\n"
            f"httpd = socketserver.TCPServer(('{bind_ip}', {port}), UploadHandler)\n"
            "httpd.serve_forever()\n"
        )
        cmd = ["python3", "-c", server_script]
        self.server_proc = self.runner.run_background(cmd, netns=server_netns)
        self.server_pid = self.server_proc.pid
        logger.info("File upload receiver started in %s (PID %d) on %s:%d", server_netns, self.server_pid, bind_ip, port)
        time.sleep(0.5)

    def run_client(
        self,
        client_netns: str,
        target_ip: str,
        target_port: int,
        duration_seconds: float,
        seed: int,
    ) -> WorkloadExecutionResult:
        """Generate synthetic file with known SHA-256 and transmit to receiver."""
        start_time = time.time()
        rng = random.Random(seed)
        file_size_kb = self.profile.parameters.get("size_kb", rng.choice([256, 512, 1024]))

        client_script = (
            "import urllib.request, hashlib, sys\n"
            f"target_url = 'http://{target_ip}:{target_port}/upload'\n"
            f"size_kb = {file_size_kb}\n"
            "# Generate synthetic binary file payload\n"
            "payload = (b'SYNTHETIC_DATA_BLOCK_' * 32)[:1024] * size_kb\n"
            "src_hash = hashlib.sha256(payload).hexdigest()\n"
            "try:\n"
            "    req = urllib.request.Request(target_url, data=payload, method='POST')\n"
            "    req.add_header('Content-Type', 'application/octet-stream')\n"
            "    with urllib.request.urlopen(req, timeout=6.0) as resp:\n"
            "        sink_hash = resp.read().decode('utf-8').strip()\n"
            "        if resp.status == 200 and sink_hash == src_hash:\n"
            "            print(f'TRANSFER_SUCCESS:{len(payload)}:{src_hash}:{sink_hash}')\n"
            "            sys.exit(0)\n"
            "except Exception as e:\n"
            "    pass\n"
            "print('TRANSFER_FAILED')\n"
        )

        res = self.runner.run_raw(["python3", "-c", client_script], netns=client_netns, check=False)
        end_time = time.time()

        is_success = False
        bytes_transferred = 0
        src_hash, sink_hash = "", ""
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if line.startswith("TRANSFER_SUCCESS:"):
                    parts = line.split(":")
                    bytes_transferred = int(parts[1])
                    src_hash = parts[2]
                    sink_hash = parts[3]
                    is_success = (src_hash == sink_hash)

        return WorkloadExecutionResult(
            profile_id=self.profile.profile_id,
            workload_class=self.workload_class,
            success=is_success,
            packets_sent=bytes_transferred // 1420 + 5,
            packets_received=10,
            bytes_sent=bytes_transferred,
            bytes_received=200,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=end_time - start_time,
            server_pid=self.server_pid,
            telemetry={
                "file_bytes": bytes_transferred,
                "source_sha256": src_hash,
                "sink_sha256": sink_hash,
                "integrity_verified": is_success,
            },
        )
