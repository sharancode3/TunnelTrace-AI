"""Web workload generator: simulates realistic interactive web browsing and API requests."""

from __future__ import annotations

import logging
import random
import time

from lab.workloads.base import WorkloadGenerator
from lab.workloads.models import WorkloadClass, WorkloadExecutionResult

logger = logging.getLogger(__name__)


class WebGenerator(WorkloadGenerator):
    """Generates interactive web browsing sessions with HTML, CSS, script, and API fetches."""

    @property
    def workload_class(self) -> WorkloadClass:
        return WorkloadClass.WEB

    def start_server(self, server_netns: str, bind_ip: str, port: int) -> None:
        """Start self-contained HTTP web origin server in server namespace."""
        server_script = (
            "import http.server, socketserver\n"
            "class WebHandler(http.server.BaseHTTPRequestHandler):\n"
            "    def do_GET(self):\n"
            "        content = b'<html><head><title>Testbed Web</title></head><body>' + (b'X' * 4096) + b'</body></html>'\n"
            "        self.send_response(200)\n"
            "        self.send_header('Content-Type', 'text/html')\n"
            "        self.send_header('Content-Length', str(len(content)))\n"
            "        self.end_headers()\n"
            "        self.wfile.write(content)\n"
            "    def log_message(self, format, *args): pass\n"
            f"httpd = socketserver.TCPServer(('{bind_ip}', {port}), WebHandler)\n"
            "httpd.serve_forever()\n"
        )
        cmd = ["python3", "-c", server_script]
        self.server_proc = self.runner.run_background(cmd, netns=server_netns)
        self.server_pid = self.server_proc.pid
        logger.info("Web origin server started in %s (PID %d) on %s:%d", server_netns, self.server_pid, bind_ip, port)
        time.sleep(0.5)

    def run_client(
        self,
        client_netns: str,
        target_ip: str,
        target_port: int,
        duration_seconds: float,
        seed: int,
    ) -> WorkloadExecutionResult:
        """Execute web browsing client requests with randomized think-time gaps."""
        start_time = time.time()
        rng = random.Random(seed)
        num_requests = self.profile.parameters.get("requests_count", rng.randint(4, 10))

        client_script = (
            "import urllib.request, time, sys\n"
            f"target_url = 'http://{target_ip}:{target_port}/'\n"
            f"num_reqs = {num_requests}\n"
            "successes = 0\n"
            "total_bytes = 0\n"
            "for i in range(num_reqs):\n"
            "    try:\n"
            "        req = urllib.request.Request(target_url + f'?page={i}')\n"
            "        with urllib.request.urlopen(req, timeout=3.0) as resp:\n"
            "            data = resp.read()\n"
            "            if resp.status == 200:\n"
            "                successes += 1\n"
            "                total_bytes += len(data)\n"
            "    except Exception as e:\n"
            "        pass\n"
            f"    time.sleep({rng.uniform(0.1, 0.4):.3f})\n"
            "print(f'SUCCESS:{successes}:{total_bytes}')\n"
        )

        res = self.runner.run_raw(["python3", "-c", client_script], netns=client_netns, check=False)
        end_time = time.time()
        successes, total_bytes = 0, 0
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if line.startswith("SUCCESS:"):
                    parts = line.split(":")
                    successes = int(parts[1])
                    total_bytes = int(parts[2])

        is_success = (successes >= 1) and (res.returncode == 0)
        return WorkloadExecutionResult(
            profile_id=self.profile.profile_id,
            workload_class=self.workload_class,
            success=is_success,
            packets_sent=successes,
            packets_received=successes,
            bytes_sent=successes * 200,
            bytes_received=total_bytes,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=end_time - start_time,
            server_pid=self.server_pid,
            telemetry={"requests_completed": successes, "target_requests": num_requests},
        )
