"""Video streaming workload generator: simulates chunked media streaming (HLS/DASH)."""

from __future__ import annotations

import logging
import random
import time

from lab.workloads.base import WorkloadGenerator
from lab.workloads.models import WorkloadClass, WorkloadExecutionResult

logger = logging.getLogger(__name__)


class VideoGenerator(WorkloadGenerator):
    """Generates continuous video media streaming traffic with burst replenishment patterns."""

    @property
    def workload_class(self) -> WorkloadClass:
        return WorkloadClass.VIDEO_STREAMING

    def start_server(self, server_netns: str, bind_ip: str, port: int) -> None:
        """Start media segment server in server namespace."""
        server_script = (
            "import http.server, socketserver\n"
            "class MediaHandler(http.server.BaseHTTPRequestHandler):\n"
            "    def do_GET(self):\n"
            "        # Generate synthetic 64KB video segment payload\n"
            "        segment_data = b'\\x00\\x00\\x00\\x1cftypisom' + (b'\\xaa' * 65512)\n"
            "        self.send_response(200)\n"
            "        self.send_header('Content-Type', 'video/mp4')\n"
            "        self.send_header('Content-Length', str(len(segment_data)))\n"
            "        self.end_headers()\n"
            "        self.wfile.write(segment_data)\n"
            "    def log_message(self, format, *args): pass\n"
            f"httpd = socketserver.TCPServer(('{bind_ip}', {port}), MediaHandler)\n"
            "httpd.serve_forever()\n"
        )
        cmd = ["python3", "-c", server_script]
        self.server_proc = self.runner.run_background(cmd, netns=server_netns)
        self.server_pid = self.server_proc.pid
        logger.info("Video media server started in %s (PID %d) on %s:%d", server_netns, self.server_pid, bind_ip, port)
        time.sleep(0.5)

    def run_client(
        self,
        client_netns: str,
        target_ip: str,
        target_port: int,
        duration_seconds: float,
        seed: int,
    ) -> WorkloadExecutionResult:
        """Client downloads consecutive media segments simulating video playback."""
        start_time = time.time()
        rng = random.Random(seed)
        num_segments = self.profile.parameters.get("segments_count", rng.randint(4, 8))

        client_script = (
            "import urllib.request, time\n"
            f"target_url = 'http://{target_ip}:{target_port}/segment.mp4'\n"
            f"num_segs = {num_segments}\n"
            "segments_done = 0\n"
            "total_bytes = 0\n"
            "for i in range(num_segs):\n"
            "    try:\n"
            "        with urllib.request.urlopen(target_url, timeout=4.0) as resp:\n"
            "            data = resp.read()\n"
            "            if resp.status == 200:\n"
            "                segments_done += 1\n"
            "                total_bytes += len(data)\n"
            "    except Exception:\n"
            "        pass\n"
            f"    time.sleep({rng.uniform(0.15, 0.35):.3f})\n"
            "print(f'VIDEO_DONE:{segments_done}:{total_bytes}')\n"
        )

        res = self.runner.run_raw(["python3", "-c", client_script], netns=client_netns, check=False)
        end_time = time.time()
        segments_done, total_bytes = 0, 0
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if line.startswith("VIDEO_DONE:"):
                    parts = line.split(":")
                    segments_done = int(parts[1])
                    total_bytes = int(parts[2])

        is_success = (segments_done >= 1) and (res.returncode == 0)
        return WorkloadExecutionResult(
            profile_id=self.profile.profile_id,
            workload_class=self.workload_class,
            success=is_success,
            packets_sent=segments_done * 2,
            packets_received=segments_done * 45,  # TCP segments for 64KB
            bytes_sent=segments_done * 300,
            bytes_received=total_bytes,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=end_time - start_time,
            server_pid=self.server_pid,
            telemetry={"segments_downloaded": segments_done, "total_media_bytes": total_bytes},
        )
