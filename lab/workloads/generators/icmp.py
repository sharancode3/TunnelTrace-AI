"""ICMP workload generator: executes controlled ICMP echo request/reply probing."""

from __future__ import annotations

import logging
import random
import time

from lab.workloads.base import WorkloadGenerator
from lab.workloads.models import WorkloadClass, WorkloadExecutionResult

logger = logging.getLogger(__name__)


class ICMPGenerator(WorkloadGenerator):
    """Generates controlled ICMP echo request and reply streams across IPv4 and IPv6."""

    @property
    def workload_class(self) -> WorkloadClass:
        return WorkloadClass.ICMP

    def start_server(self, server_netns: str, bind_ip: str, port: int) -> None:
        """ICMP echo reply is handled natively by the Linux kernel network stack."""
        self.server_proc = None
        self.server_pid = None
        logger.debug("ICMP responder active via kernel in %s", server_netns)

    def run_client(
        self,
        client_netns: str,
        target_ip: str,
        target_port: int,
        duration_seconds: float,
        seed: int,
    ) -> WorkloadExecutionResult:
        """Execute ping command with variable packet size and count."""
        start_time = time.time()
        rng = random.Random(seed)
        packet_count = self.profile.parameters.get("packet_count", rng.randint(4, 10))
        packet_size = self.profile.parameters.get("packet_size", rng.choice([64, 256, 512, 1024]))

        is_ipv6 = ":" in target_ip
        ping_bin = "ping6" if is_ipv6 else "ping"

        cmd = [
            ping_bin,
            "-c", str(packet_count),
            "-s", str(packet_size),
            "-W", "2",
            target_ip,
        ]

        res = self.runner.run_raw(cmd, netns=client_netns, check=False)
        end_time = time.time()

        is_success = (res.returncode == 0)
        transmitted = packet_count if is_success else 0
        received = packet_count if is_success else 0
        total_bytes = packet_count * (packet_size + 28)

        return WorkloadExecutionResult(
            profile_id=self.profile.profile_id,
            workload_class=self.workload_class,
            success=is_success,
            packets_sent=transmitted,
            packets_received=received,
            bytes_sent=total_bytes,
            bytes_received=total_bytes,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=end_time - start_time,
            server_pid=None,
            telemetry={"packets_transmitted": transmitted, "packet_size": packet_size, "is_ipv6": is_ipv6},
        )
