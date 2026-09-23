"""
TunnelTrace AI - Traffic Control / Network Emulation (tc/netem) Manager
======================================================================
Applies bounded, controlled network impairment (latency, jitter, packet loss,
bandwidth limitation) exclusively to isolated laboratory interfaces using Linux tc.
Never applies impairment to host interfaces.
"""

from typing import Optional, Dict, Any
import re
from lab.scenarios.schema import NetemConfig
from lab.agent.operations.runner import SystemRunner
from lab.agent.cleanup.tracker import LabResourceTracker


class NetemManager:
    """Manages Linux tc/netem rules on laboratory interfaces within namespaces."""

    def __init__(self, runner: SystemRunner, tracker: Optional[LabResourceTracker] = None) -> None:
        self.runner = runner
        self.tracker = tracker

    def apply_impairment(
        self,
        interface: str,
        config: NetemConfig,
        netns: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Applies tc netem queuing discipline to an isolated interface.
        Uses 'replace' to safely overwrite any existing root qdisc idempotently.
        """
        if not config.has_impairment():
            return {"applied": False, "reason": "No impairment parameters configured"}

        # Validate interface safety
        self.runner.validate_safety(interface)

        # Build netem command arguments
        # Example: tc qdisc replace dev veth-wan-a root netem delay 20ms 5ms loss 0.5% rate 10000kbit
        args = ["qdisc", "replace", "dev", interface, "root", "netem"]

        if config.delay_ms is not None:
            if config.jitter_ms is not None:
                args.extend(["delay", f"{config.delay_ms}ms", f"{config.jitter_ms}ms"])
            else:
                args.extend(["delay", f"{config.delay_ms}ms"])

        if config.loss_pct is not None and config.loss_pct > 0.0:
            args.extend(["loss", f"{config.loss_pct}%"])

        if config.rate_kbps is not None and config.rate_kbps > 0:
            args.extend(["rate", f"{config.rate_kbps}kbit"])

        # Execute tc command
        res = self.runner.run_tc(args, netns=netns)

        # Track for guaranteed cleanup
        if self.tracker:
            self.tracker.track_qdisc(interface, netns)

        # Inspect and verify applied qdisc
        current_state = self.get_qdisc(interface, netns=netns)

        return {
            "applied": True,
            "interface": interface,
            "netns": netns,
            "config": config.model_dump(),
            "tc_output": res.stdout,
            "verified_qdisc": current_state
        }

    def clear_impairment(self, interface: str, netns: Optional[str] = None) -> Dict[str, Any]:
        """
        Removes the netem queuing discipline from an interface.
        Gracefully handles cases where no non-default qdisc was installed.
        """
        self.runner.validate_safety(interface)

        res = self.runner.run_tc(["qdisc", "del", "dev", interface, "root"], netns=netns, check=False)
        return {
            "cleared": True,
            "interface": interface,
            "netns": netns,
            "returncode": res.returncode
        }

    def get_qdisc(self, interface: str, netns: Optional[str] = None) -> str:
        """Inspects the current qdisc on an interface."""
        self.runner.validate_safety(interface)
        res = self.runner.run_tc(["qdisc", "show", "dev", interface], netns=netns, check=False)
        return res.stdout.strip()
