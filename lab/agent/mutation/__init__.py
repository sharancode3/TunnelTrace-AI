"""
TunnelTrace AI - Lab Mutation Module
====================================
Defensive protocol mutation and parser resilience testing for isolated IPsec lab captures.
"""

from lab.agent.mutation.scapy_mutator import (
    MutationConfig,
    MutationResult,
    MutationType,
    PcapMutator,
    SCAPY_AVAILABLE,
    SCAPY_VERSION,
)

__all__ = [
    "MutationConfig",
    "MutationResult",
    "MutationType",
    "PcapMutator",
    "SCAPY_AVAILABLE",
    "SCAPY_VERSION",
]
