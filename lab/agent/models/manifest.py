"""
TunnelTrace AI - Lab Run Manifest Schema
========================================
Comprehensive, machine-readable provenance manifest recording ground-truth
configuration, execution environment, runtime observations, and cryptographic hashes.
Strictly excludes all plaintext secrets, PSKs, and private keys.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class CaptureArtifact(BaseModel):
    """Details of a single packet capture artifact produced during a run."""
    capture_id: str
    role: str # "WAN_ENCRYPTED", "PLAINTEXT_CLIENT", "PLAINTEXT_SERVER"
    interface: str
    netns: Optional[str] = None
    output_path: str
    file_size_bytes: int
    packet_count: int
    sha256: str
    bpf_filter: Optional[str] = None


class RunManifest(BaseModel):
    """Complete immutable manifest for a single testbed run."""
    run_id: str
    scenario_id: str
    scenario_version: str = "1.0.0"
    topology_type: str
    
    # Timestamps (ISO 8601 UTC)
    started_at_utc: str
    ended_at_utc: Optional[str] = None
    duration_seconds: Optional[float] = None
    
    # Host & Toolchain Environment
    environment: Dict[str, Any] = Field(default_factory=dict)
    
    # Requested Specification
    requested_configuration: Dict[str, Any] = Field(default_factory=dict)
    scenario_sha256: str
    config_hashes: Dict[str, str] = Field(default_factory=dict)
    
    # Allocated Network Resources
    namespaces: List[str] = Field(default_factory=list)
    interfaces: List[str] = Field(default_factory=list)
    address_plan: Dict[str, Any] = Field(default_factory=dict)
    
    # Runtime Observability (Zero-Secrets)
    observed_runtime_state: Dict[str, Any] = Field(default_factory=dict)
    
    # Captured Evidence
    captures: List[CaptureArtifact] = Field(default_factory=list)
    
    # Validation & Final Status
    traffic_probe_passed: bool = False
    sa_established: bool = False
    validation_status: str = "READY_TO_EXECUTE" # "VALIDATED", "PARTIAL", "FAILED", "BLOCKED"
    status_summary: str = ""
    evidence_directory: Optional[str] = None
    workload_profile: Optional[Dict[str, Any]] = None
    workload_result: Optional[Dict[str, Any]] = None
