"""Typed domain models and schemas for Stage 5 Workload Generators."""

from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, Field


class WorkloadClass(str, enum.Enum):
    """The seven authoritative supervised application classes plus OOD holdout."""
    WEB = "Web"
    VIDEO_STREAMING = "Video Streaming"
    VOIP = "VoIP"
    CHAT_MESSAGING = "Chat/Messaging"
    EMAIL = "Email"
    ICMP = "ICMP"
    FILE_TRANSFER = "File Transfer"
    OOD_HOLDOUT = "OOD_HOLDOUT"


class WorkloadProtocol(str, enum.Enum):
    """Transport protocol used by workload generator."""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"


class WorkloadProfile(BaseModel):
    """Configuration definition for a deterministic, reproducible synthetic workload."""
    profile_id: str = Field(..., description="Unique profile identifier, e.g. web-browsing-v1")
    workload_class: WorkloadClass = Field(..., description="Target application category")
    version: str = Field(default="1.0.0", description="Profile schema version")
    protocol: WorkloadProtocol = Field(default=WorkloadProtocol.TCP, description="Transport layer")
    target_port: int = Field(default=8080, ge=1, le=65535, description="Server port")
    duration_seconds: float = Field(default=10.0, ge=1.0, le=300.0, description="Nominal run duration")
    random_seed: int = Field(default=42, description="RNG seed for reproducible traffic variability")
    parameters: dict[str, Any] = Field(default_factory=dict, description="Generator-specific parameters")

    # Safety: disallow arbitrary shell or command execution
    def validate_safety(self) -> None:
        """Ensure no unsafe injection tokens exist in parameters."""
        forbidden_keys = {"shell", "exec", "eval", "pre_run", "post_run", "command"}
        for k in self.parameters:
            if k.lower() in forbidden_keys:
                raise ValueError(f"Forbidden parameter key '{k}' in workload profile")


class WorkloadExecutionResult(BaseModel):
    """Execution telemetry and verified success signal from a workload generator run."""
    profile_id: str
    workload_class: WorkloadClass
    success: bool
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    start_time: float
    end_time: float
    duration_seconds: float
    client_pid: int | None = None
    server_pid: int | None = None
    error_message: str | None = None
    telemetry: dict[str, Any] = Field(default_factory=dict)
