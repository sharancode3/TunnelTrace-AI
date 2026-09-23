"""Workload generators and execution models for Stage 5 Dataset Factory."""

from lab.workloads.base import WorkloadGenerator
from lab.workloads.doctor import WorkloadDoctor
from lab.workloads.generators.chat import ChatGenerator
from lab.workloads.generators.email import EmailGenerator
from lab.workloads.generators.file_transfer import FileTransferGenerator
from lab.workloads.generators.icmp import ICMPGenerator
from lab.workloads.generators.ood import OODHoldoutGenerator
from lab.workloads.generators.video import VideoGenerator
from lab.workloads.generators.voip import VoIPGenerator
from lab.workloads.generators.web import WebGenerator
from lab.workloads.models import (
    WorkloadClass,
    WorkloadExecutionResult,
    WorkloadProfile,
    WorkloadProtocol,
)

WORKLOAD_GENERATOR_REGISTRY: dict[WorkloadClass, type[WorkloadGenerator]] = {
    WorkloadClass.WEB: WebGenerator,
    WorkloadClass.VIDEO_STREAMING: VideoGenerator,
    WorkloadClass.VOIP: VoIPGenerator,
    WorkloadClass.CHAT_MESSAGING: ChatGenerator,
    WorkloadClass.EMAIL: EmailGenerator,
    WorkloadClass.ICMP: ICMPGenerator,
    WorkloadClass.FILE_TRANSFER: FileTransferGenerator,
    WorkloadClass.OOD_HOLDOUT: OODHoldoutGenerator,
}


def get_generator_for_profile(
    profile: WorkloadProfile,
    runner: object | None = None,
) -> WorkloadGenerator:
    """Factory creating the appropriate generator instance for a workload profile."""
    gen_cls = WORKLOAD_GENERATOR_REGISTRY.get(profile.workload_class)
    if not gen_cls:
        raise ValueError(f"No generator registered for workload class {profile.workload_class}")
    return gen_cls(profile=profile, runner=runner)


__all__ = [
    "WORKLOAD_GENERATOR_REGISTRY",
    "ChatGenerator",
    "EmailGenerator",
    "FileTransferGenerator",
    "ICMPGenerator",
    "OODHoldoutGenerator",
    "VideoGenerator",
    "VoIPGenerator",
    "WebGenerator",
    "WorkloadClass",
    "WorkloadDoctor",
    "WorkloadExecutionResult",
    "WorkloadGenerator",
    "WorkloadProfile",
    "WorkloadProtocol",
    "get_generator_for_profile",
]
