"""Stage 2 Authorized Asset Discovery subsystem."""

from app.discovery.profiles import DiscoveryProfile, SCAN_PROFILES
from app.discovery.validator import (
    AuthorizationError,
    ScopeValidationError,
    ValidatedScope,
    validate_scope_request,
)
from app.discovery.parser import (
    NmapParseError,
    ParsedDiscoveryResult,
    ParsedHostObservation,
    ParsedServiceObservation,
    parse_nmap_xml,
)
from app.discovery.runner import (
    ExecutionResult,
    NmapBinaryInfo,
    ToolUnavailableError,
    build_nmap_argv,
    detect_nmap_binary,
    run_discovery_scan,
)
from app.discovery.service import DiscoveryService

__all__ = [
    "DiscoveryProfile",
    "SCAN_PROFILES",
    "AuthorizationError",
    "ScopeValidationError",
    "ValidatedScope",
    "validate_scope_request",
    "NmapParseError",
    "ParsedDiscoveryResult",
    "ParsedHostObservation",
    "ParsedServiceObservation",
    "parse_nmap_xml",
    "ExecutionResult",
    "NmapBinaryInfo",
    "ToolUnavailableError",
    "build_nmap_argv",
    "detect_nmap_binary",
    "run_discovery_scan",
    "DiscoveryService",
]
