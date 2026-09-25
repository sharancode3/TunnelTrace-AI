"""
TunnelTrace AI - Operational Security Audit Logging Subsystem
=============================================================
Provides structured, secret-redacted, append-only operational audit logging
for security-relevant actions across privileged, configuration, telemetry,
and reporting boundaries.

Audit Integrity Notice:
-----------------------
Audit records are application-level structured events persisted to disk/DB.
They provide operational transparency, access control tracking, and failure correlation.
They do NOT possess hardware HSM or blockchain non-repudiation guarantees; log
file protection relies on host OS access control (UID 10001 / root separation).
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.core.logging import SecretRedactionFilter
from app.core.request_context import get_request_id

audit_logger = logging.getLogger("tunneltrace.audit")


class AuditOutcome(str, Enum):
    """Execution outcome status for an audited security action."""
    SUCCESS = "SUCCESS"
    DENIED = "DENIED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"


@dataclass
class AuditEvent:
    """Represents a discrete security-relevant audit event record."""

    action: str
    target_resource: str
    authorized_scope: str
    outcome: AuditOutcome
    actor_id: str = "system"
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    reason_or_error: str | None = None
    correlation_id: str | None = None
    evidence_ref: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert record to dictionary with normalized outcome string."""
        d = asdict(self)
        d["outcome"] = self.outcome.value if isinstance(self.outcome, AuditOutcome) else str(self.outcome)
        return d

    def to_json(self) -> str:
        """Convert record to canonical JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True)


class SecurityAuditLogger:
    """Singleton operational audit logger enforcing secret scrubbing and atomic persistence."""

    _instance: SecurityAuditLogger | None = None
    _lock = threading.Lock()

    def __init__(self, log_dir: Path | str | None = None) -> None:
        self.log_dir = Path(log_dir) if log_dir else Path(settings.STORAGE_ROOT) / "audit"
        self._ensure_log_dir()
        self._file_lock = threading.Lock()

    def _ensure_log_dir(self) -> None:
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            logging.getLogger(__name__).warning(f"Could not create audit log dir '{self.log_dir}': {exc}")

    @classmethod
    def get_logger(cls) -> SecurityAuditLogger:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @staticmethod
    def sanitize_metadata(data: Any) -> Any:
        """Recursively scrub secrets from audit event metadata."""
        if isinstance(data, dict):
            sanitized = {}
            for k, v in data.items():
                if any(sec in k.lower() for sec in ("secret", "password", "key", "token", "psk", "auth")):
                    sanitized[k] = "[REDACTED_SECRET]"
                else:
                    sanitized[k] = SecurityAuditLogger.sanitize_metadata(v)
            return sanitized
        elif isinstance(data, (list, tuple)):
            return [SecurityAuditLogger.sanitize_metadata(x) for x in data]
        elif isinstance(data, str):
            return SecretRedactionFilter._redact(data)
        return data

    def record_event(
        self,
        action: str,
        target_resource: str,
        authorized_scope: str,
        outcome: AuditOutcome | str,
        actor_id: str = "system",
        reason_or_error: str | None = None,
        correlation_id: str | None = None,
        evidence_ref: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Constructs, scrubs, and records a structured audit event."""
        # Normalize outcome
        if isinstance(outcome, str):
            try:
                outcome_enum = AuditOutcome(outcome.upper())
            except ValueError:
                outcome_enum = AuditOutcome.FAILED
        else:
            outcome_enum = outcome

        # Derive correlation ID if not provided
        cid = correlation_id or get_request_id() or "-"

        # Scrub metadata and error strings
        clean_metadata = self.sanitize_metadata(metadata or {})
        clean_error = SecretRedactionFilter._redact(reason_or_error) if reason_or_error else None
        clean_target = SecretRedactionFilter._redact(target_resource)

        event = AuditEvent(
            action=action,
            target_resource=clean_target,
            authorized_scope=authorized_scope,
            outcome=outcome_enum,
            actor_id=actor_id,
            reason_or_error=clean_error,
            correlation_id=cid,
            evidence_ref=evidence_ref,
            metadata=clean_metadata,
        )

        # 1. Log to structured python logger
        audit_logger.info(
            f"AUDIT_EVENT: action={event.action} outcome={event.outcome.value} "
            f"actor={event.actor_id} target={event.target_resource} scope={event.authorized_scope} "
            f"req={event.correlation_id} error={event.reason_or_error}"
        )

        # 2. Append atomically to audit log file
        self._append_to_file(event)

        return event

    def _append_to_file(self, event: AuditEvent) -> None:
        """Appends the event as a JSON line to audit_events.jsonl."""
        log_file = self.log_dir / "audit_events.jsonl"
        raw_line = event.to_json() + "\n"
        with self._file_lock:
            try:
                self.log_dir.mkdir(parents=True, exist_ok=True)
                with open(log_file, "a", encoding="utf-8") as f:
                    f.write(raw_line)
                    f.flush()
                    os.fsync(f.fileno())
            except Exception as exc:
                logging.getLogger(__name__).error(f"Failed to append to audit log file '{log_file}': {exc}")

    def query_events(
        self,
        limit: int = 100,
        action: str | None = None,
        actor_id: str | None = None,
        outcome: str | None = None,
    ) -> list[dict[str, Any]]:
        """Reads persisted audit events with optional filtering for operational diagnostics."""
        log_file = self.log_dir / "audit_events.jsonl"
        if not log_file.exists():
            return []

        results: list[dict[str, Any]] = []
        with self._file_lock:
            try:
                with open(log_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            record = json.loads(line)
                            if action and record.get("action") != action:
                                continue
                            if actor_id and record.get("actor_id") != actor_id:
                                continue
                            if outcome and record.get("outcome") != outcome.upper():
                                continue
                            results.append(record)
                        except json.JSONDecodeError:
                            continue
            except Exception as exc:
                logging.getLogger(__name__).error(f"Error reading audit log file: {exc}")

        # Return latest events up to limit
        return results[-limit:]
