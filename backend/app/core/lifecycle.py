"""
TunnelTrace AI - Data Retention & Storage Lifecycle Subsystem
============================================================
Defines authoritative data classifications, storage boundaries, retention
policies, and safe deletion semantics with database metadata synchronization.

Retention and Purge Invariant:
------------------------------
When an artifact (e.g. raw PCAP or generated report) is purged or expires,
its physical storage file is deleted AND the corresponding database entity is
transactionally updated to "PURGED" status with its path cleared.
Under NO circumstances does the system silently leave database records or
evidence DAG nodes falsely claiming that a deleted artifact is available on disk.
"""

from __future__ import annotations

import logging
import os
import shutil
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditOutcome, SecurityAuditLogger
from app.core.config import settings
from app.core.errors import NotFoundError, PathTraversalError, StorageError
from app.db.models.capture import Capture
from app.services.storage import get_storage_provider

logger = logging.getLogger("tunneltrace.lifecycle")


class DataClassification(str, Enum):
    """Categorization of data managed across the TunnelTrace AI platform."""
    RAW_PCAP = "RAW_PCAP"
    DERIVED_OBSERVATIONS = "DERIVED_OBSERVATIONS"
    REPORTS = "REPORTS"
    TEMPORARY_LAB_FILES = "TEMPORARY_LAB_FILES"
    AUDIT_LOGS = "AUDIT_LOGS"
    CONFIG_CERT_SNAPSHOTS = "CONFIG_CERT_SNAPSHOTS"


@dataclass(frozen=True)
class LifecyclePolicy:
    """Documented lifecycle, retention, and access policy for a data classification."""
    classification: DataClassification
    description: str
    storage_location: str
    retention_period: str
    access_boundary: str
    deletion_behavior: str
    db_sync_required: bool


LIFECYCLE_POLICIES: dict[DataClassification, LifecyclePolicy] = {
    DataClassification.RAW_PCAP: LifecyclePolicy(
        classification=DataClassification.RAW_PCAP,
        description="Ingested network capture files (PCAP/PCAPNG) and live capture traces",
        storage_location="storage/captures/{id}.pcap, storage/live/{session_id}/live.pcap",
        retention_period=f"{settings.RETENTION_PCAP_DAYS} days (or indefinite if flagged as golden/benchmark)",
        access_boundary="Class A API read, Class B capture write, root-contained, no public URL",
        deletion_behavior="Physical file unlink + DB Capture status set to PURGED + storage_path set to NULL",
        db_sync_required=True,
    ),
    DataClassification.DERIVED_OBSERVATIONS: LifecyclePolicy(
        classification=DataClassification.DERIVED_OBSERVATIONS,
        description="Normalized protocol observations, SPI states, and transform observations",
        storage_location="Database (protocol_observations, ike_sessions, esp_flows)",
        retention_period="Co-located with parent analysis run (cascading delete on analysis deletion)",
        access_boundary="Class A API read via authenticated analysis ID",
        deletion_behavior="Relational foreign-key cascading purge",
        db_sync_required=True,
    ),
    DataClassification.REPORTS: LifecyclePolicy(
        classification=DataClassification.REPORTS,
        description="Publication-grade executive security briefings and technical forensic audit reports",
        storage_location="storage/reports/{id}.html, storage/reports/{id}.pdf",
        retention_period=f"{settings.RETENTION_REPORT_DAYS} days",
        access_boundary="Class A API download and safe sandboxed iframe preview",
        deletion_behavior="Physical file unlink + DB Report status set to PURGED",
        db_sync_required=True,
    ),
    DataClassification.TEMPORARY_LAB_FILES: LifecyclePolicy(
        classification=DataClassification.TEMPORARY_LAB_FILES,
        description="Ephemeral testbed namespaces, VICI sockets, swanctl config copies, staged pcaps",
        storage_location="/tmp/tt-{run_id}, storage/tmp/*",
        retention_period=f"{settings.RETENTION_TEMP_FILES_HOURS} hours (purged immediately upon experiment completion)",
        access_boundary="Strictly contained in /tmp/tt-* or storage/tmp, tracked by LabResourceTracker",
        deletion_behavior="Recursive directory removal + unmount /var/run tmpfs per peer",
        db_sync_required=False,
    ),
    DataClassification.AUDIT_LOGS: LifecyclePolicy(
        classification=DataClassification.AUDIT_LOGS,
        description="Structured operational security audit records and privileged action traces",
        storage_location="storage/audit/audit_events.jsonl",
        retention_period=f"{settings.RETENTION_AUDIT_LOG_DAYS} days",
        access_boundary="Append-only via SecurityAuditLogger, read-only via authorized internal query",
        deletion_behavior="Log rotation / archived to cold storage",
        db_sync_required=False,
    ),
    DataClassification.CONFIG_CERT_SNAPSHOTS: LifecyclePolicy(
        classification=DataClassification.CONFIG_CERT_SNAPSHOTS,
        description="Scrubbed strongSwan swanctl configuration baselines and X.509 certificate metadata",
        storage_location="Database (gateway_configuration_snapshots, gateway_certificates)",
        retention_period="Maintained as historical baseline audit lineage",
        access_boundary="Class A API, credentials scrubbed to [REDACTED_SECRET] before database commit",
        deletion_behavior="Explicit administrator baseline retirement",
        db_sync_required=True,
    ),
}


class DataLifecycleManager:
    """Manages operational data retention, storage audits, and safe artifact purging."""

    def __init__(self) -> None:
        self.storage = get_storage_provider()
        self.audit = SecurityAuditLogger.get_logger()

    @staticmethod
    def get_policies() -> dict[str, dict[str, Any]]:
        """Returns documented lifecycle policies formatted for audit disclosure."""
        return {
            k.value: {
                "classification": p.classification.value,
                "description": p.description,
                "storage_location": p.storage_location,
                "retention_period": p.retention_period,
                "access_boundary": p.access_boundary,
                "deletion_behavior": p.deletion_behavior,
                "db_sync_required": p.db_sync_required,
            }
            for k, p in LIFECYCLE_POLICIES.items()
        }

    def purge_temporary_staging_files(self, max_age_hours: int | None = None) -> dict[str, Any]:
        """Safely cleans up stale files in storage/tmp older than threshold."""
        age_limit = max_age_hours if max_age_hours is not None else settings.RETENTION_TEMP_FILES_HOURS
        now = time.time()
        cutoff_sec = now - (age_limit * 3600)

        tmp_dir = Path(settings.STORAGE_ROOT) / "tmp"
        if not tmp_dir.exists():
            return {"purged_files": 0, "purged_bytes": 0, "errors": []}

        purged_files = 0
        purged_bytes = 0
        errors: list[str] = []

        for item in tmp_dir.glob("**/*"):
            if item.is_file():
                try:
                    mtime = item.stat().st_mtime
                    if mtime < cutoff_sec:
                        size = item.stat().st_size
                        item.unlink()
                        purged_files += 1
                        purged_bytes += size
                except Exception as exc:
                    errors.append(f"Failed to delete '{item.name}': {exc}")

        self.audit.record_event(
            action="LIFECYCLE_PURGE_TMP",
            target_resource="storage/tmp",
            authorized_scope="storage:local",
            outcome=AuditOutcome.SUCCESS if not errors else AuditOutcome.FAILED,
            reason_or_error=errors[0] if errors else None,
            metadata={"purged_files": purged_files, "purged_bytes": purged_bytes},
        )

        return {
            "purged_files": purged_files,
            "purged_bytes": purged_bytes,
            "cutoff_hours": age_limit,
            "errors": errors,
        }

    async def purge_capture_artifact(
        self,
        capture_id: uuid.UUID,
        db: AsyncSession,
        operator_id: str = "system",
    ) -> dict[str, Any]:
        """Atomically unlinks physical PCAP bytes and transactionally updates DB state to PURGED."""
        stmt = select(Capture).where(Capture.id == capture_id)
        res = await db.execute(stmt)
        capture = res.scalar_one_or_none()

        if not capture:
            raise NotFoundError(f"Capture record '{capture_id}' not found.")

        stored_path = capture.storage_path
        original_sha = capture.sha256
        file_deleted = False
        bytes_freed = 0

        if stored_path:
            try:
                # Safe path resolution prevents deleting outside storage root
                target = self.storage.resolve_safe_path(stored_path)
                if target.exists() and target.is_file():
                    bytes_freed = target.stat().st_size
                    target.unlink()
                    file_deleted = True
            except (PathTraversalError, StorageError) as exc:
                logger.error(f"Error during physical capture deletion: {exc}")
                raise

        # Transactionally update Capture record
        capture.status = "PURGED"
        capture.storage_path = None
        capture.file_available = False
        await db.commit()

        self.audit.record_event(
            action="LIFECYCLE_PURGE_CAPTURE",
            target_resource=f"capture:{capture_id}",
            authorized_scope=f"capture_sha:{original_sha}",
            outcome=AuditOutcome.SUCCESS,
            actor_id=operator_id,
            evidence_ref=original_sha,
            metadata={
                "capture_id": str(capture_id),
                "file_deleted": file_deleted,
                "bytes_freed": bytes_freed,
                "new_status": "PURGED",
            },
        )

        return {
            "capture_id": str(capture_id),
            "status": "PURGED",
            "file_deleted": file_deleted,
            "bytes_freed": bytes_freed,
            "sha256_preserved": original_sha,
        }

    def inspect_storage_footprint(self) -> dict[str, Any]:
        """Calculates observed disk consumption across each storage category."""
        root = Path(settings.STORAGE_ROOT)
        categories = ["captures", "live", "reports", "tmp", "audit"]
        footprint: dict[str, dict[str, Any]] = {}
        total_bytes = 0

        for cat in categories:
            cat_dir = root / cat
            if not cat_dir.exists():
                footprint[cat] = {"file_count": 0, "total_bytes": 0, "exists": False}
                continue

            count = 0
            cat_bytes = 0
            for p in cat_dir.glob("**/*"):
                if p.is_file():
                    count += 1
                    try:
                        cat_bytes += p.stat().st_size
                    except OSError:
                        pass

            footprint[cat] = {
                "file_count": count,
                "total_bytes": cat_bytes,
                "total_mb": round(cat_bytes / (1024 * 1024), 2),
                "exists": True,
            }
            total_bytes += cat_bytes

        return {
            "storage_root": str(root.resolve()),
            "total_bytes": total_bytes,
            "total_mb": round(total_bytes / (1024 * 1024), 2),
            "categories": footprint,
        }
