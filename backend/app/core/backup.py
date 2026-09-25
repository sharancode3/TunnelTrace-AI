"""
TunnelTrace AI - Database Backup & Disaster Recovery Subsystem
=============================================================
Provides consistent database backup creation, verification, and foreign-key
integrity validation across SQLite and PostgreSQL runtimes.

Recovery Invariants:
--------------------
1. Consistency Point: Backups must capture committed state with WAL/journal sync.
2. Integrity Verification: Post-backup validation tests foreign key integrity
   and verifies critical artifact SHA-256 digests.
3. Access Control: Backup artifacts contain sensitive telemetry and are restricted
   to storage/backups with non-root ownership.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import sqlite3
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.audit import AuditOutcome, SecurityAuditLogger
from app.core.config import settings

logger = logging.getLogger("tunneltrace.backup")


@dataclass
class BackupMetadata:
    """Documented metadata and verification state for a database backup artifact."""
    backup_id: str
    backup_file: str
    backup_sha256: str
    size_bytes: int
    created_at: str
    runtime_dialect: str
    tables_verified: int
    foreign_keys_valid: bool
    status: str


class DatabaseBackupManager:
    """Manages database backup creation and disaster recovery integrity audits."""

    def __init__(self, backup_dir: Path | str | None = None) -> None:
        self.backup_dir = (
            Path(backup_dir) if backup_dir else Path(settings.STORAGE_ROOT) / "backups"
        )
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.audit = SecurityAuditLogger.get_logger()

    def create_sqlite_backup(self, db_path: str | Path) -> BackupMetadata:
        """Atomically creates a consistent online SQLite backup using the SQLite backup API."""
        src_path = Path(db_path).resolve()
        if not src_path.exists():
            raise FileNotFoundError(f"Source database file '{src_path}' does not exist.")

        backup_id = f"backup_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        dest_file = self.backup_dir / f"{backup_id}.sqlite"

        # Use SQLite Online Backup API for 100% transactional consistency across WAL/shm
        src_conn = sqlite3.connect(str(src_path))
        dest_conn = sqlite3.connect(str(dest_file))
        try:
            with dest_conn:
                src_conn.backup(dest_conn)
        finally:
            dest_conn.close()
            src_conn.close()

        # Compute SHA-256 of backup artifact
        sha = hashlib.sha256()
        size_bytes = 0
        with open(dest_file, "rb") as f:
            while chunk := f.read(65536):
                sha.update(chunk)
                size_bytes += len(chunk)
        backup_sha = sha.hexdigest()

        # Verify integrity of the backup artifact
        verify_conn = sqlite3.connect(str(dest_file))
        try:
            cursor = verify_conn.cursor()
            cursor.execute("PRAGMA foreign_key_check;")
            fk_violations = cursor.fetchall()
            fk_valid = len(fk_violations) == 0

            cursor.execute("SELECT count(*) FROM sqlite_master WHERE type='table';")
            table_count = cursor.fetchone()[0]
        finally:
            verify_conn.close()

        metadata = BackupMetadata(
            backup_id=backup_id,
            backup_file=str(dest_file),
            backup_sha256=backup_sha,
            size_bytes=size_bytes,
            created_at=datetime.now(timezone.utc).isoformat(),
            runtime_dialect="sqlite",
            tables_verified=table_count,
            foreign_keys_valid=fk_valid,
            status="VERIFIED_CONSISTENT" if fk_valid else "FK_VIOLATIONS_DETECTED",
        )

        self.audit.record_event(
            action="DATABASE_BACKUP_CREATE",
            target_resource=str(dest_file),
            authorized_scope="db:local",
            outcome=AuditOutcome.SUCCESS if fk_valid else AuditOutcome.FAILED,
            evidence_ref=backup_sha,
            metadata={
                "backup_id": backup_id,
                "size_bytes": size_bytes,
                "tables_verified": table_count,
                "foreign_keys_valid": fk_valid,
            },
        )

        return metadata

    def verify_backup_file(self, backup_file_path: str | Path, expected_sha: str | None = None) -> dict[str, Any]:
        """Validates that a backup file exists, matches expected digest, and passes foreign key checks."""
        p = Path(backup_file_path).resolve()
        if not p.exists():
            return {"valid": False, "error": f"Backup file not found: {p}"}

        # Verify digest if provided
        sha = hashlib.sha256()
        with open(p, "rb") as f:
            while chunk := f.read(65536):
                sha.update(chunk)
        computed_sha = sha.hexdigest()

        if expected_sha and computed_sha != expected_sha:
            return {
                "valid": False,
                "error": f"Digest mismatch! Expected {expected_sha}, computed {computed_sha}",
            }

        # Check SQLite structure
        try:
            conn = sqlite3.connect(str(p))
            cursor = conn.cursor()
            cursor.execute("PRAGMA quick_check;")
            quick_check = cursor.fetchone()[0]

            cursor.execute("PRAGMA foreign_key_check;")
            fk_errors = cursor.fetchall()
            conn.close()

            is_valid = quick_check == "ok" and len(fk_errors) == 0
            return {
                "valid": is_valid,
                "quick_check": quick_check,
                "foreign_key_errors": len(fk_errors),
                "computed_sha256": computed_sha,
                "size_bytes": p.stat().st_size,
            }
        except Exception as exc:
            return {"valid": False, "error": f"Integrity check failed: {exc}"}
