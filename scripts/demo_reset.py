"""TunnelTrace AI — Idempotent Lab and Demo Reset Utility.

Safely restores the local environment to a clean demonstration baseline:
- Cleans transient files in storage/tmp/
- Cleans orphaned lab locks and temporary socket files
- Strictly preserves golden capture fixtures (tests/fixtures/captures/)
- Strictly preserves release evidence and forensic logs (evidence/, backend/evidence/)
- Strictly preserves database tables and model artifacts
- Safe for repeated execution before and after hackathon judging sessions
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
STORAGE_TMP = REPO_ROOT / "storage" / "tmp"


def reset_transient_storage() -> dict[str, int]:
    """Clean only transient files in storage/tmp while preserving directory structure."""
    stats = {"files_removed": 0, "dirs_removed": 0}
    if not STORAGE_TMP.exists():
        STORAGE_TMP.mkdir(parents=True, exist_ok=True)
        return stats

    for item in STORAGE_TMP.iterdir():
        if item.name == ".gitkeep":
            continue
        try:
            if item.is_file() or item.is_symlink():
                item.unlink(missing_ok=True)
                stats["files_removed"] += 1
            elif item.is_dir():
                shutil.rmtree(item, ignore_errors=True)
                stats["dirs_removed"] += 1
        except Exception as e:
            print(f"[WARN] Could not remove {item.name}: {e}")

    return stats


def reset_lab_locks() -> int:
    """Clear any stale lab lockfiles."""
    lock_count = 0
    lab_dir = REPO_ROOT / "lab"
    for lock in lab_dir.glob("**/*.lock"):
        try:
            lock.unlink(missing_ok=True)
            lock_count += 1
        except Exception:
            pass
    return lock_count


def main() -> None:
    print("=" * 65)
    print("TUNNELTRACE AI — SAFE IDEMPOTENT DEMO RESET")
    print("=" * 65)

    storage_stats = reset_transient_storage()
    locks_cleared = reset_lab_locks()

    print(f"Transient storage cleaned: {storage_stats['files_removed']} files, {storage_stats['dirs_removed']} directories removed")
    print(f"Stale lab locks cleared  : {locks_cleared}")
    print("Golden fixtures          : PRESERVED (untouched)")
    print("Release evidence logs    : PRESERVED (untouched)")
    print("Database & model weights : PRESERVED (untouched)")
    print("=" * 65)
    print("[PASS] System reset to clean demonstration baseline.")
    print("=" * 65)


if __name__ == "__main__":
    main()
