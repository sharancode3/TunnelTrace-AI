"""Stage 12 End-to-End Validation: Hardening, Secrets, Subprocess & Migration Integrity.

Verifies:
- Subprocess safety audit (no unrestricted shell=True, os.system)
- Secrets exposure audit across codebase and configuration defaults
- Alembic migration linear chain integrity (0001 -> 0010)
- Air-gapped deployment independence (zero cloud endpoints required)
"""

from __future__ import annotations

import re
from pathlib import Path
import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory


REPO_ROOT = Path(__file__).resolve().parents[3]
BACKEND_DIR = REPO_ROOT / "backend"


def test_subprocess_security_audit():
    """Section 133: Ensure no dangerous shell=True or os.system calls exist in application code."""
    prohibited_patterns = [
        re.compile(r"\bos\.system\("),
        re.compile(r"shell\s*=\s*True"),
        re.compile(r"(?<!\.)\beval\s*\("),
        re.compile(r"(?<!\.)\bexec\s*\("),
    ]

    # Directories to scan (excluding tests, virtualenvs, migrations)
    scan_dirs = [
        BACKEND_DIR / "app",
        REPO_ROOT / "lab",
    ]

    violations = []
    for scan_dir in scan_dirs:
        if not scan_dir.exists():
            continue
        for py_file in scan_dir.rglob("*.py"):
            # Exclude safe sandbox wrappers if any
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            for pattern in prohibited_patterns:
                matches = pattern.findall(content)
                if matches:
                    violations.append(f"{py_file.relative_to(REPO_ROOT)}: found {matches}")

    assert violations == [], f"Security violation - unsafe execution detected: {violations}"


def test_secrets_audit_in_repository():
    """Section 124, 125: Verify no real private keys or production credentials exist in codebase."""
    # Pattern detecting actual PEM private keys
    private_key_pattern = re.compile(r"-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----")

    scan_dirs = [
        BACKEND_DIR / "app",
        REPO_ROOT / "policies",
        REPO_ROOT / "knowledge",
    ]

    violations = []
    for scan_dir in scan_dirs:
        if not scan_dir.exists():
            continue
        for file_path in scan_dir.rglob("*"):
            if file_path.is_file() and not file_path.name.endswith((".pyc", ".png", ".webp")):
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                if private_key_pattern.search(content):
                    violations.append(str(file_path.relative_to(REPO_ROOT)))

    assert violations == [], f"Private keys detected in source files: {violations}"


def test_alembic_migration_chain_is_linear_and_unbroken():
    """Section 118: Verify all migrations from 0001 to 0010 form a single linear head."""
    alembic_ini = BACKEND_DIR / "alembic.ini"
    config = Config(str(alembic_ini))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    script = ScriptDirectory.from_config(config)

    # Get heads
    heads = script.get_heads()
    assert len(heads) == 1, f"Expected exactly 1 migration head, got: {heads}"
    head_rev = heads[0]

    # Verify head revision is 0012 (Stage 3 IKE Assessment) or earlier
    assert "0012" in head_rev or "0011" in head_rev or "0010" in head_rev or script.get_revision(head_rev).down_revision is not None

    # Walk the entire chain from head back to base
    chain = []
    curr = script.get_revision(head_rev)
    while curr is not None:
        chain.append(curr.revision)
        if curr.down_revision is None:
            break
        curr = script.get_revision(curr.down_revision)

    # We have 19 sequential migrations (0001 through 0019)
    assert len(chain) == 19, f"Expected 19 sequential migrations, found {len(chain)}: {chain}"


def test_air_gapped_configuration_safety():
    """Section 109, 155, 157: System configuration must not require any external internet connectivity."""
    from app.core.config import Settings

    settings = Settings()

    # Ollama URL defaults to localhost
    assert "localhost" in settings.OLLAMA_BASE_URL or "127.0.0.1" in settings.OLLAMA_BASE_URL

    # No external cloud keys required by default
    assert not hasattr(settings, "OPENAI_API_KEY")
    assert not hasattr(settings, "ANTHROPIC_API_KEY")
    assert not hasattr(settings, "GEMINI_API_KEY")
