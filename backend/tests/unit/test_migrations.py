"""Unit tests for Alembic database migration lineage and consistency."""

from pathlib import Path

import alembic.config
from alembic.script import ScriptDirectory


def test_alembic_migration_lineage():
    """Verify Alembic migration linear history from 0001 to 0003 without forks or detached heads."""
    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    ini_path = repo_root / "backend" / "alembic.ini"
    script_location = repo_root / "backend" / "alembic"

    cfg = alembic.config.Config(str(ini_path))
    cfg.set_main_option("script_location", str(script_location))

    script = ScriptDirectory.from_config(cfg)
    heads = script.get_heads()

    # Invariant: exactly one head revision
    assert len(heads) == 1
    assert heads[0] == "0006"

    # Invariant: verify chain 0006 -> 0005 -> 0004 -> 0003 -> 0002 -> 0001 -> None
    rev_0006 = script.get_revision("0006")
    assert rev_0006 is not None
    assert rev_0006.down_revision == "0005"

    rev_0005 = script.get_revision("0005")
    assert rev_0005 is not None
    assert rev_0005.down_revision == "0004"

    rev_0004 = script.get_revision("0004")
    assert rev_0004 is not None
    assert rev_0004.down_revision == "0003"

    rev_0003 = script.get_revision("0003")
    assert rev_0003 is not None
    assert rev_0003.down_revision == "0002"

    rev_0002 = script.get_revision("0002")
    assert rev_0002 is not None
    assert rev_0002.down_revision == "0001"

    rev_0001 = script.get_revision("0001")
    assert rev_0001 is not None
    assert rev_0001.down_revision is None
