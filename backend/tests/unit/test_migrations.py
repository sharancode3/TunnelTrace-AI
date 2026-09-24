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
    assert heads[0] == "0012"

    # Invariant: verify chain 0012 -> 0011 -> 0010 -> 0009 -> 0008 -> 0007 -> 0006 -> 0005 -> 0004 -> 0003 -> 0002 -> 0001 -> None
    rev_0012 = script.get_revision("0012")
    assert rev_0012 is not None
    assert rev_0012.down_revision == "0011"

    rev_0011 = script.get_revision("0011")
    assert rev_0011 is not None
    assert rev_0011.down_revision == "0010"

    rev_0010 = script.get_revision("0010")
    assert rev_0010 is not None
    assert rev_0010.down_revision == "0009"

    rev_0009 = script.get_revision("0009")
    assert rev_0009 is not None
    assert rev_0009.down_revision == "0008"

    rev_0008 = script.get_revision("0008")
    assert rev_0008 is not None
    assert rev_0008.down_revision == "0007"

    rev_0007 = script.get_revision("0007")
    assert rev_0007 is not None
    assert rev_0007.down_revision == "0006"

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
