"""Evidence-Based Risk and Policy Engine: Factor breakdowns, methodology hash, and ATT&CK bindings

Revision ID: 0016
Revises: 0015
Create Date: 2026-09-25 18:30:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Additive columns for risk_assessments
    op.add_column(
        "risk_assessments",
        sa.Column("evidence_coverage", sa.Float(), nullable=True),
    )
    op.add_column(
        "risk_assessments",
        sa.Column("evidence_gaps_count", sa.Integer(), nullable=True, server_default="0"),
    )
    op.add_column(
        "risk_assessments",
        sa.Column(
            "methodology_type",
            sa.String(length=64),
            nullable=True,
            server_default="DETERMINISTIC_PRIORITIZATION_HEURISTIC",
        ),
    )
    op.add_column(
        "risk_assessments",
        sa.Column(
            "external_context",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
    )

    # 2. Additive columns for threat_instances
    op.add_column(
        "threat_instances",
        sa.Column("mitre_attack_id", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "threat_instances",
        sa.Column("mitre_attack_name", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "threat_instances",
        sa.Column("mitre_attack_url", sa.String(length=256), nullable=True),
    )
    op.add_column(
        "threat_instances",
        sa.Column("mitre_attack_rationale", sa.Text(), nullable=True),
    )
    op.add_column(
        "threat_instances",
        sa.Column("catalog_hash", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    # 1. Drop threat_instances columns
    op.drop_column("threat_instances", "catalog_hash")
    op.drop_column("threat_instances", "mitre_attack_rationale")
    op.drop_column("threat_instances", "mitre_attack_url")
    op.drop_column("threat_instances", "mitre_attack_name")
    op.drop_column("threat_instances", "mitre_attack_id")

    # 2. Drop risk_assessments columns
    op.drop_column("risk_assessments", "external_context")
    op.drop_column("risk_assessments", "methodology_type")
    op.drop_column("risk_assessments", "evidence_gaps_count")
    op.drop_column("risk_assessments", "evidence_coverage")
