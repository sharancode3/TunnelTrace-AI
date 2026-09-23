"""Stage 7 migration: Flow Classifications

Revision ID: 0006
Revises: 0005
Create Date: 2026-09-24 01:25:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "flow_classifications",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "flow_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("esp_flows.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "artifact_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("model_artifacts.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("known_class", sa.String(length=64), nullable=False),
        sa.Column("final_class", sa.String(length=64), nullable=False),
        sa.Column("calibrated_confidence", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("entropy", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("normalized_entropy", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("ood_status", sa.String(length=32), nullable=False, server_default="KNOWN_ACCEPTED"),
        sa.Column("rejection_reason", sa.String(length=64), nullable=True),
        sa.Column("is_degraded", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("degraded_reason", sa.String(length=128), nullable=True),
        sa.Column("behavioral_anomaly_status", sa.String(length=64), nullable=False, server_default="NORMAL_BEHAVIOR"),
        sa.Column("anomaly_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column(
            "transparency_data",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_flow_classifications_flow_id", "flow_classifications", ["flow_id"])
    op.create_index("ix_flow_classifications_artifact_id", "flow_classifications", ["artifact_id"])


def downgrade() -> None:
    op.drop_index("ix_flow_classifications_artifact_id", table_name="flow_classifications")
    op.drop_index("ix_flow_classifications_flow_id", table_name="flow_classifications")
    op.drop_table("flow_classifications")
