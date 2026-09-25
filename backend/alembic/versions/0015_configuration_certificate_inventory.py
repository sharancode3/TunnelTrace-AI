"""Configuration and Certificate Inventory: Snapshots, Baselines, Drifts, and Public Certificates

Revision ID: 0015
Revises: 0014
Create Date: 2026-09-24 23:30:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. gateway_configuration_snapshots
    op.create_table(
        "gateway_configuration_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "gateway_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("monitored_gateways.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("gateway_identity", sa.String(length=128), nullable=False),
        sa.Column("authorized_scope", sa.String(length=256), nullable=False, server_default="0.0.0.0/0"),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("collection_method", sa.String(length=64), nullable=False, server_default="OFFLINE_IMPORT"),
        sa.Column("collector_version", sa.String(length=32), nullable=False, server_default="1.0.0"),
        sa.Column("parser_version", sa.String(length=32), nullable=False, server_default="swanctl-6.0.4"),
        sa.Column("schema_version", sa.String(length=32), nullable=False, server_default="1.0.0"),
        sa.Column("canonical_digest", sa.String(length=64), nullable=False),
        sa.Column("normalized_ir", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("unsupported_directives", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("is_baseline", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("baseline_version", sa.Integer(), nullable=True),
        sa.Column("approved_by", sa.String(length=128), nullable=True),
        sa.Column("approval_reference", sa.String(length=256), nullable=True),
        sa.Column("source_observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("provenance", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index(
        "ix_gateway_config_snapshots_gateway_id",
        "gateway_configuration_snapshots",
        ["gateway_id"],
    )
    op.create_index(
        "ix_gateway_config_snapshots_gateway_identity",
        "gateway_configuration_snapshots",
        ["gateway_identity"],
    )
    op.create_index(
        "ix_gateway_config_snapshots_source_type",
        "gateway_configuration_snapshots",
        ["source_type"],
    )
    op.create_index(
        "ix_gateway_config_snapshots_canonical_digest",
        "gateway_configuration_snapshots",
        ["canonical_digest"],
    )
    op.create_index(
        "ix_gateway_config_snapshots_is_baseline",
        "gateway_configuration_snapshots",
        ["is_baseline"],
    )

    # 2. gateway_configuration_drifts
    op.create_table(
        "gateway_configuration_drifts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("gateway_identity", sa.String(length=128), nullable=False),
        sa.Column(
            "baseline_snapshot_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("gateway_configuration_snapshots.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "observed_snapshot_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("gateway_configuration_snapshots.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("comparison_status", sa.String(length=32), nullable=False),
        sa.Column("drift_summary", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("field_drifts", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index(
        "ix_gateway_config_drifts_gateway_identity",
        "gateway_configuration_drifts",
        ["gateway_identity"],
    )
    op.create_index(
        "ix_gateway_config_drifts_baseline_snapshot_id",
        "gateway_configuration_drifts",
        ["baseline_snapshot_id"],
    )
    op.create_index(
        "ix_gateway_config_drifts_observed_snapshot_id",
        "gateway_configuration_drifts",
        ["observed_snapshot_id"],
    )
    op.create_index(
        "ix_gateway_config_drifts_comparison_status",
        "gateway_configuration_drifts",
        ["comparison_status"],
    )

    # 3. gateway_certificates
    op.create_table(
        "gateway_certificates",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "gateway_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("monitored_gateways.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("gateway_identity", sa.String(length=128), nullable=False),
        sa.Column(
            "snapshot_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("gateway_configuration_snapshots.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("sha256_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("serial_number", sa.String(length=128), nullable=False),
        sa.Column("subject_dn", sa.String(length=512), nullable=False),
        sa.Column("issuer_dn", sa.String(length=512), nullable=False),
        sa.Column("subject_alt_names", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("not_valid_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("not_valid_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("validity_status", sa.String(length=32), nullable=False),
        sa.Column("days_until_expiry", sa.Integer(), nullable=False),
        sa.Column("public_key_algorithm", sa.String(length=64), nullable=False),
        sa.Column("public_key_bits", sa.Integer(), nullable=False),
        sa.Column("signature_algorithm", sa.String(length=64), nullable=False),
        sa.Column("is_ca", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("key_usages", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("extended_key_usages", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("associated_connection", sa.String(length=128), nullable=True),
        sa.Column("identity_association_status", sa.String(length=32), nullable=False, server_default="UNASSOCIATED"),
        sa.Column("chain_validation_status", sa.String(length=32), nullable=False, server_default="UNCHECKED"),
        sa.Column("trust_store_identifier", sa.String(length=128), nullable=True),
        sa.Column("trust_store_digest", sa.String(length=64), nullable=True),
        sa.Column("revocation_status", sa.String(length=32), nullable=False, server_default="UNCHECKED"),
        sa.Column("source_alias", sa.String(length=256), nullable=False, server_default="x509_certificate"),
        sa.Column("epistemic_status", sa.String(length=32), nullable=False, server_default="CONFIGURED"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index(
        "ix_gateway_certificates_gateway_id",
        "gateway_certificates",
        ["gateway_id"],
    )
    op.create_index(
        "ix_gateway_certificates_gateway_identity",
        "gateway_certificates",
        ["gateway_identity"],
    )
    op.create_index(
        "ix_gateway_certificates_snapshot_id",
        "gateway_certificates",
        ["snapshot_id"],
    )
    op.create_index(
        "ix_gateway_certificates_sha256_fingerprint",
        "gateway_certificates",
        ["sha256_fingerprint"],
    )
    op.create_index(
        "ix_gateway_certificates_validity_status",
        "gateway_certificates",
        ["validity_status"],
    )


def downgrade() -> None:
    op.drop_table("gateway_certificates")
    op.drop_table("gateway_configuration_drifts")
    op.drop_table("gateway_configuration_snapshots")
