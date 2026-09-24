"""Stage 2 migration: Authorized Asset Discovery (Nmap)

Revision ID: 0011
Revises: 0010
Create Date: 2026-09-24 21:15:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. discovery_jobs
    op.create_table(
        "discovery_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("job_name", sa.String(length=128), nullable=False),
        sa.Column("operator_id", sa.String(length=128), nullable=False),
        sa.Column("authorization_reference", sa.String(length=256), nullable=False),
        sa.Column("authorization_attestation", sa.Text(), nullable=False),
        sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("profile", sa.String(length=64), nullable=False, server_default="IKE_SERVICE_DISCOVERY"),
        sa.Column("requested_targets", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("canonical_targets", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("exclusions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("permitted_ports", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="QUEUED"),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("raw_output_sha256", sa.String(length=64), nullable=True),
        sa.Column("output_bytes_count", sa.Integer(), nullable=True),
        sa.Column("tool_version", sa.String(length=64), nullable=True),
        sa.Column("target_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("hosts_up_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("services_discovered_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_discovery_jobs_operator_id", "discovery_jobs", ["operator_id"])
    op.create_index("ix_discovery_jobs_status", "discovery_jobs", ["status"])

    # 2. discovered_hosts
    op.create_table(
        "discovered_hosts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("discovery_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ip_address", sa.String(length=64), nullable=False),
        sa.Column("ip_version", sa.String(length=16), nullable=False, server_default="IPv4"),
        sa.Column("state", sa.String(length=32), nullable=False, server_default="UP"),
        sa.Column("hostnames", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_discovered_hosts_job_id", "discovered_hosts", ["job_id"])
    op.create_index("ix_discovered_hosts_ip_address", "discovered_hosts", ["ip_address"])

    # 3. discovered_services
    op.create_table(
        "discovered_services",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("job_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("discovery_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("discovered_hosts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("state_reason", sa.String(length=64), nullable=True),
        sa.Column("service_name", sa.String(length=64), nullable=True),
        sa.Column("product", sa.String(length=128), nullable=True),
        sa.Column("version", sa.String(length=64), nullable=True),
        sa.Column("extra_info", sa.String(length=256), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("fingerprint", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_discovered_services_job_id", "discovered_services", ["job_id"])
    op.create_index("ix_discovered_services_host_id", "discovered_services", ["host_id"])
    op.create_index("ix_discovered_services_port", "discovered_services", ["port"])


def downgrade() -> None:
    op.drop_index("ix_discovered_services_port", table_name="discovered_services")
    op.drop_index("ix_discovered_services_host_id", table_name="discovered_services")
    op.drop_index("ix_discovered_services_job_id", table_name="discovered_services")
    op.drop_table("discovered_services")

    op.drop_index("ix_discovered_hosts_ip_address", table_name="discovered_hosts")
    op.drop_index("ix_discovered_hosts_job_id", table_name="discovered_hosts")
    op.drop_table("discovered_hosts")

    op.drop_index("ix_discovery_jobs_status", table_name="discovery_jobs")
    op.drop_index("ix_discovery_jobs_operator_id", table_name="discovery_jobs")
    op.drop_table("discovery_jobs")
