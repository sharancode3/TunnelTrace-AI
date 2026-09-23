"""Initial migration: enable pgvector extension

Revision ID: 0001
Revises: None
Create Date: 2026-09-23 22:45:00.000000

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Enable pgvector extension for subsequent embedding storage
    op.execute("CREATE EXTENSION IF NOT EXISTS vector;")


def downgrade() -> None:
    # Drop pgvector extension if tearing down from scratch
    op.execute("DROP EXTENSION IF EXISTS vector;")
