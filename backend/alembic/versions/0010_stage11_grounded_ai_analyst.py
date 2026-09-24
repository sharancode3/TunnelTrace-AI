"""Stage 11 migration: Grounded AI Analyst, Standards Knowledge Corpus & Answer Provenance

Revision ID: 0010
Revises: 0009
Create Date: 2026-09-24 18:45:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from pgvector.sqlalchemy import Vector
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Ensure vector extension is present
    op.execute("CREATE EXTENSION IF NOT EXISTS vector;")

    # 1. knowledge_documents
    op.create_table(
        "knowledge_documents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("document_code", sa.String(length=64), nullable=False, unique=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("authority", sa.String(length=64), nullable=False),
        sa.Column("revision", sa.String(length=32), nullable=False),
        sa.Column("publication_date", sa.String(length=32), nullable=True),
        sa.Column("source_url", sa.String(length=512), nullable=True),
        sa.Column("source_file_path", sa.String(length=512), nullable=False),
        sa.Column("source_sha256", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="APPROVED"),
        sa.Column("parser_version", sa.String(length=32), nullable=False, server_default="1.0.0"),
        sa.Column("total_sections", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_chunks", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_knowledge_documents_document_code", "knowledge_documents", ["document_code"])
    op.create_index("ix_knowledge_documents_source_sha256", "knowledge_documents", ["source_sha256"])

    # 2. knowledge_chunks
    op.create_table(
        "knowledge_chunks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "document_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("knowledge_documents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("document_code", sa.String(length=64), nullable=False),
        sa.Column("authority", sa.String(length=64), nullable=False),
        sa.Column("revision", sa.String(length=32), nullable=False),
        sa.Column("section_reference", sa.String(length=64), nullable=False),
        sa.Column("section_title", sa.String(length=255), nullable=False),
        sa.Column("chunk_index", sa.Integer(), nullable=False),
        sa.Column("chunk_text", sa.Text(), nullable=False),
        sa.Column("chunk_sha256", sa.String(length=64), nullable=False),
        sa.Column("normative_keywords", sa.JSON().with_variant(postgresql.JSONB, "postgresql"), nullable=True),
        sa.Column("embedding_model", sa.String(length=64), nullable=False),
        sa.Column("embedding", Vector(768), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_knowledge_chunks_document_id", "knowledge_chunks", ["document_id"])
    op.create_index("ix_knowledge_chunks_document_code", "knowledge_chunks", ["document_code"])
    op.create_index("ix_knowledge_chunks_section_reference", "knowledge_chunks", ["section_reference"])
    op.create_index("ix_knowledge_chunks_chunk_sha256", "knowledge_chunks", ["chunk_sha256"])

    # 3. knowledge_index_versions
    op.create_table(
        "knowledge_index_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("version_tag", sa.String(length=64), nullable=False, unique=True),
        sa.Column("embedding_model", sa.String(length=64), nullable=False),
        sa.Column("vector_dimension", sa.Integer(), nullable=False, server_default="768"),
        sa.Column("document_count", sa.Integer(), nullable=False),
        sa.Column("chunk_count", sa.Integer(), nullable=False),
        sa.Column("corpus_hash", sa.String(length=64), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_knowledge_index_versions_version_tag", "knowledge_index_versions", ["version_tag"])

    # 4. ai_chat_sessions
    op.create_table(
        "ai_chat_sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_runs.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("title", sa.String(length=255), nullable=False, server_default="Security Analysis Session"),
        sa.Column("model_name", sa.String(length=64), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_ai_chat_sessions_analysis_id", "ai_chat_sessions", ["analysis_id"])

    # 5. ai_chat_messages
    op.create_table(
        "ai_chat_messages",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "session_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ai_chat_sessions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="COMPLETED"),
        sa.Column("claims", sa.JSON().with_variant(postgresql.JSONB, "postgresql"), nullable=True),
        sa.Column("citations", sa.JSON().with_variant(postgresql.JSONB, "postgresql"), nullable=True),
        sa.Column("limitations", sa.JSON().with_variant(postgresql.JSONB, "postgresql"), nullable=True),
        sa.Column("fact_locks", sa.JSON().with_variant(postgresql.JSONB, "postgresql"), nullable=True),
        sa.Column("query_run_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_ai_chat_messages_session_id", "ai_chat_messages", ["session_id"])

    # 6. rag_query_runs
    op.create_table(
        "rag_query_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_runs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "session_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ai_chat_sessions.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("query_text_hash", sa.String(length=64), nullable=False),
        sa.Column("query_intent", sa.String(length=64), nullable=False, server_default="GENERAL"),
        sa.Column("retrieved_source_ids", sa.JSON().with_variant(postgresql.JSONB, "postgresql"), nullable=False),
        sa.Column("model_name", sa.String(length=64), nullable=False),
        sa.Column("embedding_model", sa.String(length=64), nullable=False),
        sa.Column("prompt_template_version", sa.String(length=32), nullable=False, server_default="1.0.0"),
        sa.Column("citation_validity_rate", sa.Float(), nullable=True),
        sa.Column("execution_status", sa.String(length=32), nullable=False, server_default="COMPLETED"),
        sa.Column("latency_ms", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_rag_query_runs_analysis_id", "rag_query_runs", ["analysis_id"])
    op.create_index("ix_rag_query_runs_session_id", "rag_query_runs", ["session_id"])

    # 7. answer_provenance_records
    op.create_table(
        "answer_provenance_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "query_run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("rag_query_runs.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("analysis_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("answer_hash", sa.String(length=64), nullable=False),
        sa.Column("fact_lock_hash", sa.String(length=64), nullable=False),
        sa.Column("retrieved_sources_hash", sa.String(length=64), nullable=False),
        sa.Column("prompt_hash", sa.String(length=64), nullable=False),
        sa.Column("model_digest", sa.String(length=64), nullable=False),
        sa.Column("citation_summary", sa.JSON().with_variant(postgresql.JSONB, "postgresql"), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_answer_provenance_records_query_run_id", "answer_provenance_records", ["query_run_id"])
    op.create_index("ix_answer_provenance_records_analysis_id", "answer_provenance_records", ["analysis_id"])
    op.create_index("ix_answer_provenance_records_answer_hash", "answer_provenance_records", ["answer_hash"])


def downgrade() -> None:
    op.drop_table("answer_provenance_records")
    op.drop_table("rag_query_runs")
    op.drop_table("ai_chat_messages")
    op.drop_table("ai_chat_sessions")
    op.drop_table("knowledge_index_versions")
    op.drop_table("knowledge_chunks")
    op.drop_table("knowledge_documents")
