"""Unit tests for Stage 11 Authoritative Knowledge Ingestion and Parsing.

Tests:
- Section-aware parsing of approved standards
- Normative keyword extraction (MUST, SHALL, SHOULD)
- SHA-256 content hashing and chunk determinism
- Idempotent ingestion and index versioning
"""

import hashlib
import tempfile
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.ai.knowledge.parser import StandardsDocumentParser
from app.ai.knowledge.service import KnowledgeService
from app.db.base import Base
from app.db.models.ai import KnowledgeChunkModel, KnowledgeDocumentModel, KnowledgeIndexVersionModel


SAMPLE_STANDARD_MD = """# RFC 9999: Test IPsec Protocol Requirements
**Authority:** IETF
**Document Code:** RFC 9999
**Publication Date:** 2026-01-01
**URL:** https://www.rfc-editor.org/rfc/rfc9999

## Abstract
This document specifies test requirements for IPsec encryption.

### Section 1.1 Mandatory Ciphers
Implementations MUST support AES-GCM-256. Implementations SHOULD NOT use 3DES or DES.
CBC mode without AEAD is NOT RECOMMENDED.

### Section 1.2 Key Exchange
The initiator SHALL offer Diffie-Hellman Group 19 or higher.
"""


def test_standards_parser_extracts_sections_and_keywords():
    """Verify StandardsDocumentParser extracts sections, normative keywords, and hashes."""
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as tmp:
        tmp.write(SAMPLE_STANDARD_MD)
        tmp_path = Path(tmp.name)

    try:
        parsed = StandardsDocumentParser.parse_file(tmp_path)

        assert parsed.document_code == "RFC 9999"
        assert parsed.authority == "IETF"
        assert len(parsed.chunks) == 2

        # Check Chunk 1 (Section 1.1)
        c1 = parsed.chunks[0]
        assert c1.section_reference == "Section 1.1"
        assert "Mandatory Ciphers" in c1.section_title
        assert "MUST" in c1.normative_keywords
        assert "SHOULD NOT" in c1.normative_keywords
        assert len(c1.chunk_sha256) == 64

        # Check Chunk 2 (Section 1.2)
        c2 = parsed.chunks[1]
        assert c2.section_reference == "Section 1.2"
        assert "SHALL" in c2.normative_keywords

        # Source hash check
        expected_hash = hashlib.sha256(SAMPLE_STANDARD_MD.encode("utf-8")).hexdigest()
        assert parsed.source_sha256 == expected_hash
    finally:
        tmp_path.unlink(missing_ok=True)


def test_standards_parser_handles_unsectioned_fallback():
    """Verify single-chunk fallback if document contains no ### Section headers."""
    content = "# Simple Document\n**Authority:** NIST\n**Document Code:** SP 800-TEST\n\nAll gateways MUST use TLS 1.3 or IPsec."
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        parsed = StandardsDocumentParser.parse_file(tmp_path)
        assert len(parsed.chunks) == 1
        assert parsed.chunks[0].section_reference == "General"
        assert "MUST" in parsed.chunks[0].normative_keywords
    finally:
        tmp_path.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_knowledge_service_ingestion_idempotency(monkeypatch):
    """Verify KnowledgeService ingests standards and skips identical re-runs."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    # Mock provider.embed to avoid hitting real Ollama in fast unit tests
    class MockProvider:
        async def embed(self, texts: list[str], model: str | None = None):
            from app.ai.provider import EmbeddingResult
            return EmbeddingResult(
                embeddings=[[0.05] * 768 for _ in texts],
                model="nomic-embed-text",
                dimension=768,
                duration_ms=5.0,
            )

    svc = KnowledgeService()
    monkeypatch.setattr(svc, "provider", MockProvider())

    with tempfile.TemporaryDirectory() as tmp_dir:
        doc_path = Path(tmp_dir) / "RFC_9999.md"
        doc_path.write_text(SAMPLE_STANDARD_MD, encoding="utf-8")

        async with factory() as session:
            # First ingestion
            res1 = await svc.ingest_all_standards(session, standards_dir=tmp_dir)
            assert res1["status"] == "success"
            assert res1["documents_indexed"] == 1
            assert res1["chunks_indexed"] == 2

            # Check status
            status = await svc.get_index_status(session)
            assert status["is_indexed"] is True
            assert status["total_chunks"] == 2

            # Second ingestion with unchanged files (should skip re-embedding)
            res2 = await svc.ingest_all_standards(session, standards_dir=tmp_dir)
            assert res2["status"] == "success"
            assert res2["documents_indexed"] == 0  # Skipped!
            assert res2["chunks_indexed"] == 0
