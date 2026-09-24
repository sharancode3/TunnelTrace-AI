"""Knowledge Ingestion and Management Service for Authoritative Standards.

Orchestrates parsing of approved standards, generation of 768-dimensional
embeddings via local Ollama (nomic-embed-text), transactional storage in
PostgreSQL with pgvector, and index versioning.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.knowledge.parser import StandardsDocumentParser
from app.ai.provider import get_llm_provider
from app.core.config import get_settings
from app.db.models.ai import (
    KnowledgeChunkModel,
    KnowledgeDocumentModel,
    KnowledgeIndexVersionModel,
)

logger = logging.getLogger(__name__)


class KnowledgeService:
    """Service for managing the authoritative standards knowledge base."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self.provider = get_llm_provider()

    async def ingest_all_standards(
        self, session: AsyncSession, standards_dir: Path | str | None = None
    ) -> dict[str, Any]:
        """Ingest all approved Markdown standards documents into PostgreSQL + pgvector.

        Transactional, idempotent, with content-hash checks to avoid duplicate embedding.
        """
        dir_path = Path(standards_dir or self.settings.STANDARDS_DIR)
        if not dir_path.exists() or not dir_path.is_dir():
            repo_root_dir = Path(__file__).resolve().parents[4] / "knowledge" / "standards"
            if repo_root_dir.exists() and repo_root_dir.is_dir():
                dir_path = repo_root_dir
            else:
                return {
                    "status": "error",
                    "message": f"Standards directory does not exist: {dir_path.resolve()}",
                    "documents_ingested": 0,
                    "chunks_ingested": 0,
                }

        md_files = sorted(dir_path.glob("*.md"))
        if not md_files:
            return {
                "status": "empty",
                "message": f"No Markdown standards found in {dir_path.resolve()}",
                "documents_ingested": 0,
                "chunks_ingested": 0,
            }

        docs_ingested = 0
        chunks_ingested = 0
        doc_hashes: list[str] = []

        for md_file in md_files:
            parsed = StandardsDocumentParser.parse_file(md_file)
            doc_hashes.append(parsed.source_sha256)

            # Check existing document record
            stmt = select(KnowledgeDocumentModel).where(
                KnowledgeDocumentModel.document_code == parsed.document_code
            )
            res = await session.execute(stmt)
            existing_doc = res.scalar_one_or_none()

            # If identical hash and already indexed, skip re-embedding
            if (
                existing_doc
                and existing_doc.source_sha256 == parsed.source_sha256
                and existing_doc.status == "INDEXED"
            ):
                logger.info("Document %s already indexed and unchanged; skipping.", parsed.document_code)
                continue

            # If existing doc needs update, remove old record and its chunks (cascade)
            if existing_doc:
                await session.delete(existing_doc)
                await session.flush()

            # Create document record
            doc_record = KnowledgeDocumentModel(
                document_code=parsed.document_code,
                title=parsed.title,
                authority=parsed.authority,
                revision=parsed.revision,
                publication_date=parsed.publication_date,
                source_url=parsed.source_url,
                source_file_path=parsed.source_file_path,
                source_sha256=parsed.source_sha256,
                status="INDEXING",
                parser_version=StandardsDocumentParser.PARSER_VERSION,
                total_sections=len(parsed.chunks),
                total_chunks=len(parsed.chunks),
            )
            session.add(doc_record)
            await session.flush()

            # Embed chunks in batch
            chunk_texts = [c.chunk_text for c in parsed.chunks]
            embed_res = await self.provider.embed(chunk_texts)

            for chunk_data, embedding_vec in zip(parsed.chunks, embed_res.embeddings):
                chunk_record = KnowledgeChunkModel(
                    document_id=doc_record.id,
                    document_code=chunk_data.document_code,
                    authority=chunk_data.authority,
                    revision=chunk_data.revision,
                    section_reference=chunk_data.section_reference,
                    section_title=chunk_data.section_title,
                    chunk_index=chunk_data.chunk_index,
                    chunk_text=chunk_data.chunk_text,
                    chunk_sha256=chunk_data.chunk_sha256,
                    normative_keywords=list(chunk_data.normative_keywords),
                    embedding_model=embed_res.model,
                    embedding=embedding_vec,
                )
                session.add(chunk_record)
                chunks_ingested += 1

            doc_record.status = "INDEXED"
            docs_ingested += 1

        # Count total active documents and chunks
        total_docs_res = await session.execute(
            select(KnowledgeDocumentModel).where(KnowledgeDocumentModel.status == "INDEXED")
        )
        all_indexed_docs = total_docs_res.scalars().all()
        total_doc_count = len(all_indexed_docs)

        total_chunks_res = await session.execute(select(KnowledgeChunkModel))
        total_chunk_count = len(total_chunks_res.scalars().all())

        # Create or update index version
        combined_hash = hashlib.sha256("".join(sorted(doc_hashes)).encode("utf-8")).hexdigest()
        version_tag = f"index-v1-{combined_hash[:8]}"

        # Deactivate old versions
        await session.execute(
            KnowledgeIndexVersionModel.__table__.update().values(is_active=False)
        )

        existing_ver_res = await session.execute(
            select(KnowledgeIndexVersionModel).where(
                KnowledgeIndexVersionModel.version_tag == version_tag
            )
        )
        existing_ver = existing_ver_res.scalar_one_or_none()
        if existing_ver:
            existing_ver.is_active = True
            existing_ver.document_count = total_doc_count
            existing_ver.chunk_count = total_chunk_count
        else:
            version_record = KnowledgeIndexVersionModel(
                version_tag=version_tag,
                embedding_model=self.settings.AI_EMBEDDING_MODEL,
                vector_dimension=self.settings.AI_EMBEDDING_DIM,
                document_count=total_doc_count,
                chunk_count=total_chunk_count,
                corpus_hash=combined_hash,
                is_active=True,
            )
            session.add(version_record)
        await session.commit()

        return {
            "status": "success",
            "version_tag": version_tag,
            "documents_indexed": docs_ingested,
            "chunks_indexed": chunks_ingested,
            "total_documents": total_doc_count,
            "total_chunks": total_chunk_count,
            "corpus_hash": combined_hash,
            "embedding_model": self.settings.AI_EMBEDDING_MODEL,
            "vector_dimension": self.settings.AI_EMBEDDING_DIM,
        }

    async def get_index_status(self, session: AsyncSession) -> dict[str, Any]:
        """Retrieve current status and statistics of the knowledge base."""
        version_stmt = (
            select(KnowledgeIndexVersionModel)
            .where(KnowledgeIndexVersionModel.is_active == True)
            .order_by(KnowledgeIndexVersionModel.created_at.desc())
        )
        res = await session.execute(version_stmt)
        active_version = res.scalar_one_or_none()

        docs_res = await session.execute(select(KnowledgeDocumentModel))
        docs = docs_res.scalars().all()

        return {
            "is_indexed": active_version is not None and active_version.chunk_count > 0,
            "active_version": active_version.version_tag if active_version else None,
            "embedding_model": active_version.embedding_model if active_version else self.settings.AI_EMBEDDING_MODEL,
            "vector_dimension": active_version.vector_dimension if active_version else self.settings.AI_EMBEDDING_DIM,
            "total_documents": len(docs),
            "total_chunks": active_version.chunk_count if active_version else 0,
            "documents": [
                {
                    "document_code": d.document_code,
                    "title": d.title,
                    "authority": d.authority,
                    "revision": d.revision,
                    "status": d.status,
                    "chunks": d.total_chunks,
                }
                for d in docs
            ],
        }

    async def semantic_search(
        self,
        session: AsyncSession,
        query: str,
        top_k: int | None = None,
        similarity_threshold: float | None = None,
        document_code: str | None = None,
    ) -> list[tuple[KnowledgeChunkModel, float]]:
        """Perform semantic vector search against knowledge chunks using pgvector cosine distance."""
        k = top_k or self.settings.AI_RETRIEVAL_TOP_K
        threshold = (
            similarity_threshold
            if similarity_threshold is not None
            else self.settings.AI_RETRIEVAL_SIMILARITY_THRESHOLD
        )

        embed_res = await self.provider.embed([query])
        if not embed_res.embeddings:
            return []

        query_vec = embed_res.embeddings[0]

        bind = session.bind
        dialect_name = bind.dialect.name if bind is not None else ""

        if dialect_name == "postgresql":
            # pgvector cosine_distance returns 1 - cosine_similarity
            distance_expr = KnowledgeChunkModel.embedding.cosine_distance(query_vec)
            query_stmt = select(KnowledgeChunkModel, distance_expr.label("distance")).order_by(
                distance_expr.asc()
            )
            if document_code:
                query_stmt = query_stmt.where(KnowledgeChunkModel.document_code == document_code)
            query_stmt = query_stmt.limit(k)
            result = await session.execute(query_stmt)

            matches: list[tuple[KnowledgeChunkModel, float]] = []
            for row in result.all():
                chunk: KnowledgeChunkModel = row[0]
                dist: float = float(row[1])
                similarity = max(0.0, min(1.0, 1.0 - dist))
                if similarity >= threshold:
                    matches.append((chunk, round(similarity, 4)))
            return matches

        # Non-PostgreSQL dialect fallback (e.g. SQLite in-memory test environment)
        import math

        query_stmt = select(KnowledgeChunkModel)
        if document_code:
            query_stmt = query_stmt.where(KnowledgeChunkModel.document_code == document_code)
        result = await session.execute(query_stmt)
        all_chunks = result.scalars().all()

        def _calc_sim(vec_a: list[float], vec_b: list[float]) -> float:
            dot = sum(x * y for x, y in zip(vec_a, vec_b))
            norm_a = math.sqrt(sum(x * x for x in vec_a))
            norm_b = math.sqrt(sum(y * y for y in vec_b))
            if norm_a == 0.0 or norm_b == 0.0:
                return 0.0
            return dot / (norm_a * norm_b)

        scored_chunks: list[tuple[KnowledgeChunkModel, float]] = []
        for chunk in all_chunks:
            # Chunk embedding could be string in SQLite or list
            raw_emb = chunk.embedding
            if isinstance(raw_emb, str):
                import json
                try:
                    raw_emb = json.loads(raw_emb)
                except Exception:
                    continue
            sim = _calc_sim(query_vec, raw_emb)
            if sim >= threshold:
                scored_chunks.append((chunk, round(sim, 4)))

        scored_chunks.sort(key=lambda x: x[1], reverse=True)
        return scored_chunks[:k]

    async def lexical_search(
        self,
        session: AsyncSession,
        query: str,
        top_k: int | None = None,
        document_code: str | None = None,
    ) -> list[tuple[KnowledgeChunkModel, float]]:
        """Perform lexical keyword search against chunk text and section titles."""
        k = top_k or self.settings.AI_RETRIEVAL_TOP_K
        terms = [t.strip().lower() for t in query.split() if len(t.strip()) > 2]
        if not terms:
            return []

        query_stmt = select(KnowledgeChunkModel)
        if document_code:
            query_stmt = query_stmt.where(KnowledgeChunkModel.document_code == document_code)

        result = await session.execute(query_stmt)
        all_chunks = result.scalars().all()

        scored: list[tuple[KnowledgeChunkModel, float]] = []
        for chunk in all_chunks:
            text_lower = chunk.chunk_text.lower()
            title_lower = chunk.section_title.lower()
            ref_lower = chunk.section_reference.lower()

            score = 0.0
            for term in terms:
                if term in ref_lower:
                    score += 3.0
                if term in title_lower:
                    score += 2.0
                if term in text_lower:
                    score += 1.0

            if score > 0:
                scored.append((chunk, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:k]

    async def hybrid_search(
        self,
        session: AsyncSession,
        query: str,
        top_k: int | None = None,
        similarity_threshold: float | None = None,
        document_code: str | None = None,
    ) -> list[tuple[KnowledgeChunkModel, float]]:
        """Combine semantic vector search and lexical search using Reciprocal Rank Fusion (RRF)."""
        k = top_k or self.settings.AI_RETRIEVAL_TOP_K
        rrf_k = 60

        # Run vector search
        vector_results = await self.semantic_search(
            session, query, top_k=k * 2, similarity_threshold=similarity_threshold, document_code=document_code
        )

        # Run lexical search
        lexical_results = await self.lexical_search(
            session, query, top_k=k * 2, document_code=document_code
        )

        rrf_scores: dict[str, float] = {}
        chunk_map: dict[str, KnowledgeChunkModel] = {}

        for rank, (chunk, _) in enumerate(vector_results):
            cid = str(chunk.id)
            chunk_map[cid] = chunk
            rrf_scores[cid] = rrf_scores.get(cid, 0.0) + (1.0 / (rrf_k + rank + 1))

        for rank, (chunk, _) in enumerate(lexical_results):
            cid = str(chunk.id)
            chunk_map[cid] = chunk
            rrf_scores[cid] = rrf_scores.get(cid, 0.0) + (1.0 / (rrf_k + rank + 1))

        sorted_items = sorted(rrf_scores.items(), key=lambda x: x[1], reverse=True)
        return [(chunk_map[cid], round(score, 4)) for cid, score in sorted_items[:k]]

    async def get_exact_chunk_by_reference(
        self, session: AsyncSession, document_code: str, section_reference: str
    ) -> KnowledgeChunkModel | None:
        """Exact lookup of a normative standard chunk by document code and section reference."""
        stmt = select(KnowledgeChunkModel).where(
            KnowledgeChunkModel.document_code == document_code,
            KnowledgeChunkModel.section_reference.ilike(f"%{section_reference}%"),
        )
        res = await session.execute(stmt)
        return res.scalar_one_or_none()


_knowledge_service: KnowledgeService | None = None


def get_knowledge_service() -> KnowledgeService:
    """Singleton getter for KnowledgeService."""
    global _knowledge_service
    if _knowledge_service is None:
        _knowledge_service = KnowledgeService()
    return _knowledge_service
