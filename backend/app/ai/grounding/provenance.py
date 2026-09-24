"""Answer Provenance Ledger for Grounded AI Analyst.

Persists cryptographic hashes and audit metadata proving exactly what facts,
standards chunks, prompt templates, and local models produced each generated explanation.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.ai import AnswerProvenanceRecordModel

logger = logging.getLogger(__name__)


class AnswerProvenanceLedger:
    """Audit ledger for immutable, tamper-evident AI explanation provenance."""

    @classmethod
    async def record_provenance(
        cls,
        session: AsyncSession,
        query_run_id: uuid.UUID,
        analysis_id: uuid.UUID | None,
        answer_text: str,
        fact_lock_hash: str,
        retrieved_source_ids: list[str],
        prompt_text: str,
        model_name: str,
        citation_summary: dict[str, Any],
    ) -> AnswerProvenanceRecordModel:
        """Create and persist an immutable answer provenance record."""
        # 1. Answer hash
        answer_hash = hashlib.sha256(answer_text.strip().encode("utf-8")).hexdigest()

        # 2. Retrieved sources hash
        sorted_sources = sorted(retrieved_source_ids)
        sources_hash = hashlib.sha256(json.dumps(sorted_sources).encode("utf-8")).hexdigest()

        # 3. Prompt hash
        prompt_hash = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()

        # 4. Model digest
        model_digest = hashlib.sha256(model_name.encode("utf-8")).hexdigest()

        record = AnswerProvenanceRecordModel(
            query_run_id=query_run_id,
            analysis_id=analysis_id,
            answer_hash=answer_hash,
            fact_lock_hash=fact_lock_hash,
            retrieved_sources_hash=sources_hash,
            prompt_hash=prompt_hash,
            model_digest=model_digest,
            citation_summary=citation_summary,
        )
        session.add(record)
        await session.flush()

        logger.info(
            "Recorded answer provenance for run %s: answer_hash=%s, fact_hash=%s",
            query_run_id,
            answer_hash[:8],
            fact_lock_hash[:8],
        )
        return record
