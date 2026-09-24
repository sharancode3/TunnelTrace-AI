"""FastAPI Router for Grounded AI Analyst and Knowledge Base (Stage 11).

Endpoints:
- POST /analyses/{analysis_id}/ai/chat: Grounded conversational forensic Q&A
- GET  /analyses/{analysis_id}/ai/chat/{session_id}: Retrieve chat session history
- GET  /analyses/{analysis_id}/ai/search: Deterministic evidence search fallback
- GET  /ai/health: AI subsystem and local LLM runtime health check
- GET  /ai/knowledge/status: Authoritative knowledge corpus index status
- POST /ai/knowledge/ingest: Trigger ingestion of approved standards
- POST /analyses/{analysis_id}/ai/benchmark: Empirical benchmark comparing Qwen 3 4B vs Gemma 3 4B
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.analyst import get_analyst_service
from app.ai.knowledge.service import get_knowledge_service
from app.ai.provider import get_llm_provider
from app.ai.retrieval.engine import get_retrieval_engine
from app.core.config import get_settings
from app.db.models.ai import AIChatMessageModel, AIChatSessionModel
from app.db.models.capture import AnalysisRun
from app.db.session import get_db_session

router = APIRouter(tags=["Grounded AI Analyst / RAG"])


# --- Schemas ---
class ChatQueryRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=2000, description="Analyst question regarding current analysis")
    session_id: uuid.UUID | None = Field(default=None, description="Optional existing session ID")
    model_override: str | None = Field(default=None, description="Optional local model override (e.g. qwen3 or gemma3)")


class ChatQueryResponse(BaseModel):
    query_run_id: str
    session_id: str
    analysis_id: str
    status: str
    answer: str
    claims: list[dict[str, Any]]
    citations: list[dict[str, Any]]
    limitations: list[str]
    provenance: dict[str, Any] | None = None
    metrics: dict[str, Any]


class ChatMessageOut(BaseModel):
    id: uuid.UUID
    role: str
    content: str
    status: str
    claims: list[dict[str, Any]] | None
    citations: list[dict[str, Any]] | None
    limitations: list[str] | None
    created_at: str


class ChatSessionHistoryResponse(BaseModel):
    session_id: uuid.UUID
    analysis_id: uuid.UUID | None
    title: str
    model_name: str
    is_active: bool
    messages: list[ChatMessageOut]


class EvidenceSearchResponse(BaseModel):
    analysis_id: str
    query: str
    intent: str
    fact_lock_hash: str
    matched_facts: list[dict[str, Any]]
    matched_standards: list[dict[str, Any]]


# --- Routes ---

@router.post("/analyses/{analysis_id}/ai/chat", response_model=ChatQueryResponse)
async def chat_analysis(
    analysis_id: uuid.UUID,
    req: ChatQueryRequest,
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Execute grounded question answering against an immutable AnalysisRun."""
    # Verify analysis exists
    run_res = await session.execute(select(AnalysisRun).where(AnalysisRun.id == analysis_id))
    if not run_res.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AnalysisRun not found: {analysis_id}",
        )

    analyst = get_analyst_service()
    result = await analyst.execute_query(
        session=session,
        analysis_id=analysis_id,
        question=req.question,
        chat_session_id=req.session_id,
        model_override=req.model_override,
    )
    return result


@router.get("/analyses/{analysis_id}/ai/chat/{session_id}", response_model=ChatSessionHistoryResponse)
async def get_chat_history(
    analysis_id: uuid.UUID,
    session_id: uuid.UUID,
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Retrieve full message history for a scoped chat session."""
    stmt = select(AIChatSessionModel).where(
        AIChatSessionModel.id == session_id,
        AIChatSessionModel.analysis_id == analysis_id,
    )
    res = await session.execute(stmt)
    chat_sess = res.scalar_one_or_none()
    if not chat_sess:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat session not found for this analysis.",
        )

    msg_stmt = (
        select(AIChatMessageModel)
        .where(AIChatMessageModel.session_id == session_id)
        .order_by(AIChatMessageModel.created_at.asc())
    )
    msg_res = await session.execute(msg_stmt)
    messages = msg_res.scalars().all()

    return {
        "session_id": chat_sess.id,
        "analysis_id": chat_sess.analysis_id,
        "title": chat_sess.title,
        "model_name": chat_sess.model_name,
        "is_active": chat_sess.is_active,
        "messages": [
            {
                "id": m.id,
                "role": m.role,
                "content": m.content,
                "status": m.status,
                "claims": m.claims,
                "citations": m.citations,
                "limitations": m.limitations,
                "created_at": m.created_at.isoformat(),
            }
            for m in messages
        ],
    }


@router.get("/analyses/{analysis_id}/ai/search", response_model=EvidenceSearchResponse)
async def evidence_search_only(
    analysis_id: uuid.UUID,
    q: str = Query(..., min_length=2, max_length=500, description="Search query"),
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Deterministic Evidence Search fallback (functions completely without LLM)."""
    # Verify analysis exists
    run_res = await session.execute(select(AnalysisRun).where(AnalysisRun.id == analysis_id))
    if not run_res.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AnalysisRun not found: {analysis_id}",
        )

    engine = get_retrieval_engine()
    return await engine.search_evidence_only(session, analysis_id, q)


@router.get("/ai/health")
async def ai_health(
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Probe status of local Ollama runtime and knowledge index."""
    provider = get_llm_provider()
    knowledge_svc = get_knowledge_service()
    settings = get_settings()

    provider_health = await provider.health()
    index_status = await knowledge_svc.get_index_status(session)

    models_available = provider_health.get("models", [])
    primary_loaded = any(settings.AI_PRIMARY_MODEL in m for m in models_available)
    fallback_loaded = any(settings.AI_FALLBACK_MODEL in m for m in models_available)
    embedding_loaded = any(settings.AI_EMBEDDING_MODEL in m for m in models_available)

    overall_status = "healthy" if (provider_health.get("status") == "healthy" and primary_loaded) else "degraded"
    if provider_health.get("status") != "healthy":
        overall_status = "offline"

    return {
        "status": overall_status,
        "runtime": "ollama (local)",
        "base_url": provider.base_url,
        "primary_model": settings.AI_PRIMARY_MODEL,
        "primary_model_available": primary_loaded,
        "fallback_model": settings.AI_FALLBACK_MODEL,
        "fallback_model_available": fallback_loaded,
        "embedding_model": settings.AI_EMBEDDING_MODEL,
        "embedding_model_available": embedding_loaded,
        "embedding_dimension": settings.AI_EMBEDDING_DIM,
        "knowledge_index_ready": index_status.get("is_indexed", False),
        "total_documents_indexed": index_status.get("total_documents", 0),
        "total_chunks_indexed": index_status.get("total_chunks", 0),
        "installed_models": models_available,
    }


@router.get("/ai/knowledge/status")
async def knowledge_status(
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Retrieve full details and document registry for the knowledge base."""
    svc = get_knowledge_service()
    return await svc.get_index_status(session)


@router.post("/ai/knowledge/ingest")
async def ingest_standards(
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Trigger ingestion of all approved standards documents."""
    svc = get_knowledge_service()
    return await svc.ingest_all_standards(session)
