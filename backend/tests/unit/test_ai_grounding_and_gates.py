"""Unit tests for Citation Integrity Gate, Claim Grounding Gate, and Answer Provenance.

Tests:
- Rejection of fabricated citations
- Rejection of score contradictions
- Rejection of invented CVE identifiers
- Enforcement of epistemic states (UNKNOWN, PROJECTED)
- Tamper-evident Answer Provenance Ledger hashing
"""

import uuid
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.ai.context.fact_lock import FactLockContext, FactLockItem
from app.ai.grounding.abstention import (
    CANONICAL_ABSTENTION_MESSAGE,
    AbstentionDetector,
)
from app.ai.grounding.citation_gate import CitationIntegrityGate
from app.ai.grounding.claim_gate import ClaimGroundingGate
from app.ai.grounding.provenance import AnswerProvenanceLedger
from app.db.base import Base
from app.db.models.ai import AnswerProvenanceRecordModel, RAGQueryRunModel


def test_citation_integrity_gate_rejects_fabricated_citations():
    """Verify CitationIntegrityGate validates allowed sources and rejects hallucinations."""
    allowed = frozenset([
        "finding:SEC-001",
        "standard:RFC 8247:Section 2.1",
        "score:assessment:1",
    ])

    # 1. Valid citations
    valid_cits = [
        {"source_id": "finding:SEC-001", "source_type": "finding", "title": "Weak Cipher"},
        {"source_id": "standard:RFC 8247:Section 2.1", "source_type": "standard", "title": "RFC 8247"},
    ]
    res1 = CitationIntegrityGate.validate(valid_cits, "Observed in [finding:SEC-001].", allowed)
    assert res1.is_valid is True
    assert res1.validity_rate == 1.0
    assert len(res1.valid_citations) == 2

    # 2. Fabricated citation
    invalid_cits = [
        {"source_id": "standard:RFC 99999:Section 9", "source_type": "standard", "title": "Fake RFC"},
        {"source_id": "finding:SEC-001", "source_type": "finding", "title": "Weak Cipher"},
    ]
    res2 = CitationIntegrityGate.validate(invalid_cits, "Check [standard:RFC 99999:Section 9].", allowed)
    assert res2.is_valid is False
    assert len(res2.invalid_citations) >= 1
    assert "RFC 99999" in str(res2.invalid_citations)


def test_claim_grounding_gate_rejects_score_contradiction():
    """Verify ClaimGroundingGate catches numerical score hallucinations."""
    fact_lock = FactLockContext(
        analysis_id="aid-1",
        capture_name="test.pcap",
        capture_sha256="0"*64,
        items=(
            FactLockItem(
                source_id="score:assessment:1",
                fact_type="SECURITY_SCORE",
                name="security_posture_score",
                value={"overall_score": 62.0},
                epistemic_state="VERIFIED",
                entity="ScoreAssessment",
                provenance="Stage 8",
            ),
        ),
        fact_lock_hash="hash1",
    )

    # Contradictory score statement
    answer_text = "The overall Security Posture Score is 95 points with no critical failures."
    res = ClaimGroundingGate.validate(claims=[], answer_text=answer_text, fact_lock=fact_lock)
    assert res.is_valid is False
    assert len(res.contradicted_claims) == 1
    assert res.contradicted_claims[0]["claim_type"] == "SCORE_CONTRADICTION"
    assert res.contradicted_claims[0]["claimed"] == 95.0
    assert res.contradicted_claims[0]["expected"] == 62.0


def test_claim_grounding_gate_rejects_cve_hallucination():
    """Verify ClaimGroundingGate flags invented CVEs not supported by context."""
    fact_lock = FactLockContext(
        analysis_id="aid-1",
        capture_name="test.pcap",
        capture_sha256="0"*64,
        items=(),
        fact_lock_hash="hash1",
    )

    # Invented CVE from model memory
    answer_text = "This setup is vulnerable to CVE-2024-34567 which allows remote code execution."
    res = ClaimGroundingGate.validate(claims=[], answer_text=answer_text, fact_lock=fact_lock)
    assert res.is_valid is False
    assert len(res.hallucinated_claims) == 1
    assert res.hallucinated_claims[0]["claim_type"] == "CVE_HALLUCINATION"
    assert "CVE-2024-34567" in res.hallucinated_claims[0]["text"]


def test_claim_grounding_gate_enforces_epistemic_states():
    """Verify ClaimGroundingGate prevents elevating UNKNOWN to VERIFIED."""
    fact_lock = FactLockContext(
        analysis_id="aid-1",
        capture_name="test.pcap",
        capture_sha256="0"*64,
        items=(
            FactLockItem(
                source_id="sa:child:1",
                fact_type="PROTOCOL_FACT",
                name="pfs_state",
                value="UNKNOWN",
                epistemic_state="UNKNOWN",
                entity="ChildSA",
                provenance="Stage 4",
            ),
        ),
        fact_lock_hash="hash1",
    )

    # Claim claiming UNKNOWN PFS is VERIFIED disabled
    claims = [
        {
            "claim_id": "c1",
            "text": "PFS is disabled on this tunnel",
            "claim_type": "PROTOCOL_FACT",
            "epistemic_state": "VERIFIED",
            "citation_ids": ["sa:child:1"],
        }
    ]
    res = ClaimGroundingGate.validate(claims=claims, answer_text="PFS is disabled.", fact_lock=fact_lock)
    assert res.is_valid is False
    assert len(res.contradicted_claims) == 1
    assert res.contradicted_claims[0]["claim_type"] == "EPISTEMIC_VIOLATION"


def test_abstention_detector():
    """Verify AbstentionDetector correctly identifies abstentions."""
    assert AbstentionDetector.is_abstention(CANONICAL_ABSTENTION_MESSAGE) is True
    assert AbstentionDetector.is_abstention("The tunnel uses IKEv2 with AES-GCM.") is False
    assert AbstentionDetector.is_abstention("I cannot verify this information from the available capture.") is True


@pytest.mark.asyncio
async def test_answer_provenance_ledger():
    """Verify AnswerProvenanceLedger computes hashes and records audit entry."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    qid = uuid.uuid4()
    aid = uuid.uuid4()

    async with factory() as session:
        # Create prerequisite RAGQueryRun
        q_run = RAGQueryRunModel(
            id=qid,
            analysis_id=aid,
            query_text_hash="qhash1",
            query_intent="EXPLANATION",
            retrieved_source_ids=["finding:SEC-001"],
            model_name="qwen3:4b-instruct-2507-q4_K_M",
            embedding_model="nomic-embed-text",
            prompt_template_version="1.0.0",
            citation_validity_rate=1.0,
            execution_status="COMPLETED",
        )
        session.add(q_run)
        await session.commit()

        # Record provenance
        rec = await AnswerProvenanceLedger.record_provenance(
            session=session,
            query_run_id=qid,
            analysis_id=aid,
            answer_text="Authoritative explanation.",
            fact_lock_hash="fhash1",
            retrieved_source_ids=["finding:SEC-001"],
            prompt_text="User prompt",
            model_name="qwen3:4b-instruct-2507-q4_K_M",
            citation_summary={"total": 1, "valid": 1},
        )

        assert rec.query_run_id == qid
        assert len(rec.answer_hash) == 64
        assert rec.fact_lock_hash == "fhash1"
