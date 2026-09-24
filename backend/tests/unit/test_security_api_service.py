"""Integration tests for SecurityAssessmentService and REST API endpoints."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.models.reconstruction import (
    ChildSecurityAssociation,
    ESPFlow,
    IKESecurityAssociation,
    IKESession,
)
from app.main import app
from app.reconstruction.models import Mode, PFSStatus
from app.security.service import SecurityAssessmentService


class TestSecurityAssessmentServiceAndEndpoints:
    """Verifies end-to-end security assessment orchestration and REST API responses."""

    @pytest.fixture
    def rules_dir(self):
        return Path(__file__).resolve().parent.parent.parent.parent / "policies" / "rules"

    def test_service_run_assessment_direct(self, rules_dir) -> None:
        service = SecurityAssessmentService(rules_dir=rules_dir)
        analysis_id = str(uuid.uuid4())
        capture_sha = "a" * 64

        # Create mock reconstructed session
        session = IKESession(
            id=uuid.uuid4(),
            analysis_id=uuid.UUID(analysis_id),
            initiator_spi="1122334455667788",
            responder_spi="8877665544332211",
            ike_version="IKEv2",
        )
        ike_sa = IKESecurityAssociation(
            id=uuid.uuid4(),
            session_id=session.id,
            encryption_algorithm="AES-256-GCM-16",
            key_length_bits=256,
            prf_algorithm="PRF-HMAC-SHA2-256",
            integrity_algorithm=None,  # Implicit in AEAD
            dh_group="MODP_2048",
        )
        session.parent_sa = ike_sa

        child_sa = ChildSecurityAssociation(
            id=uuid.uuid4(),
            analysis_id=uuid.UUID(analysis_id),
            ike_sa_id=ike_sa.id,
            protocol="ESP",
            inbound_spi="0x12345678",
            outbound_spi="0x87654321",
            mode=Mode.TUNNEL,
            encryption_algorithm="AES-256-GCM-16",
            integrity_algorithm=None,
            pfs_status=PFSStatus.ENABLED,
            pfs_dh_group="MODP_2048",
        )

        flow = ESPFlow(
            id=uuid.uuid4(),
            analysis_id=uuid.UUID(analysis_id),
            child_sa_id=child_sa.id,
            spi="0x12345678",
            packet_count=50,
            byte_count=60000,
            forward_packets=25,
            reverse_packets=25,
            duration_seconds=2.5,
        )

        result = service.run_assessment(
            analysis_id=analysis_id,
            capture_sha256=capture_sha,
            sessions=[session],
            child_sas=[child_sa],
            flows=[flow],
            profile_id="profile_nist_sp800_77",
        )

        assert result.analysis_id == analysis_id
        assert result.manifest.manifest_sha256
        assert result.score_assessment.overall_score == 100.0  # Fully compliant modern stack
        assert result.score_assessment.evidence_coverage.coverage_percentage >= 75.0
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_rest_api_policy_profiles(self) -> None:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as ac:
            res = await ac.get("/api/v1/security/policy-profiles")
            assert res.status_code == 200
            data = res.json()
            assert len(data) >= 1
            nist_prof = next(p for p in data if p["profile_id"] == "profile_nist_sp800_77")
            assert nist_prof["name"] == "NIST SP 800-77 Rev. 1 Guidelines"
            assert nist_prof["rule_count"] >= 7
