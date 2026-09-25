"""Unit tests for Replay and Evidence Chain phase.

Verifies:
1. Secret redaction and canonical configuration hashing.
2. Capture SHA-256 integrity verification (fail-closed on tampered or missing files).
3. Deterministic forensic re-analysis comparator (exact match, volatile field normalization, discrepancy detection).
4. Scenario replay semantic comparator (runtime variance handling, SA/traffic assertions, environment mismatch).
5. ReplayService execution (immutable child creation, parent preserved, comparison persistence).
6. Evidence DAG lineage (REPLAY_RUN, SCENARIO nodes and edges, sealed manifest).
7. REST APIs (POST /analyses/{id}/re-analyze, GET /analyses/{id}/replay-lineage).
8. Lab agent scenario replay preflight and manifest validation.
"""

from __future__ import annotations

import hashlib
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.models.capture import AnalysisRun, Capture
from app.db.models.replay import ReplayComparisonModel
from app.db.session import get_db_session
from app.main import app
from app.replay.comparator import (
    ForensicReplayComparator,
    ReplayStatus,
    ScenarioReplayComparator,
)
from app.replay.models import (
    CaptureIntegrityError,
    ForensicReanalysisRequestDTO,
    ReplayLineageDTO,
)
from app.replay.redaction import (
    compute_canonical_config_digest,
    redact_secrets_dict,
    redact_secrets_text,
)
from app.replay.service import ReplayService
from app.security.evidence.builder import EvidenceGraphBuilder
from app.security.evidence.models import EvidenceNodeType, EvidenceRelationType
from app.security.manifest import AssessmentManifest
from app.security.scoring.models import EvidenceCoverage, ScoreAssessment
from lab.agent.models.manifest import RunManifest


class TestSecretRedactionAndCanonicalHashing:
    """Verifies confidential credentials are never leaked in configs or manifests."""

    def test_redact_secrets_text_psk_and_keys(self) -> None:
        raw_config = """
        secrets {
            ike-s2s {
                secret = "VerySuperSecretPSK12345!"
            }
            private_key = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC"
            password = "AdminPassword987"
        }
        connections {
            ike_version = 2
            proposals = aes256gcm16-sha256-modp3072
        }
        """
        redacted = redact_secrets_text(raw_config)
        assert "VerySuperSecretPSK12345!" not in redacted
        assert "AdminPassword987" not in redacted
        assert "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC" not in redacted
        assert "[REDACTED_SECRET]" in redacted
        # Non-secret directives remain intact
        assert "aes256gcm16-sha256-modp3072" in redacted
        assert "ike_version = 2" in redacted

    def test_redact_secrets_dict_deep(self) -> None:
        raw_dict = {
            "scenario": "s2s-prod",
            "auth": {
                "psk": "raw_secret_key",
                "token": "bearer_abc123",
                "nested": {
                    "private_key_data": "PEM-DATA-SECRET",
                    "safe_param": "aes-gcm",
                },
            },
            "public_cert_fingerprint": "SHA256:abcd1234ef",
        }
        redacted = redact_secrets_dict(raw_dict)
        assert redacted["auth"]["psk"] == "[REDACTED_SECRET]"
        assert redacted["auth"]["token"] == "[REDACTED_SECRET]"
        assert redacted["auth"]["nested"]["private_key_data"] == "[REDACTED_SECRET]"
        assert redacted["auth"]["nested"]["safe_param"] == "aes-gcm"
        assert redacted["public_cert_fingerprint"] == "SHA256:abcd1234ef"

    def test_canonical_config_digest_stability(self) -> None:
        config_a = {"mode": "tunnel", "cipher": "aes256-gcm"}
        config_b = {"cipher": "aes256-gcm", "mode": "tunnel"}
        # Both represent same logical config, should have identical digest after canonicalization
        text_a, digest_a = compute_canonical_config_digest(config_a)
        text_b, digest_b = compute_canonical_config_digest(config_b)
        assert digest_a == digest_b
        assert len(digest_a) == 64  # SHA-256 hex


class TestCaptureIntegrityVerification:
    """Verifies fail-closed integrity gating on capture files before re-analysis."""

    def test_capture_integrity_pass(self) -> None:
        mock_db = MagicMock()
        service = ReplayService(mock_db)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"SAMPLE_PCAP_DATA_1234567890")
            temp_path = f.name

        try:
            expected_hash = hashlib.sha256(b"SAMPLE_PCAP_DATA_1234567890").hexdigest()
            capture = Capture(
                id=uuid.uuid4(),
                storage_path=temp_path,
                sha256_hash=expected_hash,
                original_filename="sample.pcap",
                capture_source="LAB_CAPTURE",
                capture_format="PCAP",
                file_size_bytes=len(b"SAMPLE_PCAP_DATA_1234567890"),
                validation_state="VALID",
            )
            is_valid, computed_hash, recorded_hash = service.verify_capture_integrity(capture)
            assert is_valid is True
            assert computed_hash == expected_hash
            assert recorded_hash == expected_hash
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_capture_integrity_mismatch_detected(self) -> None:
        mock_db = MagicMock()
        service = ReplayService(mock_db)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"TAMPERED_PCAP_DATA")
            temp_path = f.name

        try:
            expected_hash = hashlib.sha256(b"ORIGINAL_LEGITIMATE_PCAP_DATA").hexdigest()
            capture = Capture(
                id=uuid.uuid4(),
                storage_path=temp_path,
                sha256_hash=expected_hash,
                original_filename="tampered.pcap",
                capture_source="LAB_CAPTURE",
                capture_format="PCAP",
                file_size_bytes=100,
                validation_state="VALID",
            )
            is_valid, computed_hash, recorded_hash = service.verify_capture_integrity(capture)
            assert is_valid is False
            assert computed_hash != expected_hash
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_capture_integrity_missing_file_detected(self) -> None:
        mock_db = MagicMock()
        service = ReplayService(mock_db)
        capture = Capture(
            id=uuid.uuid4(),
            storage_path="non_existent_path_xyz123.pcap",
            sha256_hash="abcdef0123456789" * 4,
            original_filename="missing.pcap",
            capture_source="LAB_CAPTURE",
            capture_format="PCAP",
            file_size_bytes=100,
            validation_state="VALID",
        )
        is_valid, computed_hash, recorded_hash = service.verify_capture_integrity(capture)
        assert is_valid is False
        assert computed_hash == "FILE_NOT_FOUND"


class TestForensicReplayComparator:
    """Verifies deterministic comparison between baseline and re-analysis outputs."""

    def test_forensic_exact_match(self) -> None:
        baseline = {
            "observations": [
                {
                    "frame_number": 1,
                    "protocol": "IKEv2",
                    "category": "TRANSFORM",
                    "field_name": "ENCR",
                    "normalized_value": "AES-GCM-256",
                    "evidence_state": "VERIFIED",
                },
                {
                    "frame_number": 2,
                    "protocol": "IKEv2",
                    "category": "TRANSFORM",
                    "field_name": "PRF",
                    "normalized_value": "PRF_HMAC_SHA2_256",
                    "evidence_state": "VERIFIED",
                },
            ],
            "ike_sessions": [
                {"initiator_spi": "0x11223344", "responder_spi": "0x55667788", "version": "2"}
            ],
            "child_sas": [
                {"inbound_spi": "0x01", "outbound_spi": "0x02", "mode": "TUNNEL", "protocol": "ESP"}
            ],
            "flows": [{"spi": "0x01", "reverse_spi": "0x02", "packet_count": 50, "byte_count": 1000}],
            "evaluations": [
                {"rule_id": "POL-001", "subject_id": "sa-1", "compliance_state": "PASS"}
            ],
            "findings": [{"record_hash": "hash-finding-1"}],
            "score": {"overall_score": 85.0, "raw_score": 85.0},
        }
        reanalysis = {
            # Same observations and entities
            "observations": [
                {
                    "frame_number": 1,
                    "protocol": "IKEv2",
                    "category": "TRANSFORM",
                    "field_name": "ENCR",
                    "normalized_value": "AES-GCM-256",
                    "evidence_state": "VERIFIED",
                },
                {
                    "frame_number": 2,
                    "protocol": "IKEv2",
                    "category": "TRANSFORM",
                    "field_name": "PRF",
                    "normalized_value": "PRF_HMAC_SHA2_256",
                    "evidence_state": "VERIFIED",
                },
            ],
            "ike_sessions": [
                {"initiator_spi": "0x11223344", "responder_spi": "0x55667788", "version": "2"}
            ],
            "child_sas": [
                {"inbound_spi": "0x01", "outbound_spi": "0x02", "mode": "TUNNEL", "protocol": "ESP"}
            ],
            "flows": [{"spi": "0x01", "reverse_spi": "0x02", "packet_count": 50, "byte_count": 1000}],
            "evaluations": [
                {"rule_id": "POL-001", "subject_id": "sa-1", "compliance_state": "PASS"}
            ],
            "findings": [{"record_hash": "hash-finding-1"}],
            "score": {"overall_score": 85.0, "raw_score": 85.0},
        }

        result = ForensicReplayComparator.compare_runs(baseline, reanalysis)
        assert result["comparison_status"] == ReplayStatus.EXACT_MATCH
        assert result["metrics"]["matched_facts"] == 2
        assert result["differences"] is None

    def test_forensic_discrepancy_detected(self) -> None:
        baseline = {
            "observations": [
                {
                    "frame_number": 1,
                    "protocol": "IKEv2",
                    "category": "TRANSFORM",
                    "field_name": "ENCR",
                    "normalized_value": "AES-GCM-256",
                    "evidence_state": "VERIFIED",
                }
            ],
            "ike_sessions": [],
            "child_sas": [],
            "flows": [],
            "evaluations": [{"rule_id": "POL-001", "subject_id": "sa-1", "compliance_state": "PASS"}],
            "findings": [],
            "score": {"overall_score": 100.0, "raw_score": 100.0},
        }
        reanalysis = {
            "observations": [
                {
                    "frame_number": 1,
                    "protocol": "IKEv2",
                    "category": "TRANSFORM",
                    "field_name": "ENCR",
                    "normalized_value": "3DES-CBC",
                    "evidence_state": "VERIFIED",
                }
            ],
            "ike_sessions": [],
            "child_sas": [],
            "flows": [],
            "evaluations": [{"rule_id": "POL-001", "subject_id": "sa-1", "compliance_state": "FAIL"}],
            "findings": [{"record_hash": "hash-fnd-3des"}],
            "score": {"overall_score": 60.0, "raw_score": 60.0},
        }

        result = ForensicReplayComparator.compare_runs(baseline, reanalysis)
        assert result["comparison_status"] == ReplayStatus.DISCREPANCY_DETECTED
        assert result["differences"] is not None
        assert "protocol_facts" in result["differences"]
        assert "compliance_evaluations" in result["differences"]
        assert "security_findings" in result["differences"]
        assert "score_assessment" in result["differences"]


class TestScenarioReplayComparator:
    """Verifies semantic assertion comparison for live lab scenario replays."""

    def test_scenario_semantic_match_with_runtime_variance(self) -> None:
        baseline_manifest = {
            "scenario_id": "scenario_ikev2_aes_gcm",
            "scenario_version": "1.0.0",
            "scenario_sha256": "abcdef1234567890" * 4,
            "canonical_config_digest": "1122334455667788" * 4,
            "sa_established": True,
            "traffic_probe_passed": True,
            "validation_status": "VALID",
            # Volatile fields that differ across runs
            "start_time": "2026-09-25T10:00:00Z",
            "ike_initiator_spi": "0x11111111",
            "packet_count": 42,
        }
        replay_manifest = {
            "scenario_id": "scenario_ikev2_aes_gcm",
            "scenario_version": "1.0.0",
            "scenario_sha256": "abcdef1234567890" * 4,
            "canonical_config_digest": "1122334455667788" * 4,
            "sa_established": True,
            "traffic_probe_passed": True,
            "validation_status": "VALID",
            # Fresh runtime nonces, timestamps, SPIs
            "start_time": "2026-09-25T11:30:00Z",
            "ike_initiator_spi": "0x99999999",
            "packet_count": 44,
        }

        result = ScenarioReplayComparator.compare_manifests(baseline_manifest, replay_manifest)
        assert result["comparison_status"] == ReplayStatus.SEMANTIC_MATCH
        assert result["differences"] is None

    def test_scenario_semantic_discrepancy(self) -> None:
        baseline_manifest = {
            "scenario_id": "scenario_ikev2_aes_gcm",
            "scenario_version": "1.0.0",
            "canonical_config_digest": "abcdef1234567890" * 4,
            "sa_established": True,
            "traffic_probe_passed": True,
            "validation_status": "VALID",
        }
        replay_manifest = {
            "scenario_id": "scenario_ikev2_aes_gcm",
            "scenario_version": "1.0.0",
            "canonical_config_digest": "abcdef1234567890" * 4,
            "sa_established": False,  # Discrepancy! SA failed to establish
            "traffic_probe_passed": False,
            "validation_status": "VALID",
        }

        result = ScenarioReplayComparator.compare_manifests(baseline_manifest, replay_manifest)
        assert result["comparison_status"] == ReplayStatus.DISCREPANCY_DETECTED
        assert result["differences"] is not None

    def test_scenario_environment_mismatch(self) -> None:
        baseline_manifest = {
            "scenario_id": "scenario_ikev2_aes_gcm",
            "scenario_version": "1.0.0",
            "canonical_config_digest": "abcdef1234567890" * 4,
            "sa_established": True,
            "traffic_probe_passed": True,
            "validation_status": "VALID",
        }
        replay_manifest = {
            "scenario_id": "scenario_ikev2_aes_gcm",
            "scenario_version": "1.0.0",
            "canonical_config_digest": "abcdef1234567890" * 4,
            "sa_established": False,
            "traffic_probe_passed": False,
            "validation_status": "BLOCKED",
            "status_summary": "Preflight check failed: iproute2 not installed",
        }

        result = ScenarioReplayComparator.compare_manifests(baseline_manifest, replay_manifest)
        assert result["comparison_status"] == ReplayStatus.ENVIRONMENT_MISMATCH


class TestEvidenceDAGReplayNodesAndManifest:
    """Verifies that evidence graph builders and assessment manifests bind replay lineage."""

    def test_evidence_builder_with_replay_and_scenario_nodes(self) -> None:
        analysis_id = "analysis-child-uuid"
        parent_id = "analysis-parent-uuid"
        scenario_id = "scenario-s2s-nist"
        scenario_version = "1.0.0"

        builder = EvidenceGraphBuilder()
        graph = builder.build_graph(
            analysis_id=analysis_id,
            capture_sha256="1234567890abcdef" * 4,
            security_facts=[],
            eval_records=[],
            findings=[],
            evidence_gaps=[],
            parent_analysis_id=parent_id,
            scenario_metadata={"scenario_id": scenario_id, "scenario_version": scenario_version},
        )

        node_types = {n.node_type for n in graph.nodes}
        assert EvidenceNodeType.REPLAY_RUN in node_types
        assert EvidenceNodeType.SCENARIO in node_types

        relations = {e.relation for e in graph.edges}
        assert EvidenceRelationType.REPLAYED_FROM in relations
        assert EvidenceRelationType.GENERATED_BY in relations

        replay_node = next(n for n in graph.nodes if n.node_type == EvidenceNodeType.REPLAY_RUN)
        assert replay_node.properties["parent_analysis_id"] == parent_id

        scenario_node = next(n for n in graph.nodes if n.node_type == EvidenceNodeType.SCENARIO)
        assert scenario_node.properties["scenario_id"] == scenario_id
        assert scenario_node.properties["scenario_version"] == scenario_version

    def test_assessment_manifest_seals_replay_metadata(self) -> None:
        manifest_a = AssessmentManifest.create(
            analysis_id="child-1",
            capture_sha256="abcdef" * 10,
            policy_bundle_id="nist",
            policy_bundle_version="1.0.0",
            policy_bundle_hash="p_hash",
            score_policy_hash="s_hash",
            risk_policy_hash="r_hash",
            threat_catalog_hash="t_hash",
            ml_bundle_hash=None,
            finding_hashes=[],
            score_value=100.0,
            coverage_percentage=100.0,
            fingerprintability_hash="f_hash",
            parent_analysis_id="parent-1",
            replay_mode="FORENSIC_REANALYSIS",
        )

        manifest_b = AssessmentManifest.create(
            analysis_id="child-1",
            capture_sha256="abcdef" * 10,
            policy_bundle_id="nist",
            policy_bundle_version="1.0.0",
            policy_bundle_hash="p_hash",
            score_policy_hash="s_hash",
            risk_policy_hash="r_hash",
            threat_catalog_hash="t_hash",
            ml_bundle_hash=None,
            finding_hashes=[],
            score_value=100.0,
            coverage_percentage=100.0,
            fingerprintability_hash="f_hash",
            parent_analysis_id=None,  # Not a replay
            replay_mode=None,
        )

        assert manifest_a.parent_analysis_id == "parent-1"
        assert manifest_a.replay_mode == "FORENSIC_REANALYSIS"
        assert manifest_a.manifest_sha256 != manifest_b.manifest_sha256


class TestReplayServiceExecutionAndLineage:
    """Verifies ReplayService executes re-analysis and maintains immutable lineage."""

    @pytest.mark.asyncio
    async def test_execute_forensic_reanalysis_flow(self) -> None:
        parent_id = uuid.uuid4()
        cap_id = uuid.uuid4()

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"PCAP_REANALYSIS_TEST_DATA")
            temp_path = f.name

        try:
            expected_hash = hashlib.sha256(b"PCAP_REANALYSIS_TEST_DATA").hexdigest()
            mock_capture = Capture(
                id=cap_id,
                storage_path=temp_path,
                sha256_hash=expected_hash,
                original_filename="valid.pcap",
                capture_source="LAB_CAPTURE",
                capture_format="PCAP",
                file_size_bytes=len(b"PCAP_REANALYSIS_TEST_DATA"),
                validation_state="VALID",
            )
            mock_parent_run = AnalysisRun(
                id=parent_id,
                capture_id=cap_id,
                status="COMPLETED",
                current_stage="COMPLETED",
                parser_engine="tshark",
                parser_version="4.2.0",
                schema_version="1.0.0",
                created_at=datetime.now(timezone.utc),
            )
            mock_parent_run.capture = mock_capture

            mock_session = AsyncMock()

            # Mock finding parent run
            mock_res_parent = MagicMock()
            mock_res_parent.scalar_one_or_none.return_value = mock_parent_run

            # Mock finding baseline entities
            mock_res_obs = MagicMock()
            mock_res_obs.scalars().all.return_value = []
            mock_res_ikes = MagicMock()
            mock_res_ikes.scalars().all.return_value = []
            mock_res_csas = MagicMock()
            mock_res_csas.scalars().all.return_value = []
            mock_res_flows = MagicMock()
            mock_res_flows.scalars().all.return_value = []
            mock_res_evals = MagicMock()
            mock_res_evals.scalars().all.return_value = []
            mock_res_finds = MagicMock()
            mock_res_finds.scalars().all.return_value = []
            mock_res_score = MagicMock()
            mock_res_score.scalar_one_or_none.return_value = None

            mock_session.execute.side_effect = [
                mock_res_parent,
                # For parent extraction
                mock_res_obs,
                mock_res_ikes,
                mock_res_csas,
                mock_res_flows,
                mock_res_evals,
                mock_res_finds,
                mock_res_score,
                # For child extraction
                mock_res_obs,
                mock_res_ikes,
                mock_res_csas,
                mock_res_flows,
                mock_res_evals,
                mock_res_finds,
                mock_res_score,
            ]

            service = ReplayService(mock_session)

            req = ForensicReanalysisRequestDTO(
                pinned_parser_version="4.2.0",
                pinned_policy_bundle_version="1.0.0",
            )

            with patch("app.replay.service.execute_full_analysis_pipeline", new_callable=AsyncMock):
                child, comparison = await service.execute_forensic_reanalysis(parent_id, req)

            assert child.parent_analysis_id == parent_id
            assert child.replay_mode == "FORENSIC_REANALYSIS"
            assert comparison.comparison_status == ReplayStatus.EXACT_MATCH
            assert comparison.artifact_integrity == "VERIFIED"
            assert mock_session.add.call_count >= 2
            assert mock_session.commit.called
        finally:
            Path(temp_path).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_execute_forensic_reanalysis_tampered_fails_closed(self) -> None:
        parent_id = uuid.uuid4()
        cap_id = uuid.uuid4()

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"TAMPERED_BYTES")
            temp_path = f.name

        try:
            expected_hash = hashlib.sha256(b"ORIGINAL_BYTES").hexdigest()
            mock_capture = Capture(
                id=cap_id,
                storage_path=temp_path,
                sha256_hash=expected_hash,
                original_filename="tampered.pcap",
                capture_source="LAB_CAPTURE",
                capture_format="PCAP",
                file_size_bytes=100,
                validation_state="VALID",
            )
            mock_parent_run = AnalysisRun(
                id=parent_id,
                capture_id=cap_id,
                status="COMPLETED",
                current_stage="COMPLETED",
                created_at=datetime.now(timezone.utc),
            )
            mock_parent_run.capture = mock_capture

            mock_session = AsyncMock()
            mock_res_parent = MagicMock()
            mock_res_parent.scalar_one_or_none.return_value = mock_parent_run
            mock_session.execute.return_value = mock_res_parent

            service = ReplayService(mock_session)

            with pytest.raises(CaptureIntegrityError) as exc_info:
                await service.execute_forensic_reanalysis(parent_id)

            assert "SHA-256 integrity verification" in str(exc_info.value)
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestReplayAPIEndpoints:
    """Verifies FastAPI REST endpoints for replay triggering and lineage inspection."""

    @pytest.mark.asyncio
    async def test_reanalyze_api_endpoint(self) -> None:
        analysis_id = uuid.uuid4()
        child_id = uuid.uuid4()
        comp_id = uuid.uuid4()

        mock_db = AsyncMock()

        mock_child = AnalysisRun(
            id=child_id,
            capture_id=uuid.uuid4(),
            parent_analysis_id=analysis_id,
            replay_mode="FORENSIC_REANALYSIS",
            status="COMPLETED",
            current_stage="COMPLETED",
            parser_engine="tshark",
            parser_version="4.2.0",
            schema_version="1.0.0",
            created_at=datetime.now(timezone.utc),
        )
        mock_comparison = ReplayComparisonModel(
            id=comp_id,
            replay_mode="FORENSIC_REANALYSIS",
            parent_run_id=str(analysis_id),
            child_run_id=str(child_id),
            comparison_status="EXACT_MATCH",
            artifact_integrity="VERIFIED",
            differences=None,
            summary="Deterministic match verified",
            metrics={"matched_facts": 5},
            created_at=datetime.now(timezone.utc),
        )

        with patch.object(ReplayService, "execute_forensic_reanalysis", return_value=(mock_child, mock_comparison)):
            app.dependency_overrides[get_db_session] = lambda: mock_db
            try:
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://test"
                ) as ac:
                    payload = {"pinned_parser_version": "4.2.0"}
                    res = await ac.post(f"/api/v1/analyses/{analysis_id}/re-analyze", json=payload)
                    assert res.status_code == 200
                    data = res.json()
                    assert data["parent_analysis_id"] == str(analysis_id)
                    assert data["child_analysis_id"] == str(child_id)
                    assert data["comparison_status"] == "EXACT_MATCH"
                    assert data["artifact_integrity"] == "VERIFIED"
            finally:
                app.dependency_overrides.pop(get_db_session, None)

    @pytest.mark.asyncio
    async def test_reanalyze_api_fails_closed_on_integrity_error(self) -> None:
        analysis_id = uuid.uuid4()
        mock_db = AsyncMock()

        with patch.object(
            ReplayService,
            "execute_forensic_reanalysis",
            side_effect=CaptureIntegrityError("Capture artifact failed SHA-256 integrity check"),
        ):
            app.dependency_overrides[get_db_session] = lambda: mock_db
            try:
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://test"
                ) as ac:
                    res = await ac.post(f"/api/v1/analyses/{analysis_id}/re-analyze", json={})
                    assert res.status_code == 422
                    data = res.json()
                    assert "Capture artifact failed SHA-256" in data["detail"]
            finally:
                app.dependency_overrides.pop(get_db_session, None)

    @pytest.mark.asyncio
    async def test_get_replay_lineage_api_endpoint(self) -> None:
        analysis_id = uuid.uuid4()
        cap_id = uuid.uuid4()
        mock_db = AsyncMock()

        lineage_dto = ReplayLineageDTO(
            analysis_id=analysis_id,
            parent_analysis_id=None,
            replay_mode=None,
            capture_id=cap_id,
            capture_filename="test.pcap",
            capture_sha256="abcdef1234567890" * 4,
            capture_integrity_verified=True,
            child_runs=[],
            version_pins={"parser_engine": "tshark", "parser_version": "4.2.0"},
            latest_comparison=None,
        )

        with patch.object(ReplayService, "get_replay_lineage", return_value=lineage_dto):
            app.dependency_overrides[get_db_session] = lambda: mock_db
            try:
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://test"
                ) as ac:
                    res = await ac.get(f"/api/v1/analyses/{analysis_id}/replay-lineage")
                    assert res.status_code == 200
                    data = res.json()
                    assert data["analysis_id"] == str(analysis_id)
                    assert data["capture_sha256"] == "abcdef1234567890" * 4
                    assert data["capture_integrity_verified"] is True
            finally:
                app.dependency_overrides.pop(get_db_session, None)


class TestLabAgentScenarioReplay:
    """Verifies lab agent preflight environment check and replay manifest handling."""

    def test_lab_experiment_manifest_sha256_sealing(self) -> None:
        manifest = RunManifest(
            run_id="run-test-1",
            scenario_id="s2s-aes-gcm",
            scenario_version="1.0.0",
            topology_type="SITE_TO_SITE",
            started_at_utc=datetime.now(timezone.utc).isoformat(),
            scenario_sha256="1234567890abcdef" * 4,
            parent_run_id=None,
            replay_mode=None,
            canonical_config_digest="abcdef1234567890" * 4,
            semantic_assertions={
                "expected_sa_state": "ESTABLISHED",
                "expected_traffic_pass": True,
                "expected_validation_status": "VALID",
            },
        )
        manifest_json = manifest.model_dump_json(exclude={"manifest_sha256"}, indent=2)
        manifest.manifest_sha256 = hashlib.sha256(manifest_json.encode("utf-8")).hexdigest()
        assert len(manifest.manifest_sha256) == 64

        # Modifying a field must alter the sealed manifest hash
        manifest_tampered = manifest.model_copy()
        manifest_tampered.parent_run_id = "run-parent-xyz"
        tampered_json = manifest_tampered.model_dump_json(exclude={"manifest_sha256"}, indent=2)
        manifest_tampered.manifest_sha256 = hashlib.sha256(tampered_json.encode("utf-8")).hexdigest()
        assert manifest.manifest_sha256 != manifest_tampered.manifest_sha256

    def test_lab_experiment_replay_scenario_preflight_blocks_without_prerequisites(self) -> None:
        from lab.agent.experiment import ExperimentRunner
        from lab.scenarios.schema import ScenarioDefinition, TopologyType

        runner = ExperimentRunner(storage_base_dir=tempfile.gettempdir())
        with patch.object(
            runner.doctor, "check_environment", return_value={"ready": False, "checks": {"strongswan": False}}
        ):
            scenario = ScenarioDefinition(
                scenario_id="scenario_test_ikev2",
                description="Test",
                topology=TopologyType.TUNNEL_SITE_TO_SITE,
            )
            parent_manifest = RunManifest(
                run_id="run-parent-1",
                scenario_id="scenario_test_ikev2",
                scenario_version="1.0",
                topology_type="TUNNEL_SITE_TO_SITE",
                started_at_utc=datetime.now(timezone.utc).isoformat(),
                scenario_sha256="1234567890abcdef" * 4,
                sa_established=True,
                traffic_probe_passed=True,
                validation_status="VALIDATED",
            )

            child_manifest, cmp_res = runner.replay_scenario(scenario, parent_manifest)
            assert child_manifest.parent_run_id == "run-parent-1"
            assert child_manifest.replay_mode == "SCENARIO_REPLAY"
            assert child_manifest.validation_status == "BLOCKED"
            assert cmp_res["comparison_status"] == ReplayStatus.ENVIRONMENT_MISMATCH

