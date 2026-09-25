"""Stage 8 Forensic Assessment Manifest.

Computes a cryptographic SHA-256 checksum across all versioned policies,
rule catalogs, findings, risk outputs, and scoring assessments for tamper-evidence.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class AssessmentManifest:
    """Tamper-evident cryptographic manifest of an entire security assessment."""

    analysis_id: str
    capture_sha256: str
    engine_version: str
    policy_bundle_id: str
    policy_bundle_version: str
    policy_bundle_hash: str
    score_policy_hash: str
    risk_policy_hash: str
    threat_catalog_hash: str
    ml_bundle_hash: str | None
    finding_count: int
    finding_hashes: list[str]
    score_value: float
    coverage_percentage: float
    fingerprintability_hash: str
    created_at: str
    parent_analysis_id: str | None = None
    replay_mode: str | None = None
    manifest_sha256: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def create(
        cls,
        analysis_id: str,
        capture_sha256: str,
        policy_bundle_id: str,
        policy_bundle_version: str,
        policy_bundle_hash: str,
        score_policy_hash: str,
        risk_policy_hash: str,
        threat_catalog_hash: str,
        ml_bundle_hash: str | None,
        finding_hashes: list[str],
        score_value: float,
        coverage_percentage: float,
        fingerprintability_hash: str,
        engine_version: str = "Stage8-v1.0.0",
        parent_analysis_id: str | None = None,
        replay_mode: str | None = None,
    ) -> AssessmentManifest:
        """Create and cryptographically seal an assessment manifest."""
        now_iso = datetime.now(timezone.utc).isoformat()
        sorted_finding_hashes = sorted(finding_hashes)

        canonical_payload = {
            "analysis_id": analysis_id,
            "capture_sha256": capture_sha256,
            "engine_version": engine_version,
            "policy_bundle_id": policy_bundle_id,
            "policy_bundle_version": policy_bundle_version,
            "policy_bundle_hash": policy_bundle_hash,
            "score_policy_hash": score_policy_hash,
            "risk_policy_hash": risk_policy_hash,
            "threat_catalog_hash": threat_catalog_hash,
            "ml_bundle_hash": ml_bundle_hash,
            "finding_count": len(sorted_finding_hashes),
            "finding_hashes": sorted_finding_hashes,
            "score_value": round(score_value, 2),
            "coverage_percentage": round(coverage_percentage, 2),
            "fingerprintability_hash": fingerprintability_hash,
            "created_at": now_iso,
        }
        if parent_analysis_id:
            canonical_payload["parent_analysis_id"] = parent_analysis_id
        if replay_mode:
            canonical_payload["replay_mode"] = replay_mode

        serialized = json.dumps(canonical_payload, sort_keys=True)
        m_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

        return cls(
            analysis_id=analysis_id,
            capture_sha256=capture_sha256,
            engine_version=engine_version,
            policy_bundle_id=policy_bundle_id,
            policy_bundle_version=policy_bundle_version,
            policy_bundle_hash=policy_bundle_hash,
            score_policy_hash=score_policy_hash,
            risk_policy_hash=risk_policy_hash,
            threat_catalog_hash=threat_catalog_hash,
            ml_bundle_hash=ml_bundle_hash,
            finding_count=len(sorted_finding_hashes),
            finding_hashes=sorted_finding_hashes,
            score_value=round(score_value, 2),
            coverage_percentage=round(coverage_percentage, 2),
            fingerprintability_hash=fingerprintability_hash,
            created_at=now_iso,
            parent_analysis_id=parent_analysis_id,
            replay_mode=replay_mode,
            manifest_sha256=m_hash,
        )
