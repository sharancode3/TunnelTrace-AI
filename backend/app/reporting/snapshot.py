"""Structured immutable analysis snapshot compiler for Stage 9 reporting."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.models.capture import AnalysisRun, ProtocolObservation
from app.db.models.ml import FlowClassification
from app.db.models.reconstruction import (
    ChildSecurityAssociation,
    ESPFlow,
    IKESession,
)
from app.db.models.security import (
    ComplianceEvaluationModel,
    FingerprintabilityAssessmentModel,
    RiskAssessmentModel,
    ScoreAssessmentModel,
    SecurityFindingModel,
    ThreatInstanceModel,
)


class AnalysisSnapshotBuilder:
    """Extracts, normalizes, and seals immutable forensic evidence snapshots for reporting."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def build_snapshot(self, analysis_id: uuid.UUID) -> dict[str, Any]:
        """Aggregate all analysis results across Stages 3-8 into a deterministic report dictionary."""
        # 1. Fetch AnalysisRun and Capture
        stmt_run = (
            select(AnalysisRun)
            .options(selectinload(AnalysisRun.capture))
            .where(AnalysisRun.id == analysis_id)
        )
        res_run = await self.db.execute(stmt_run)
        run = res_run.scalar_one_or_none()
        if not run:
            raise ValueError(f"Analysis '{analysis_id}' not found")

        capture = run.capture

        # 2. Fetch Protocol Observations
        stmt_obs = (
            select(ProtocolObservation)
            .where(ProtocolObservation.analysis_id == analysis_id)
            .order_by(ProtocolObservation.frame_number)
        )
        res_obs = await self.db.execute(stmt_obs)
        observations = res_obs.scalars().all()

        protocol_facts = {
            "total_observations": len(observations),
            "ike_versions": sorted({o.ike_version for o in observations if o.ike_version}),
            "protocols_detected": sorted({o.protocol for o in observations if o.protocol}),
            "nat_detected": any(o.is_nat_detected for o in observations if o.is_nat_detected is not None),
            "transforms_observed": sorted({o.cipher_suite for o in observations if o.cipher_suite}),
            "dh_groups": sorted({str(o.dh_group) for o in observations if o.dh_group}),
        }

        # 3. Fetch SAs & Flows
        stmt_ike = (
            select(IKESession)
            .options(selectinload(IKESession.ike_sas))
            .where(IKESession.analysis_id == analysis_id)
        )
        res_ike = await self.db.execute(stmt_ike)
        ike_sessions = res_ike.scalars().all()

        stmt_csa = (
            select(ChildSecurityAssociation)
            .where(ChildSecurityAssociation.analysis_id == analysis_id)
        )
        res_csa = await self.db.execute(stmt_csa)
        child_sas = res_csa.scalars().all()

        stmt_flows = select(ESPFlow).where(ESPFlow.analysis_id == analysis_id)
        res_flows = await self.db.execute(stmt_flows)
        flows = res_flows.scalars().all()

        total_bytes = sum(f.byte_count for f in flows)
        total_packets = sum(f.packet_count for f in flows)

        sa_summary = {
            "ike_session_count": len(ike_sessions),
            "child_sa_count": len(child_sas),
            "flow_count": len(flows),
            "total_bytes": total_bytes,
            "total_packets": total_packets,
            "child_sas": [
                {
                    "id": str(c.id),
                    "protocol": c.protocol,
                    "inbound_spi": c.inbound_spi,
                    "outbound_spi": c.outbound_spi,
                    "mode": c.mode,
                    "pfs_status": c.pfs_status,
                    "encryption_algorithm": c.encryption_algorithm or "UNKNOWN",
                    "integrity_algorithm": c.integrity_algorithm or "UNKNOWN",
                    "lifecycle_state": c.lifecycle_state,
                    "evidence_state": c.evidence_state,
                }
                for c in child_sas
            ],
        }

        # 4. Fetch Stage 7 ML Classifications
        stmt_ml = (
            select(FlowClassification)
            .join(ESPFlow, FlowClassification.flow_id == ESPFlow.id)
            .where(ESPFlow.analysis_id == analysis_id)
        )
        res_ml = await self.db.execute(stmt_ml)
        ml_records = res_ml.scalars().all()

        traffic_summary = {
            "classified_flows": len(ml_records),
            "classes_detected": sorted({m.final_class for m in ml_records}),
            "avg_calibrated_confidence": (
                round(sum(m.calibrated_confidence for m in ml_records) / len(ml_records), 4)
                if ml_records
                else None
            ),
            "ood_count": sum(1 for m in ml_records if m.ood_status != "KNOWN_ACCEPTED"),
            "anomaly_count": sum(1 for m in ml_records if m.behavioral_anomaly_status == "ANOMALOUS_BEHAVIOR"),
            "class_distribution": {},
        }
        for m in ml_records:
            traffic_summary["class_distribution"][m.final_class] = (
                traffic_summary["class_distribution"].get(m.final_class, 0) + 1
            )

        # 5. Fetch Stage 8 Security Data
        stmt_evals = (
            select(ComplianceEvaluationModel)
            .where(ComplianceEvaluationModel.analysis_id == analysis_id)
        )
        res_evals = await self.db.execute(stmt_evals)
        evals = res_evals.scalars().all()

        compliance_summary = {
            "total_evaluations": len(evals),
            "pass_count": sum(1 for e in evals if e.compliance_state == "PASS"),
            "fail_count": sum(1 for e in evals if e.compliance_state == "FAIL"),
            "unknown_count": sum(1 for e in evals if e.compliance_state == "UNKNOWN"),
            "not_applicable_count": sum(1 for e in evals if e.compliance_state == "NOT_APPLICABLE"),
            "evaluations": [
                {
                    "rule_id": e.rule_id,
                    "rule_title": e.rule_title,
                    "category": e.category,
                    "severity": e.severity,
                    "standard": e.standard,
                    "compliance_state": e.compliance_state,
                    "evidence_state": e.evidence_state,
                    "observed_value": e.observed_value,
                    "expected_value": e.expected_value,
                    "rationale": e.rationale,
                }
                for e in evals
            ],
        }

        # 6. Fetch Findings
        stmt_find = (
            select(SecurityFindingModel)
            .where(SecurityFindingModel.analysis_id == analysis_id)
            .order_by(SecurityFindingModel.score_deduction.desc())
        )
        res_find = await self.db.execute(stmt_find)
        findings = res_find.scalars().all()

        findings_summary = {
            "total_findings": len(findings),
            "critical_count": sum(1 for f in findings if f.severity == "CRITICAL"),
            "high_count": sum(1 for f in findings if f.severity == "HIGH"),
            "medium_count": sum(1 for f in findings if f.severity == "MEDIUM"),
            "low_count": sum(1 for f in findings if f.severity == "LOW"),
            "findings": [
                {
                    "finding_id": str(f.id),
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category,
                    "score_deduction": f.score_deduction,
                    "affected_entity": f.affected_entity,
                    "technical_description": f.technical_description,
                    "remediation_guidance": f.remediation_guidance,
                    "evidence_references": f.evidence_references or [],
                    "evidence_state": f.evidence_state,
                    "root_cause_key": f.root_cause_key,
                }
                for f in findings
            ],
        }

        # 7. Fetch Score, Risk, Threats, Fingerprintability
        stmt_score = (
            select(ScoreAssessmentModel)
            .where(ScoreAssessmentModel.analysis_id == analysis_id)
        )
        res_score = await self.db.execute(stmt_score)
        score_row = res_score.scalar_one_or_none()

        score_data = {
            "score": score_row.overall_score if score_row else 100.0,
            "evidence_coverage": (score_row.coverage_percentage / 100.0) if score_row else 0.0,
            "methodology_version": score_row.score_policy_version if score_row else "1.0.0",
            "score_policy_hash": score_row.score_policy_hash if score_row else "default",
            "itemized_deductions": score_row.deduction_audit if score_row else {},
        }

        stmt_risk = (
            select(RiskAssessmentModel)
            .where(RiskAssessmentModel.analysis_id == analysis_id)
        )
        res_risk = await self.db.execute(stmt_risk)
        risk_row = res_risk.scalar_one_or_none()

        risk_data = {
            "aggregate_risk_tier": risk_row.aggregate_risk_tier if risk_row else "LOW",
            "risk_score": risk_row.risk_score if risk_row else 0.0,
            "rationale": risk_row.rationale if risk_row else "No severe security violations observed.",
        }

        stmt_threats = (
            select(ThreatInstanceModel)
            .where(ThreatInstanceModel.analysis_id == analysis_id)
        )
        res_threats = await self.db.execute(stmt_threats)
        threat_rows = res_threats.scalars().all()

        threats_data = [
            {
                "threat_id": t.threat_id,
                "title": t.title,
                "category": t.category,
                "likelihood": t.likelihood,
                "impact": t.impact,
                "risk_tier": t.risk_tier,
                "mitre_technique_id": t.mitre_technique_id,
                "nist_control": t.nist_control,
                "evidence_state": t.evidence_state,
            }
            for t in threat_rows
        ]

        stmt_mfi = (
            select(FingerprintabilityAssessmentModel)
            .where(FingerprintabilityAssessmentModel.analysis_id == analysis_id)
        )
        res_mfi = await self.db.execute(stmt_mfi)
        mfi_row = res_mfi.scalar_one_or_none()

        mfi_data = {
            "overall_index": mfi_row.overall_index if mfi_row else 0.0,
            "is_experimental": mfi_row.is_experimental if mfi_row else True,
            "component_metrics": mfi_row.component_metrics if mfi_row else {},
            "disclaimer": (
                mfi_row.disclaimer
                if mfi_row
                else "Behavioral side-channel distinguishability of encrypted traffic metadata. Does not indicate plaintext payload recovery."
            ),
        }

        # Build master snapshot dictionary
        snapshot = {
            "analysis_id": str(analysis_id),
            "capture": {
                "id": str(capture.id) if capture else None,
                "filename": (capture.original_filename or "unknown.pcap") if capture else "unknown.pcap",
                "sha256": (capture.sha256_hash or "unknown") if capture else "unknown",
                "file_size_bytes": capture.file_size_bytes if capture else 0,
                "packet_count": capture.packet_count if capture else 0,
            },
            "analysis": {
                "status": run.status,
                "current_stage": run.current_stage,
                "parser_engine": run.parser_engine,
                "parser_version": run.parser_version,
                "schema_version": run.schema_version,
                "created_at": run.created_at.isoformat() if run.created_at else None,
                "completed_at": run.completed_at.isoformat() if run.completed_at else None,
            },
            "protocol": protocol_facts,
            "security_associations": sa_summary,
            "traffic": traffic_summary,
            "compliance": compliance_summary,
            "findings": findings_summary,
            "score": score_data,
            "risk": risk_data,
            "threats": threats_data,
            "metadata_fingerprintability": mfi_data,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        # Compute deterministic snapshot hash (sorted keys)
        serialized = json.dumps(snapshot, sort_keys=True, default=str)
        snapshot_sha256 = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        snapshot["snapshot_sha256"] = snapshot_sha256

        return snapshot
