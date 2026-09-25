"""Forensic Evidence Graph Builder.

Constructs an unbroken, fully linked directed acyclic provenance graph
connecting PCAP packets to high-level compliance violations, threats, and score deductions.
"""

from __future__ import annotations

import logging
from typing import Any

from app.security.evidence.models import (
    EvidenceEdge,
    EvidenceGraph,
    EvidenceNode,
    EvidenceNodeType,
    EvidenceRelationType,
)
from app.security.facts.models import SecurityFact
from app.security.findings.models import EvidenceGap, SecurityFinding
from app.security.fingerprintability.models import MetadataFingerprintabilityAssessment
from app.security.policy.evaluator import EvaluationRecord
from app.security.risk.models import RiskAssessment
from app.security.scoring.models import ScoreAssessment
from app.security.threats.models import ThreatInstance

logger = logging.getLogger(__name__)


class EvidenceGraphBuilder:
    """Builder for relational forensic provenance graph."""

    def build_graph(
        self,
        analysis_id: str,
        capture_sha256: str,
        security_facts: list[SecurityFact],
        eval_records: list[EvaluationRecord],
        findings: list[SecurityFinding],
        evidence_gaps: list[EvidenceGap],
        threat_instances: list[ThreatInstance] | None = None,
        risk_assessment: RiskAssessment | None = None,
        score_assessment: ScoreAssessment | None = None,
        fingerprintability: MetadataFingerprintabilityAssessment | None = None,
        parent_analysis_id: str | None = None,
        scenario_metadata: dict[str, Any] | None = None,
    ) -> EvidenceGraph:
        """Construct deterministic provenance graph."""
        nodes: dict[str, EvidenceNode] = {}
        edges: list[EvidenceEdge] = []

        def add_node(node: EvidenceNode) -> None:
            if node.node_id not in nodes:
                nodes[node.node_id] = node

        def add_edge(source_id: str, target_id: str, relation: EvidenceRelationType, props: dict[str, Any] | None = None) -> None:
            edges.append(
                EvidenceEdge(
                    source_node_id=source_id,
                    target_node_id=target_id,
                    relation=relation,
                    properties=props or {},
                )
            )

        # 0. Testbed Scenario Node (if testbed-generated)
        cap_id = f"capture:{capture_sha256[:16]}"
        if scenario_metadata:
            sc_id = scenario_metadata.get("scenario_id", "lab-scenario")
            sc_node_id = f"scenario:{sc_id}"
            add_node(
                EvidenceNode(
                    node_id=sc_node_id,
                    node_type=EvidenceNodeType.SCENARIO,
                    label=f"Scenario: {sc_id}",
                    properties=scenario_metadata,
                )
            )
            add_edge(sc_node_id, cap_id, EvidenceRelationType.GENERATED_BY)

        # 0b. Parent Replay Lineage Node (if re-analyzed from prior run)
        if parent_analysis_id:
            parent_node_id = f"replay:{parent_analysis_id[:16]}"
            add_node(
                EvidenceNode(
                    node_id=parent_node_id,
                    node_type=EvidenceNodeType.REPLAY_RUN,
                    label=f"Parent Run: {parent_analysis_id[:8]}...",
                    properties={"parent_analysis_id": parent_analysis_id},
                )
            )
            add_edge(cap_id, parent_node_id, EvidenceRelationType.REPLAYED_FROM)

        # 1. Capture Root Node (SHA-256 anchor)
        add_node(
            EvidenceNode(
                node_id=cap_id,
                node_type=EvidenceNodeType.CAPTURE,
                label=f"Capture ({capture_sha256[:8]}...)",
                properties={"capture_sha256": capture_sha256, "analysis_id": analysis_id},
            )
        )

        # 2. Frame Nodes and Fact Nodes
        for fact in security_facts:
            fact_node_id = f"fact:{fact.fact_id}"
            add_node(
                EvidenceNode(
                    node_id=fact_node_id,
                    node_type=EvidenceNodeType.SECURITY_FACT,
                    label=f"{fact.canonical_key}: {fact.value}",
                    properties={
                        "fact_id": fact.fact_id,
                        "canonical_key": fact.canonical_key,
                        "value": str(fact.value),
                        "evidence_state": fact.evidence_state.value,
                        "derivation_type": fact.derivation_type.value,
                        "subject_type": fact.subject_type.value,
                        "subject_id": fact.subject_id,
                    },
                )
            )

            # Link frame numbers to fact and frames to capture
            for frame_num in fact.source_frame_numbers:
                frame_node_id = f"frame:{frame_num}"
                add_node(
                    EvidenceNode(
                        node_id=frame_node_id,
                        node_type=EvidenceNodeType.FRAME,
                        label=f"Frame #{frame_num}",
                        properties={"frame_number": frame_num},
                    )
                )
                add_edge(cap_id, frame_node_id, EvidenceRelationType.CONTAINS)
                add_edge(frame_node_id, fact_node_id, EvidenceRelationType.DERIVED_FROM)

        # 3. Policy Rule Nodes and Evaluations
        for rec in eval_records:
            rule_node_id = f"rule:{rec.rule_id}:{rec.rule_version}"
            add_node(
                EvidenceNode(
                    node_id=rule_node_id,
                    node_type=EvidenceNodeType.POLICY_RULE,
                    label=f"Rule: {rec.rule_id}",
                    properties={
                        "rule_id": rec.rule_id,
                        "rule_version": rec.rule_version,
                        "profile_id": rec.profile_id,
                    },
                )
            )

            eval_node_id = f"eval:{rec.rule_id}:{rec.subject_id}"
            add_node(
                EvidenceNode(
                    node_id=eval_node_id,
                    node_type=EvidenceNodeType.COMPLIANCE_EVALUATION,
                    label=f"Eval: {rec.rule_id} ({rec.compliance_state.value})",
                    properties={
                        "compliance_state": rec.compliance_state.value,
                        "subject_id": rec.subject_id,
                        "rationale": rec.rationale,
                    },
                )
            )
            add_edge(rule_node_id, eval_node_id, EvidenceRelationType.EVALUATED_AGAINST)

        # 4. Evidence Gaps (from UNKNOWN results)
        for gap in evidence_gaps:
            subj_id = getattr(gap, "subject_id", "") or "global"
            gap_node_id = f"gap:{gap.rule_id}:{subj_id}"
            missing = getattr(gap, "missing_fields", getattr(gap, "required_facts", []))
            add_node(
                EvidenceNode(
                    node_id=gap_node_id,
                    node_type=EvidenceNodeType.EVIDENCE_GAP,
                    label=f"Evidence Gap: {gap.rule_id}",
                    properties={
                        "rule_id": gap.rule_id,
                        "subject_id": subj_id,
                        "missing_fields": list(missing),
                        "reason": gap.reason,
                        "recommended_action": gap.recommended_action,
                    },
                )
            )
            rule_node_id = f"rule:{gap.rule_id}:{gap.rule_version}"
            if rule_node_id in nodes:
                add_edge(rule_node_id, gap_node_id, EvidenceRelationType.GAP_IDENTIFIED)

        # 5. Security Findings (from FAIL evaluations)
        for finding in findings:
            finding_node_id = f"finding:{finding.finding_id}"
            add_node(
                EvidenceNode(
                    node_id=finding_node_id,
                    node_type=EvidenceNodeType.SECURITY_FINDING,
                    label=f"Finding: {finding.title}",
                    properties={
                        "finding_id": finding.finding_id,
                        "rule_id": finding.rule_id,
                        "rule_version": finding.rule_version,
                        "severity": finding.severity.value,
                        "category": finding.category.value,
                        "root_cause_key": finding.root_cause_key,
                        "record_hash": finding.record_hash,
                        "observed_value": str(finding.observed_value),
                        "expected_requirement": str(finding.expected_requirement),
                    },
                )
            )

            # Link rule -> finding (VIOLATES)
            rule_node_id = f"rule:{finding.rule_id}:{finding.rule_version}"
            if rule_node_id in nodes:
                add_edge(rule_node_id, finding_node_id, EvidenceRelationType.VIOLATES)

            # Link evidence facts -> finding
            for fact_id in finding.evidence_node_links:
                fact_node_id = f"fact:{fact_id}"
                if fact_node_id in nodes:
                    add_edge(fact_node_id, finding_node_id, EvidenceRelationType.DERIVED_FROM)

            # Remediation reference node if present
            if finding.remediation_guidance:
                rem_node_id = f"rem:{finding.finding_id}"
                add_node(
                    EvidenceNode(
                        node_id=rem_node_id,
                        node_type=EvidenceNodeType.REMEDIATION_REFERENCE,
                        label=f"Remediation for {finding.rule_id}",
                        properties={
                            "guidance": finding.remediation_guidance,
                            "directive": getattr(finding, "remediation_directive", getattr(finding, "remediation_strongswan_directive", "")) or "",
                        },
                    )
                )
                add_edge(finding_node_id, rem_node_id, EvidenceRelationType.REMEDIATED_BY)

        # 6. Threat Instances
        if threat_instances:
            for threat in threat_instances:
                threat_node_id = f"threat:{threat.threat_id}:{threat.finding_id}"
                add_node(
                    EvidenceNode(
                        node_id=threat_node_id,
                        node_type=EvidenceNodeType.THREAT,
                        label=f"Threat: {threat.threat_name}",
                        properties={
                            "threat_id": threat.threat_id,
                            "name": threat.threat_name,
                            "likelihood": threat.likelihood.value,
                            "impact": threat.impact.value,
                            "risk_tier": threat.risk_tier.value,
                            "attack_vector": threat.attack_vector,
                        },
                    )
                )
                finding_node_id = f"finding:{threat.finding_id}"
                if finding_node_id in nodes:
                    add_edge(finding_node_id, threat_node_id, EvidenceRelationType.MAPS_TO)

        # 7. Score Deductions
        if score_assessment:
            for ded in score_assessment.deduction_audit:
                ded_node_id = f"deduction:{ded.finding_id}"
                add_node(
                    EvidenceNode(
                        node_id=ded_node_id,
                        node_type=EvidenceNodeType.SCORE_COMPONENT,
                        label=f"Deduction: -{ded.applied_deduction:.1f} pts",
                        properties={
                            "finding_id": ded.finding_id,
                            "applied_deduction": ded.applied_deduction,
                            "raw_deduction": ded.raw_deduction,
                            "is_deduplicated": ded.is_deduplicated,
                            "rationale": ded.rationale,
                        },
                    )
                )
                finding_node_id = f"finding:{ded.finding_id}"
                if finding_node_id in nodes:
                    add_edge(finding_node_id, ded_node_id, EvidenceRelationType.DEDUCTS)

        # 8. Fingerprintability Components
        if fingerprintability and fingerprintability.components:
            for comp_name, comp in fingerprintability.components.items():
                if comp.is_available:
                    comp_node_id = f"mfi:{comp_name}"
                    add_node(
                        EvidenceNode(
                            node_id=comp_node_id,
                            node_type=EvidenceNodeType.FINGERPRINTABILITY_COMPONENT,
                            label=f"MFI: {comp.name} ({comp.score:.1f}%)",
                            properties={
                                "name": comp.name,
                                "score": comp.score,
                                "weight": comp.weight,
                                "rationale": comp.rationale,
                            },
                        )
                    )
                    add_edge(cap_id, comp_node_id, EvidenceRelationType.MEASURES)

        return EvidenceGraph(
            analysis_id=analysis_id,
            capture_sha256=capture_sha256,
            nodes=list(nodes.values()),
            edges=edges,
        )
