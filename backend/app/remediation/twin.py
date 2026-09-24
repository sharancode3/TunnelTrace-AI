"""Configuration Security Twin & Policy Projection Engine.

Executes counterfactual Policy-as-Code simulations against proposed configurations
using the identical Stage-8 policy evaluation, scoring, risk, and threat mapping engines.
Guarantees strict separation between counterfactual PROJECTION and empirical PROOF.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.remediation.ir import (
    ConfigurationIR,
    CurrentConfigurationSnapshot,
    EpistemicState,
    TransformIR,
)
from app.remediation.parser import ForensicFactsSnapshotBuilder, SwanctlParser
from app.remediation.proof import VerificationProofObligation
from app.remediation.renderer import ConfigurationDiffEngine, SwanctlRenderer
from app.remediation.templates import RemediationTemplateRegistry
from app.security.facts.models import DerivationType, EvidenceState, SecurityFact, SubjectType
from app.security.findings.generator import FindingGenerator
from app.security.findings.models import SecurityFinding
from app.security.policy.evaluator import PolicyEvaluator
from app.security.policy.registry import PolicyRegistry
from app.security.risk.engine import DeterministicRiskEngine
from app.security.scoring.engine import SecurityScoringEngine
from app.security.threats.mapper import ThreatMatrixEngine

logger = logging.getLogger(__name__)

TWIN_DISCLAIMER = (
    "This is a configuration-policy projection. It does not prove operational compatibility, "
    "successful negotiation, or remediation until validated using a fresh controlled-lab capture and reanalysis."
)


@dataclass(frozen=True)
class ProjectedRegressionAudit:
    """Rigorous whole-policy audit of a proposed configuration against all active Stage-8 rules."""

    targeted_finding_ids: tuple[str, ...]
    targeted_rule_ids: tuple[str, ...]
    projected_resolved_findings: list[dict[str, Any]]
    projected_remaining_findings: list[dict[str, Any]]
    projected_new_regressions: list[dict[str, Any]]
    baseline_score: float | None
    projected_score: float | None
    projected_score_delta: float | None
    baseline_risk_score: float | None
    projected_risk_score: float | None
    projected_risk_delta: float | None
    has_blocking_regressions: bool
    proof_obligations: list[dict[str, Any]]
    disclaimer: str = TWIN_DISCLAIMER

    def to_dict(self) -> dict[str, Any]:
        return {
            "targeted_finding_ids": list(self.targeted_finding_ids),
            "targeted_rule_ids": list(self.targeted_rule_ids),
            "projected_resolved_findings": self.projected_resolved_findings,
            "projected_remaining_findings": self.projected_remaining_findings,
            "projected_new_regressions": self.projected_new_regressions,
            "baseline_score": self.baseline_score,
            "projected_score": self.projected_score,
            "projected_score_delta": self.projected_score_delta,
            "baseline_risk_score": self.baseline_risk_score,
            "projected_risk_score": self.projected_risk_score,
            "projected_risk_delta": self.projected_risk_delta,
            "has_blocking_regressions": self.has_blocking_regressions,
            "proof_obligations": self.proof_obligations,
            "disclaimer": self.disclaimer,
        }


@dataclass
class TwinSimulationResult:
    """Consolidated counterfactual projection produced by the Configuration Security Twin."""

    twin_id: str
    analysis_id: str
    proposal_hash: str
    current_snapshot: CurrentConfigurationSnapshot
    proposed_ir: ConfigurationIR
    rendered_proposed_config: str
    semantic_diff: list[dict[str, Any]]
    text_diff: str
    regression_audit: ProjectedRegressionAudit
    projected_findings: list[SecurityFinding]
    projected_score: float | None
    projected_score_delta: float | None
    status: str = "PROJECTED"
    disclaimer: str = TWIN_DISCLAIMER


class ConfigurationSecurityTwin:
    """Core Configuration Security Twin coordinating counterfactual policy projections."""

    def __init__(self, policy_registry: PolicyRegistry | None = None) -> None:
        self.policy_registry = policy_registry or PolicyRegistry()
        self.scoring_engine = SecurityScoringEngine()
        self.risk_engine = DeterministicRiskEngine()
        self.threat_engine = ThreatMatrixEngine()
        self.template_registry = RemediationTemplateRegistry()

    def generate_remediation_proposal(
        self,
        current_snapshot: CurrentConfigurationSnapshot,
        baseline_findings: list[SecurityFinding],
        target_finding_ids: list[str] | None = None,
    ) -> ConfigurationIR:
        """Deterministically apply versioned remediation templates to CurrentConfigurationSnapshot."""
        # Convert observed facts into baseline ConfigurationIR
        working_ir = current_snapshot.to_configuration_ir()

        # Filter targeted findings
        targets = baseline_findings
        if target_finding_ids:
            targets = [f for f in baseline_findings if f.finding_id in target_finding_ids]

        # Apply deterministic templates
        for finding in targets:
            tmpl = self.template_registry.get_template_for_rule(finding.rule_id)
            if not tmpl:
                tmpl = self.template_registry.get_template_for_root_cause(finding.root_cause_key)
            if tmpl:
                logger.info(f"Applying remediation template '{tmpl.template_id}' for finding '{finding.finding_id}'")
                working_ir = tmpl.transformer(working_ir)

        return working_ir

    def synthesize_projected_facts(
        self,
        analysis_id: str,
        capture_sha256: str,
        ir: ConfigurationIR,
    ) -> list[SecurityFact]:
        """Synthesize normalized SecurityFacts representing the state if proposed IR is deployed."""
        facts: list[SecurityFact] = []
        conn = ir.connections[0] if ir.connections else None
        child = conn.children[0] if conn and conn.children else None

        ike_prop = conn.ike_proposals[0] if conn and conn.ike_proposals else None
        esp_prop = child.esp_proposals[0] if child and child.esp_proposals else None

        fake_subj_sess = f"projected-sess-{uuid.uuid4().hex[:6]}"
        fake_subj_sa = f"projected-sa-{uuid.uuid4().hex[:6]}"
        fake_subj_csa = f"projected-csa-{uuid.uuid4().hex[:6]}"
        fake_subj_esp = f"projected-esp-{uuid.uuid4().hex[:6]}"

        # 1. IKE Version
        facts.append(
            SecurityFact(
                key="ike_session.ike_version",
                value=f"IKEv{conn.ike_version}" if conn else "IKEv2",
                data_type="string",
                subject_type=SubjectType.IKE_SESSION,
                subject_id=fake_subj_sess,
                evidence_state=EvidenceState.VERIFIED,
                analysis_id=analysis_id,
                capture_sha256=capture_sha256,
                derivation_type=DerivationType.DIRECT,
            )
        )

        # 2. IKE Encryption
        if ike_prop:
            enc_name = ike_prop.encryption.upper()
            facts.append(
                SecurityFact(
                    key="ike_sa.encryption_algorithm",
                    value=enc_name,
                    data_type="string",
                    subject_type=SubjectType.IKE_SA,
                    subject_id=fake_subj_sa,
                    evidence_state=EvidenceState.VERIFIED,
                    analysis_id=analysis_id,
                    capture_sha256=capture_sha256,
                    derivation_type=DerivationType.DIRECT,
                )
            )

            # Key length
            facts.append(
                SecurityFact(
                    key="ike_sa.key_length_bits",
                    value=ike_prop.key_length or 256,
                    data_type="integer",
                    subject_type=SubjectType.IKE_SA,
                    subject_id=fake_subj_sa,
                    evidence_state=EvidenceState.VERIFIED,
                    analysis_id=analysis_id,
                    capture_sha256=capture_sha256,
                    derivation_type=DerivationType.DIRECT,
                )
            )

            # Integrity
            integ_val = ike_prop.integrity or ("AEAD-INTEGRATED" if "gcm" in ike_prop.encryption.lower() else "SHA256")
            facts.append(
                SecurityFact(
                    key="ike_sa.integrity_algorithm",
                    value=integ_val.upper(),
                    data_type="string",
                    subject_type=SubjectType.IKE_SA,
                    subject_id=fake_subj_sa,
                    evidence_state=EvidenceState.VERIFIED,
                    analysis_id=analysis_id,
                    capture_sha256=capture_sha256,
                    derivation_type=DerivationType.DIRECT,
                )
            )

            # DH group
            if ike_prop.dh_group is not None:
                facts.append(
                    SecurityFact(
                        key="ike_sa.diffie_hellman_group",
                        value=ike_prop.dh_group,
                        data_type="integer",
                        subject_type=SubjectType.IKE_SA,
                        subject_id=fake_subj_sa,
                        evidence_state=EvidenceState.VERIFIED,
                        analysis_id=analysis_id,
                        capture_sha256=capture_sha256,
                        derivation_type=DerivationType.DIRECT,
                    )
                )

        # 3. Child SA
        if child:
            facts.append(
                SecurityFact(
                    key="child_sa.protocol",
                    value="ESP",
                    data_type="string",
                    subject_type=SubjectType.CHILD_SA,
                    subject_id=fake_subj_csa,
                    evidence_state=EvidenceState.VERIFIED,
                    analysis_id=analysis_id,
                    capture_sha256=capture_sha256,
                    derivation_type=DerivationType.DIRECT,
                )
            )

            # Mode
            facts.append(
                SecurityFact(
                    key="child_sa.mode",
                    value=child.mode.upper(),
                    data_type="string",
                    subject_type=SubjectType.CHILD_SA,
                    subject_id=fake_subj_csa,
                    evidence_state=EvidenceState.VERIFIED,
                    analysis_id=analysis_id,
                    capture_sha256=capture_sha256,
                    derivation_type=DerivationType.DIRECT,
                )
            )

            if esp_prop:
                facts.append(
                    SecurityFact(
                        key="child_sa.encryption_algorithm",
                        value=esp_prop.encryption.upper(),
                        data_type="string",
                        subject_type=SubjectType.CHILD_SA,
                        subject_id=fake_subj_csa,
                        evidence_state=EvidenceState.VERIFIED,
                        analysis_id=analysis_id,
                        capture_sha256=capture_sha256,
                        derivation_type=DerivationType.DIRECT,
                    )
                )

            # PFS
            pfs_stat = "ENABLED" if child.pfs_dh_group is not None else "DISABLED"
            facts.append(
                SecurityFact(
                    key="child_sa.pfs_status",
                    value=pfs_stat,
                    data_type="string",
                    subject_type=SubjectType.CHILD_SA,
                    subject_id=fake_subj_csa,
                    evidence_state=EvidenceState.VERIFIED,
                    analysis_id=analysis_id,
                    capture_sha256=capture_sha256,
                    derivation_type=DerivationType.DIRECT,
                )
            )

            if child.pfs_dh_group is not None:
                facts.append(
                    SecurityFact(
                        key="child_sa.pfs_dh_group",
                        value=child.pfs_dh_group,
                        data_type="integer",
                        subject_type=SubjectType.CHILD_SA,
                        subject_id=fake_subj_csa,
                        evidence_state=EvidenceState.VERIFIED,
                        analysis_id=analysis_id,
                        capture_sha256=capture_sha256,
                        derivation_type=DerivationType.DIRECT,
                    )
                )

            # Replay window
            facts.append(
                SecurityFact(
                    key="child_sa.replay_window_size",
                    value=child.replay_window,
                    data_type="integer",
                    subject_type=SubjectType.CHILD_SA,
                    subject_id=fake_subj_csa,
                    evidence_state=EvidenceState.VERIFIED,
                    analysis_id=analysis_id,
                    capture_sha256=capture_sha256,
                    derivation_type=DerivationType.DIRECT,
                )
            )

        # 4. ESP Flow facts
        facts.append(
            SecurityFact(
                key="esp_flow.sequence_monotonic",
                value=True,
                data_type="boolean",
                subject_type=SubjectType.ESP_FLOW,
                subject_id=fake_subj_esp,
                evidence_state=EvidenceState.VERIFIED,
                analysis_id=analysis_id,
                capture_sha256=capture_sha256,
                derivation_type=DerivationType.DIRECT,
            )
        )

        return facts

    def run_projection(
        self,
        analysis_id: str,
        current_snapshot: CurrentConfigurationSnapshot,
        proposed_ir: ConfigurationIR,
        baseline_findings: list[SecurityFinding],
        baseline_score: float | None = None,
        baseline_risk_score: float | None = None,
        profile_id: str = "profile_nist_sp800_77",
    ) -> TwinSimulationResult:
        """Run identical Stage-8 Policy Engine against the proposed configuration IR."""
        # 1. Proposal Hash
        rendered_proposed = SwanctlRenderer.render(proposed_ir)
        proposal_hash = hashlib.sha256(rendered_proposed.encode("utf-8")).hexdigest()

        # 2. Render Current Observed text for diffing
        current_ir = current_snapshot.to_configuration_ir()
        rendered_current = SwanctlRenderer.render(current_ir)

        # 3. Compute Diffs
        semantic_diff = ConfigurationDiffEngine.compute_semantic_diff(current_snapshot, proposed_ir)
        text_diff = ConfigurationDiffEngine.compute_text_diff(rendered_current, rendered_proposed)

        # 4. Synthesize projected facts
        projected_facts = self.synthesize_projected_facts(
            analysis_id=analysis_id,
            capture_sha256=current_snapshot.capture_sha256,
            ir=proposed_ir,
        )

        # 5. Retrieve active policy bundle
        bundle = self.policy_registry.get_active_bundle(profile_id)
        if not bundle:
            registered = self.policy_registry.list_bundles()
            if registered:
                bundle = self.policy_registry.get_bundle(registered[0])
            if not bundle:
                raise RuntimeError(f"POLICY_BUNDLE_UNAVAILABLE: No active bundle for profile '{profile_id}'")

        # 6. Evaluate all rules in the policy bundle
        evaluator = PolicyEvaluator(bundle)
        eval_records = evaluator.evaluate_all(analysis_id=analysis_id, facts=projected_facts)

        finding_gen = FindingGenerator(bundle)
        projected_findings = finding_gen.generate_findings(
            analysis_id=analysis_id,
            records=eval_records,
            facts=projected_facts,
        )

        # 7. Projected Score
        score_assessment = self.scoring_engine.calculate_score(
            analysis_id=analysis_id,
            findings=projected_findings,
            eval_records=eval_records,
        )
        projected_score = score_assessment.overall_score
        score_delta = None
        if baseline_score is not None and projected_score is not None:
            score_delta = round(projected_score - baseline_score, 2)

        # 8. Projected Risk
        risk_assessment = self.risk_engine.assess_risks(
            analysis_id=analysis_id,
            findings=projected_findings,
        )
        tier_scores = {"CRITICAL": 95.0, "HIGH": 75.0, "MEDIUM": 45.0, "LOW": 15.0}
        projected_risk = tier_scores.get(risk_assessment.overall_risk_tier.value, 20.0)
        risk_delta = None
        if baseline_risk_score is not None and projected_risk is not None:
            risk_delta = round(projected_risk - baseline_risk_score, 2)


        # 9. Projected Regression Audit
        baseline_rules_failed = {f.rule_id: f for f in baseline_findings}
        projected_rules_failed = {f.rule_id: f for f in projected_findings}

        projected_resolved: list[dict[str, Any]] = []
        proof_obligations: list[dict[str, Any]] = []

        for r_id, b_finding in baseline_rules_failed.items():
            tmpl = self.template_registry.get_template_for_rule(r_id) or self.template_registry.get_template_for_root_cause(b_finding.root_cause_key)
            if tmpl:
                obl = tmpl.proof_obligation_factory(b_finding)
                proof_obligations.append(obl.to_dict())

            if r_id not in projected_rules_failed:
                projected_resolved.append(
                    {
                        "finding_id": b_finding.finding_id,
                        "rule_id": b_finding.rule_id,
                        "title": b_finding.title,
                        "severity": b_finding.severity.value,
                        "root_cause_key": b_finding.root_cause_key,
                        "projected_state": "PROJECTED_RESOLVED",
                        "rationale": f"Rule {r_id} passes under proposed configuration IR transforms.",
                    }
                )

        projected_remaining: list[dict[str, Any]] = []
        for r_id, p_finding in projected_rules_failed.items():
            if r_id in baseline_rules_failed:
                b_find = baseline_rules_failed[r_id]
                projected_remaining.append(
                    {
                        "finding_id": b_find.finding_id,
                        "rule_id": p_finding.rule_id,
                        "title": p_finding.title,
                        "severity": p_finding.severity.value,
                        "root_cause_key": p_finding.root_cause_key,
                        "projected_state": "PROJECTED_REMAINING",
                        "rationale": f"Proposed configuration does not resolve root cause '{p_finding.root_cause_key}'.",
                    }
                )

        projected_new_regressions: list[dict[str, Any]] = []
        for r_id, p_finding in projected_rules_failed.items():
            if r_id not in baseline_rules_failed:
                projected_new_regressions.append(
                    {
                        "finding_id": p_finding.finding_id,
                        "rule_id": p_finding.rule_id,
                        "title": p_finding.title,
                        "severity": p_finding.severity.value,
                        "root_cause_key": p_finding.root_cause_key,
                        "projected_state": "PROJECTED_NEW_FAILURE",
                        "rationale": f"Proposed configuration triggers a new policy violation: {p_finding.technical_description}",
                    }
                )

        has_blocking = any(r["severity"] in ("CRITICAL", "HIGH") for r in projected_new_regressions)

        regression_audit = ProjectedRegressionAudit(
            targeted_finding_ids=tuple(baseline_rules_failed.keys()),
            targeted_rule_ids=tuple(baseline_rules_failed.keys()),
            projected_resolved_findings=projected_resolved,
            projected_remaining_findings=projected_remaining,
            projected_new_regressions=projected_new_regressions,
            baseline_score=baseline_score,
            projected_score=projected_score,
            projected_score_delta=score_delta,
            baseline_risk_score=baseline_risk_score,
            projected_risk_score=projected_risk,
            projected_risk_delta=risk_delta,
            has_blocking_regressions=has_blocking,
            proof_obligations=proof_obligations,
            disclaimer=TWIN_DISCLAIMER,
        )

        return TwinSimulationResult(
            twin_id=str(uuid.uuid4()),
            analysis_id=analysis_id,
            proposal_hash=proposal_hash,
            current_snapshot=current_snapshot,
            proposed_ir=proposed_ir,
            rendered_proposed_config=rendered_proposed,
            semantic_diff=semantic_diff,
            text_diff=text_diff,
            regression_audit=regression_audit,
            projected_findings=projected_findings,
            projected_score=projected_score,
            projected_score_delta=score_delta,
            status="PROJECTED",
            disclaimer=TWIN_DISCLAIMER,
        )
