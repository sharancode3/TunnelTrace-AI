"""Security Finding and Evidence Gap Generator.

Transforms EvaluationRecords into immutable, tamper-evident SecurityFinding instances
and EvidenceGap records without any LLM hallucination.
"""

from __future__ import annotations

import hashlib
from typing import Any

from app.security.facts.models import EvidenceState
from app.security.findings.models import EvidenceGap, SecurityFinding
from app.security.policy.evaluator import ComplianceState, EvaluationRecord
from app.security.policy.schema import PolicyBundle, PolicyRule


class FindingGenerator:
    """Deterministic generator producing structured findings and evidence gaps."""

    def __init__(self, bundle: PolicyBundle | None = None) -> None:
        self.bundle = bundle

    def generate(
        self,
        analysis_id: str,
        eval_records: list[EvaluationRecord],
        bundle: PolicyBundle | None = None,
    ) -> tuple[list[SecurityFinding], list[EvidenceGap]]:
        """Process evaluation records, separating FAIL findings from UNKNOWN gaps."""
        active_bundle = bundle or self.bundle
        if active_bundle is None:
            raise ValueError("A PolicyBundle must be provided to FindingGenerator.")

        findings: list[SecurityFinding] = []
        gaps: list[EvidenceGap] = []
        rules_by_id: dict[str, PolicyRule] = {r.rule_id: r for r in active_bundle.rules}

        for rec in eval_records:
            rule = rec.rule or rules_by_id.get(rec.rule_id)
            if rule is None:
                continue

            # -----------------------------------------------------------------
            # FAIL -> Create Structured Security Finding
            # -----------------------------------------------------------------
            if rec.compliance_state == ComplianceState.FAIL:
                subj_id = rec.subject_id or "global"
                # Deterministic finding ID
                seed = f"{analysis_id}:{rule.rule_id}:{subj_id}:{rule.root_cause_key}"
                f_id = f"FIND-{hashlib.sha256(seed.encode()).hexdigest()[:12].upper()}"

                ref_dict = {
                    "source": rule.authoritative_reference.source,
                    "section": rule.authoritative_reference.section,
                    "url": rule.authoritative_reference.url,
                    "requirement": rule.authoritative_reference.normative_requirement,
                }

                ev_st = rec.evidence_state
                if isinstance(ev_st, str):
                    try:
                        ev_enum = EvidenceState(ev_st)
                    except ValueError:
                        ev_enum = EvidenceState.VERIFIED
                elif isinstance(ev_st, EvidenceState):
                    ev_enum = ev_st
                else:
                    ev_enum = EvidenceState.VERIFIED

                prof_id = (
                    active_bundle.profile.value
                    if hasattr(active_bundle.profile, "value")
                    else str(active_bundle.profile)
                )

                finding = SecurityFinding(
                    finding_id=f_id,
                    analysis_id=analysis_id,
                    rule_id=rule.rule_id,
                    rule_version=rule.rule_version,
                    policy_bundle_id=active_bundle.bundle_id,
                    policy_bundle_hash=active_bundle.manifest_hash,
                    profile_id=prof_id,
                    category=rule.category,
                    title=rule.title,
                    technical_description=f"{rule.description} Observed: {rec.observed_value}.",
                    affected_entity_type=rec.subject_type or "IPSEC_ENTITY",
                    affected_entity_id=subj_id,
                    observed_value=rec.observed_value,
                    expected_requirement=str(rule.assertion.expected_value),
                    compliance_result=ComplianceState.FAIL,
                    evidence_state=ev_enum,
                    severity=rule.severity,
                    root_cause_key=rule.root_cause_key,
                    standards_references=[ref_dict],
                    remediation_guidance=rule.remediation.summary,
                    remediation_strongswan_directive=rule.remediation.strongswan_directive,
                    threat_mapping_id=rule.threat_mapping_id,
                    evidence_node_links=rec.contributing_fact_ids,
                )
                # Compute record hash
                r_hash = finding.compute_record_hash()
                object.__setattr__(finding, "record_hash", r_hash)
                findings.append(finding)

            # -----------------------------------------------------------------
            # UNKNOWN -> Create Auditable Evidence Gap (Zero score deduction)
            # -----------------------------------------------------------------
            elif rec.compliance_state == ComplianceState.UNKNOWN:
                subj_id = rec.subject_id or "global"
                gap = EvidenceGap(
                    analysis_id=analysis_id,
                    rule_id=rule.rule_id,
                    rule_version=rule.rule_version,
                    subject_id=subj_id,
                    required_facts=tuple(rule.evidence_requirements),
                    reason=rec.rationale,
                    recommended_action=(
                        "Extend capture duration or trigger an active Child SA rekey/exchange "
                        "to observe handshake parameters."
                    ),
                )
                gaps.append(gap)

        return findings, gaps

    def generate_findings(
        self,
        analysis_id: str,
        records: list[EvaluationRecord],
        facts: list[Any] | None = None,
        bundle: PolicyBundle | None = None,
    ) -> list[SecurityFinding]:
        """Convenience method returning only FAIL findings."""
        findings, _ = self.generate(analysis_id, records, bundle or self.bundle)
        return findings

    def generate_evidence_gaps(
        self,
        analysis_id: str,
        records: list[EvaluationRecord],
        bundle: PolicyBundle | None = None,
    ) -> list[EvidenceGap]:
        """Convenience method returning only UNKNOWN evidence gaps."""
        _, gaps = self.generate(analysis_id, records, bundle or self.bundle)
        return gaps
