"""Deterministic Security Posture Scoring Engine.

Implements transparent, explainable 0-100 scoring with:
1. Itemized deduction auditing (every lost point linked to a finding).
2. Root-cause deduplication (correlated findings collapse to prevent double-punishment).
3. Monotonicity invariants (adding a violation cannot improve score; resolving one cannot decrease score).
4. Strict separation of Evidence Coverage (UNKNOWN incurs zero deduction).
"""

from __future__ import annotations

from app.security.findings.models import SecurityFinding
from app.security.policy.evaluator import ComplianceState, EvaluationRecord
from app.security.scoring.models import (
    EvidenceCoverage,
    ScoreAssessment,
    ScoreDeduction,
    ScorePolicy,
)


class SecurityScoringEngine:
    """Pure, deterministic scoring engine converting findings into an audited posture score."""

    def __init__(self, policy: ScorePolicy | None = None) -> None:
        self.policy = policy or ScorePolicy()
        if not self.policy.policy_hash:
            p_hash = self.policy.compute_policy_hash()
            object.__setattr__(self.policy, "policy_hash", p_hash)

    def calculate_score(
        self,
        analysis_id: str,
        findings: list[SecurityFinding],
        eval_records: list[EvaluationRecord],
    ) -> ScoreAssessment:
        """Execute deterministic score computation with full deduction audit."""
        # ---------------------------------------------------------------------
        # 1. Compute Evidence Coverage (Strictly independent metric)
        # ---------------------------------------------------------------------
        applicable_count = sum(1 for r in eval_records if r.compliance_state != ComplianceState.NOT_APPLICABLE)
        evaluated_count = sum(1 for r in eval_records if r.compliance_state in (ComplianceState.PASS, ComplianceState.FAIL))
        unknown_count = sum(1 for r in eval_records if r.compliance_state == ComplianceState.UNKNOWN)
        not_applicable_count = sum(1 for r in eval_records if r.compliance_state == ComplianceState.NOT_APPLICABLE)

        coverage_pct = (
            (evaluated_count / applicable_count * 100.0)
            if applicable_count > 0
            else 100.0
        )
        evidence_coverage = EvidenceCoverage(
            applicable_rules=applicable_count,
            evaluated_rules=evaluated_count,
            unknown_rules=unknown_count,
            not_applicable_rules=not_applicable_count,
            coverage_percentage=coverage_pct,
        )

        # ---------------------------------------------------------------------
        # 2. Compute Itemized Deductions with Root-Cause Deduplication
        # ---------------------------------------------------------------------
        deduction_audit: list[ScoreDeduction] = []
        category_deductions: dict[str, float] = {}

        # Group findings by root_cause_key to prevent double-counting
        findings_by_root_cause: dict[str, list[SecurityFinding]] = {}
        for f in findings:
            findings_by_root_cause.setdefault(f.root_cause_key, []).append(f)

        for rc_key, rc_findings in findings_by_root_cause.items():
            # Sort findings by deduction amount descending so the most severe wins
            sorted_by_severity = sorted(
                rc_findings,
                key=lambda x: self.policy.severity_deductions.get(x.severity, 0.0),
                reverse=True,
            )

            primary_finding = sorted_by_severity[0]
            primary_deduction = self.policy.severity_deductions.get(primary_finding.severity, 0.0)

            # Record primary finding deduction
            deduction_audit.append(
                ScoreDeduction(
                    finding_id=primary_finding.finding_id,
                    rule_id=primary_finding.rule_id,
                    category=primary_finding.category.value,
                    severity=primary_finding.severity,
                    root_cause_key=rc_key,
                    raw_deduction=primary_deduction,
                    applied_deduction=primary_deduction,
                    is_deduplicated=False,
                    rationale=f"Primary violation under root cause '{rc_key}' ({primary_finding.severity.value}).",
                )
            )
            cat_name = primary_finding.category.value
            category_deductions[cat_name] = category_deductions.get(cat_name, 0.0) + primary_deduction

            # If deduplication enabled, secondary correlated findings incur 0.0 applied deduction
            for secondary_finding in sorted_by_severity[1:]:
                sec_raw = self.policy.severity_deductions.get(secondary_finding.severity, 0.0)
                applied = 0.0 if self.policy.root_cause_deduplication else sec_raw
                deduction_audit.append(
                    ScoreDeduction(
                        finding_id=secondary_finding.finding_id,
                        rule_id=secondary_finding.rule_id,
                        category=secondary_finding.category.value,
                        severity=secondary_finding.severity,
                        root_cause_key=rc_key,
                        raw_deduction=sec_raw,
                        applied_deduction=applied,
                        is_deduplicated=self.policy.root_cause_deduplication,
                        rationale=(
                            f"Correlated finding deduplicated under root cause '{rc_key}' "
                            f"(covered by primary {primary_finding.finding_id})."
                        ),
                    )
                )
                if not self.policy.root_cause_deduplication:
                    cat_sec = secondary_finding.category.value
                    category_deductions[cat_sec] = category_deductions.get(cat_sec, 0.0) + sec_raw

        # ---------------------------------------------------------------------
        # 3. Aggregate Total and Category Subtotals
        # ---------------------------------------------------------------------
        total_applied_deductions = sum(d.applied_deduction for d in deduction_audit)
        raw_score = self.policy.base_score - total_applied_deductions
        overall_score = max(self.policy.min_score, min(self.policy.max_score, raw_score))

        # Standard category scores (100.0 minus deductions within that category)
        category_scores: dict[str, float] = {}
        for cat, ded in category_deductions.items():
            category_scores[cat] = max(0.0, 100.0 - ded)

        return ScoreAssessment(
            analysis_id=analysis_id,
            overall_score=overall_score,
            raw_score=raw_score,
            score_policy_id=self.policy.policy_id,
            score_policy_version=self.policy.policy_version,
            score_policy_hash=self.policy.policy_hash,
            status=self.policy.status,
            category_scores=category_scores,
            deduction_audit=deduction_audit,
            evidence_coverage=evidence_coverage,
        )
