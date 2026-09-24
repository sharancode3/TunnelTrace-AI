"""Pure Deterministic Policy Rule Evaluation Engine.

Executes 3-stage evaluation:
1. Applicability Check -> NOT_APPLICABLE if false.
2. Evidence Requirements Check -> UNKNOWN if required facts are missing or unobserved.
3. Assertion Evaluation via Kleene 3-Valued Logic -> PASS / FAIL / UNKNOWN.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from app.security.facts.models import EvidenceState, SecurityFact
from app.security.policy.logic import (
    LogicalState,
    kleene_all,
    kleene_any,
    kleene_not,
)
from app.security.policy.operators import evaluate_operator
from app.security.policy.schema import (
    PolicyRule,
    RuleApplicability,
    RuleAssertion,
)


class ComplianceState(str, Enum):
    """Discrete compliance outcomes from policy evaluation."""

    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True)
class EvaluationRecord:
    """Outcome of evaluating one PolicyRule against a set of security facts."""

    rule_id: str
    rule_version: str
    compliance_state: ComplianceState
    evidence_state: EvidenceState
    observed_value: Any = None
    expected_value: Any = None
    subject_id: str | None = None
    subject_type: str | None = None
    rationale: str = ""
    profile_id: str = ""
    contributing_fact_ids: tuple[str, ...] = field(default_factory=tuple)
    rule: PolicyRule | None = None


class PolicyEvaluator:
    """Pure, stateless evaluator for PolicyRule against normalized SecurityFacts."""

    def __init__(self, bundle: Any | None = None) -> None:
        self.bundle = bundle

    def evaluate_all(
        self,
        analysis_id: str,
        facts: list[SecurityFact],
        bundle: Any | None = None,
    ) -> list[EvaluationRecord]:
        """Evaluate all rules in the bundle against provided facts."""
        active_bundle = bundle or self.bundle
        if active_bundle is None:
            raise ValueError("No PolicyBundle provided to PolicyEvaluator.")
        records: list[EvaluationRecord] = []
        for rule in active_bundle.rules:
            records.extend(self.evaluate_rule(rule, facts))
        return records

    def evaluate_rule(
        self,
        rule: PolicyRule,
        facts: list[SecurityFact],
    ) -> list[EvaluationRecord]:
        """Evaluate a rule against facts, producing an EvaluationRecord for each relevant subject."""
        # Index facts by subject_id and by key
        facts_by_subject: dict[str, dict[str, SecurityFact]] = {}
        global_facts_by_key: dict[str, SecurityFact] = {}

        for fact in facts:
            global_facts_by_key[fact.key] = fact
            if fact.subject_id:
                if fact.subject_id not in facts_by_subject:
                    facts_by_subject[fact.subject_id] = {}
                facts_by_subject[fact.subject_id][fact.key] = fact

        # Determine target subjects based on rule evidence requirements
        target_subject_keys = [k for k in rule.evidence_requirements if "." in k]
        target_subject_prefixes = {k.split(".")[0] for k in target_subject_keys}

        candidate_subject_ids: set[str] = set()
        for subj_id, subj_facts in facts_by_subject.items():
            fact_prefixes = {k.split(".")[0] for k in subj_facts.keys()}
            if target_subject_prefixes.intersection(fact_prefixes):
                candidate_subject_ids.add(subj_id)

        # If no specific subject IDs grouped (or empty capture), evaluate globally
        if not candidate_subject_ids:
            return [self._evaluate_single_subject(rule, global_facts_by_key, None)]

        records: list[EvaluationRecord] = []
        for subj_id in sorted(candidate_subject_ids):
            subj_fact_map = dict(global_facts_by_key)
            subj_fact_map.update(facts_by_subject[subj_id])
            rec = self._evaluate_single_subject(rule, subj_fact_map, subj_id)
            records.append(rec)

        return records

    def _evaluate_single_subject(
        self,
        rule: PolicyRule,
        fact_map: dict[str, SecurityFact],
        subject_id: str | None,
    ) -> EvaluationRecord:
        """Evaluate rule logic against a unified fact dictionary for one subject."""
        contributing_fact_ids: list[str] = []
        subj_type: str | None = None

        # ---------------------------------------------------------------------
        # 1. Applicability Check
        # ---------------------------------------------------------------------
        if rule.applicability is not None:
            app_state = self._eval_applicability(rule.applicability, fact_map, contributing_fact_ids)
            if app_state == LogicalState.FALSE:
                return EvaluationRecord(
                    rule_id=rule.rule_id,
                    rule_version=rule.rule_version,
                    compliance_state=ComplianceState.NOT_APPLICABLE,
                    evidence_state=EvidenceState.VERIFIED,
                    observed_value=None,
                    expected_value=None,
                    subject_id=subject_id,
                    subject_type=subj_type,
                    rationale=f"Rule '{rule.rule_id}' is NOT_APPLICABLE to the observed configuration.",
                    contributing_fact_ids=tuple(contributing_fact_ids),
                    rule=rule,
                )

        # ---------------------------------------------------------------------
        # 2. Evidence Requirements Check
        # ---------------------------------------------------------------------
        missing_or_unknown: list[str] = []
        for req_key in rule.evidence_requirements:
            fact = fact_map.get(req_key)
            if fact is None:
                missing_or_unknown.append(f"{req_key} (absent)")
            elif fact.evidence_state == EvidenceState.UNKNOWN or fact.value is None:
                missing_or_unknown.append(f"{req_key} (UNKNOWN state)")
                contributing_fact_ids.append(fact.fact_id)
            else:
                contributing_fact_ids.append(fact.fact_id)
                if subj_type is None and fact.subject_type:
                    subj_type = fact.subject_type.value

        if missing_or_unknown:
            return EvaluationRecord(
                rule_id=rule.rule_id,
                rule_version=rule.rule_version,
                compliance_state=ComplianceState.UNKNOWN,
                evidence_state=EvidenceState.UNKNOWN,
                observed_value=None,
                expected_value=None,
                subject_id=subject_id,
                subject_type=subj_type,
                rationale=f"Required protocol evidence missing or unobserved: {', '.join(missing_or_unknown)}",
                contributing_fact_ids=tuple(contributing_fact_ids),
                rule=rule,
            )

        # ---------------------------------------------------------------------
        # 3. Assertion Evaluation via Kleene Logic
        # ---------------------------------------------------------------------
        res_state, observed_val, expected_val = self._eval_assertion(
            rule.assertion, fact_map, contributing_fact_ids
        )

        # Determine composite evidence state from contributing facts
        composite_ev = EvidenceState.VERIFIED
        for fid in contributing_fact_ids:
            # Check if any fact was INFERRED
            matching_facts = [f for f in fact_map.values() if f.fact_id == fid]
            for f in matching_facts:
                if f.evidence_state == EvidenceState.INFERRED and composite_ev == EvidenceState.VERIFIED:
                    composite_ev = EvidenceState.INFERRED

        if res_state == LogicalState.TRUE:
            compliance = ComplianceState.PASS
            rationale = f"Assertion satisfied for rule '{rule.rule_id}'."
        elif res_state == LogicalState.FALSE:
            compliance = ComplianceState.FAIL
            rationale = (
                f"Assertion VIOLATED: observed '{observed_val}', expected {rule.assertion.operator} '{expected_val}'."
            )
        else:
            compliance = ComplianceState.UNKNOWN
            rationale = f"Assertion evaluation inconclusive (UNKNOWN) for rule '{rule.rule_id}'."

        return EvaluationRecord(
            rule_id=rule.rule_id,
            rule_version=rule.rule_version,
            compliance_state=compliance,
            evidence_state=composite_ev,
            observed_value=observed_val,
            expected_value=expected_val,
            subject_id=subject_id,
            subject_type=subj_type,
            rationale=rationale,
            contributing_fact_ids=tuple(contributing_fact_ids),
            rule=rule,
        )

    def _eval_applicability(
        self,
        app: RuleApplicability,
        fact_map: dict[str, SecurityFact],
        contributing_fact_ids: list[str],
    ) -> LogicalState:
        """Recursively evaluate RuleApplicability condition."""
        if app.all_of:
            states = [self._eval_applicability(sub, fact_map, contributing_fact_ids) for sub in app.all_of]
            return kleene_all(states)

        if app.any_of:
            states = [self._eval_applicability(sub, fact_map, contributing_fact_ids) for sub in app.any_of]
            return kleene_any(states)

        if app.target_field and app.operator:
            fact = fact_map.get(app.target_field)
            if fact is not None:
                contributing_fact_ids.append(fact.fact_id)
                observed = fact.value
            else:
                observed = None
            return evaluate_operator(app.operator, observed, app.expected_value)

        return LogicalState.TRUE

    def _eval_assertion(
        self,
        ass: RuleAssertion,
        fact_map: dict[str, SecurityFact],
        contributing_fact_ids: list[str],
    ) -> tuple[LogicalState, Any, Any]:
        """Recursively evaluate RuleAssertion returning (LogicalState, observed_val, expected_val)."""
        if ass.all_of:
            states: list[LogicalState] = []
            obs_vals: list[Any] = []
            for sub in ass.all_of:
                st, obs, _ = self._eval_assertion(sub, fact_map, contributing_fact_ids)
                states.append(st)
                obs_vals.append(obs)
            return kleene_all(states), obs_vals, "ALL_OF"

        if ass.any_of:
            states = []
            obs_vals = []
            for sub in ass.any_of:
                st, obs, _ = self._eval_assertion(sub, fact_map, contributing_fact_ids)
                states.append(st)
                obs_vals.append(obs)
            return kleene_any(states), obs_vals, "ANY_OF"

        if ass.not_condition:
            st, obs, exp = self._eval_assertion(ass.not_condition, fact_map, contributing_fact_ids)
            return kleene_not(st), obs, f"NOT({exp})"

        if ass.target_field and ass.operator:
            fact = fact_map.get(ass.target_field)
            if fact is not None:
                contributing_fact_ids.append(fact.fact_id)
                observed = fact.value
            else:
                observed = None
            st = evaluate_operator(ass.operator, observed, ass.expected_value)
            return st, observed, ass.expected_value

        return LogicalState.TRUE, None, None
