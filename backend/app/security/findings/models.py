"""Structured Security Finding and Evidence Gap Models."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.security.facts.models import EvidenceState
from app.security.policy.evaluator import ComplianceState
from app.security.policy.schema import FindingCategory, Severity

FindingSeverity = Severity


@dataclass(frozen=True)
class SecurityFinding:
    """Immutable, evidence-linked security finding resulting from a policy violation (FAIL).

    Guarantees that no finding can be created by an LLM or without direct rule provenance.
    """

    finding_id: str
    analysis_id: str
    rule_id: str
    rule_version: str
    policy_bundle_id: str
    policy_bundle_hash: str
    profile_id: str
    category: FindingCategory
    title: str
    technical_description: str
    affected_entity_type: str
    affected_entity_id: str
    observed_value: Any
    expected_requirement: str
    compliance_result: ComplianceState  # Always ComplianceState.FAIL
    evidence_state: EvidenceState
    severity: Severity
    root_cause_key: str
    standards_references: list[dict[str, Any]] = field(default_factory=list)
    remediation_guidance: str = ""
    remediation_strongswan_directive: str | None = None
    threat_mapping_id: str | None = None
    evidence_node_links: tuple[str, ...] = field(default_factory=tuple)
    record_hash: str = field(default="")
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def create(
        cls,
        finding_id: str,
        analysis_id: str,
        rule_id: str,
        rule_version: str,
        profile_id: str,
        category: FindingCategory,
        severity: Severity,
        title: str,
        technical_description: str,
        root_cause_key: str,
        affected_entity_type: str,
        affected_entity_id: str,
        observed_value: Any,
        expected_requirement: str,
        evidence_node_links: list[str] | tuple[str, ...] = (),
        remediation_guidance: str = "",
        remediation_strongswan_directive: str | None = None,
        threat_mapping_id: str | None = None,
        policy_bundle_id: str = "bundle-default",
        policy_bundle_hash: str = "0" * 64,
        compliance_result: ComplianceState = ComplianceState.FAIL,
        evidence_state: EvidenceState = EvidenceState.VERIFIED,
    ) -> SecurityFinding:
        """Convenience constructor that computes the cryptographic record hash."""
        f_hash_payload = {
            "finding_id": finding_id,
            "analysis_id": analysis_id,
            "rule_id": rule_id,
            "rule_version": rule_version,
            "policy_bundle_hash": policy_bundle_hash,
            "affected_entity_id": affected_entity_id,
            "observed_value": str(observed_value),
            "expected_requirement": expected_requirement,
            "severity": severity.value,
            "root_cause_key": root_cause_key,
        }
        r_hash = hashlib.sha256(json.dumps(f_hash_payload, sort_keys=True).encode("utf-8")).hexdigest()

        return cls(
            finding_id=finding_id,
            analysis_id=analysis_id,
            rule_id=rule_id,
            rule_version=rule_version,
            policy_bundle_id=policy_bundle_id,
            policy_bundle_hash=policy_bundle_hash,
            profile_id=profile_id,
            category=category,
            title=title,
            technical_description=technical_description,
            affected_entity_type=affected_entity_type,
            affected_entity_id=affected_entity_id,
            observed_value=observed_value,
            expected_requirement=expected_requirement,
            compliance_result=compliance_result,
            evidence_state=evidence_state,
            severity=severity,
            root_cause_key=root_cause_key,
            standards_references=[],
            remediation_guidance=remediation_guidance,
            remediation_strongswan_directive=remediation_strongswan_directive,
            threat_mapping_id=threat_mapping_id,
            evidence_node_links=tuple(evidence_node_links),
            record_hash=r_hash,
        )

    @property
    def remediation_directive(self) -> str | None:
        """Alias for remediation_strongswan_directive."""
        return self.remediation_strongswan_directive

    def compute_record_hash(self) -> str:
        """Compute SHA-256 tamper-evident digest of canonical finding content."""
        payload = {
            "finding_id": self.finding_id,
            "analysis_id": self.analysis_id,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "policy_bundle_hash": self.policy_bundle_hash,
            "affected_entity_id": self.affected_entity_id,
            "observed_value": str(self.observed_value),
            "expected_requirement": self.expected_requirement,
            "severity": self.severity.value,
            "root_cause_key": self.root_cause_key,
        }
        serialized = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary representation."""
        return {
            "finding_id": self.finding_id,
            "analysis_id": self.analysis_id,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "policy_bundle_id": self.policy_bundle_id,
            "policy_bundle_hash": self.policy_bundle_hash,
            "profile_id": self.profile_id,
            "category": self.category.value,
            "title": self.title,
            "technical_description": self.technical_description,
            "affected_entity_type": self.affected_entity_type,
            "affected_entity_id": self.affected_entity_id,
            "observed_value": self.observed_value,
            "expected_requirement": self.expected_requirement,
            "compliance_result": self.compliance_result.value,
            "evidence_state": self.evidence_state.value,
            "severity": self.severity.value,
            "root_cause_key": self.root_cause_key,
            "standards_references": self.standards_references,
            "remediation_guidance": self.remediation_guidance,
            "remediation_strongswan_directive": self.remediation_strongswan_directive,
            "threat_mapping_id": self.threat_mapping_id,
            "evidence_node_links": list(self.evidence_node_links),
            "record_hash": self.record_hash or self.compute_record_hash(),
            "created_at": self.created_at.isoformat(),
        }


@dataclass(frozen=True)
class EvidenceGap:
    """Record of an inconclusive (UNKNOWN) policy evaluation where evidence was missing.

    Strictly separate from findings: UNKNOWN is NOT a weakness and incurs ZERO score penalty.
    """

    gap_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    analysis_id: str = ""
    rule_id: str = ""
    rule_version: str = ""
    subject_id: str = ""
    required_facts: tuple[str, ...] = field(default_factory=tuple)
    reason: str = ""
    recommended_action: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def missing_fields(self) -> list[str]:
        return list(self.required_facts)

    def to_dict(self) -> dict[str, Any]:
        """Convert evidence gap to dictionary representation."""
        return {
            "gap_id": self.gap_id,
            "analysis_id": self.analysis_id,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "subject_id": self.subject_id,
            "required_facts": list(self.required_facts),
            "missing_fields": self.missing_fields,
            "reason": self.reason,
            "recommended_action": self.recommended_action,
            "created_at": self.created_at.isoformat(),
        }
