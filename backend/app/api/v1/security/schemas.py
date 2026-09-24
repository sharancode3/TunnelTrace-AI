"""Data Transfer Objects and API Schemas for Stage 8 Security & Compliance."""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, Field


class PolicyProfileSummaryDTO(BaseModel):
    """Available Policy-as-Code profile overview."""

    profile_id: str
    name: str
    description: str
    active_bundle_id: str | None = None
    rule_count: int = 0


class ComplianceEvaluationDTO(BaseModel):
    """Itemized rule compliance evaluation record."""

    rule_id: str
    rule_version: str
    subject_type: str
    subject_id: str
    compliance_state: str  # PASS, FAIL, UNKNOWN, NOT_APPLICABLE
    evidence_state: str
    rationale: str


class ComplianceSummaryDTO(BaseModel):
    """Aggregate compliance status and itemized evaluations."""

    analysis_id: uuid.UUID
    profile_id: str
    bundle_id: str
    bundle_hash: str
    total_rules_evaluated: int
    pass_count: int
    fail_count: int
    unknown_count: int
    not_applicable_count: int
    evaluations: list[ComplianceEvaluationDTO]


class SecurityFindingDTO(BaseModel):
    """Structured security finding resulting from a FAIL compliance state."""

    finding_id: str
    analysis_id: uuid.UUID
    rule_id: str
    rule_version: str
    profile_id: str
    category: str
    severity: str
    title: str
    technical_description: str
    root_cause_key: str
    affected_entity_type: str
    affected_entity_id: str
    observed_value: Any
    expected_requirement: Any
    evidence_state: str
    remediation_guidance: str | None = None
    remediation_directive: str | None = None
    record_hash: str
    created_at: str


class ScoreDeductionDTO(BaseModel):
    """Audited score deduction trace item."""

    finding_id: str
    rule_id: str
    category: str
    severity: str
    root_cause_key: str
    raw_deduction: float
    applied_deduction: float
    is_deduplicated: bool
    rationale: str


class EvidenceCoverageDTO(BaseModel):
    """Transparent evidence coverage statistics."""

    applicable_rules: int
    evaluated_rules: int
    unknown_rules: int
    not_applicable_rules: int
    coverage_percentage: float


class SecurityScoreDTO(BaseModel):
    """Audited Security Posture Score breakdown."""

    analysis_id: uuid.UUID
    overall_score: float
    raw_score: float
    score_policy_id: str
    score_policy_version: str
    score_policy_hash: str
    status: str
    coverage_percentage: float
    category_scores: dict[str, float]
    deduction_audit: list[ScoreDeductionDTO]
    evidence_coverage: EvidenceCoverageDTO
    disclaimer: str = (
        "Internal product-defined security posture score. "
        "This is an automated analytical metric against the selected policy profile, "
        "NOT an official NIST, government, Common Criteria, or FIPS certification."
    )


class RiskItemDTO(BaseModel):
    """Deterministic risk evaluation per finding."""

    finding_id: str
    rule_id: str
    severity: str
    likelihood: str
    impact: str
    risk_tier: str
    evidence_state: str
    threat_mapped: bool
    rationale: str


class RiskAssessmentDTO(BaseModel):
    """Risk assessment summary."""

    analysis_id: uuid.UUID
    risk_policy_id: str
    risk_policy_version: str
    overall_risk_tier: str
    items: list[RiskItemDTO]


class ThreatInstanceDTO(BaseModel):
    """Pre-authored threat scenario mapped to a finding."""

    finding_id: str
    threat_id: str
    threat_name: str
    attack_vector: str
    likelihood: str
    impact: str
    risk_tier: str


class FingerprintabilityComponentDTO(BaseModel):
    """Individual side-channel distinguishability component."""

    name: str
    score: float
    weight: float
    is_available: bool
    rationale: str


class FingerprintabilityDTO(BaseModel):
    """Side-channel behavioral distinguishability assessment."""

    analysis_id: uuid.UUID
    overall_index: float | None
    status: str
    methodology_version: str
    methodology_hash: str
    components: dict[str, FingerprintabilityComponentDTO]
    flow_count: int
    calibration_status: str
    ml_model_bundle_id: str | None = None
    disclaimer: str


class ReactFlowNodeDTO(BaseModel):
    """Node formatted for React Flow canvas."""

    id: str
    type: str
    position: dict[str, int]
    data: dict[str, Any]


class ReactFlowEdgeDTO(BaseModel):
    """Directed edge formatted for React Flow canvas."""

    id: str
    source: str
    target: str
    label: str
    animated: bool = False
    data: dict[str, Any] = Field(default_factory=dict)


class EvidenceGraphDTO(BaseModel):
    """Forensic provenance graph exportable to React Flow."""

    analysis_id: uuid.UUID
    capture_sha256: str
    nodes_count: int
    edges_count: int
    react_flow: dict[str, Any]
    manifest_sha256: str
