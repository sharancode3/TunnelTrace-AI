"""Pydantic Schema and Value Objects for Policy-as-Code Rules and Bundles."""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.security.facts.registry import is_known_fact_field
from app.security.policy.operators import Operator


class PolicyProfile(str, Enum):
    """Supported Policy-as-Code compliance profiles."""

    PROFILE_IETF_BASELINE = "profile_ietf_baseline"
    PROFILE_NIST_SP800_77 = "profile_nist_sp800_77"
    PROFILE_ENTERPRISE_STRICT = "profile_enterprise_strict"
    PROFILE_CUSTOM_ORG = "profile_custom_org"


class RuleStatus(str, Enum):
    """Lifecycle and authority verification state of a policy rule."""

    DRAFT = "DRAFT"
    SCHEMA_VALIDATED = "SCHEMA_VALIDATED"
    AUTHORITY_VERIFICATION_PENDING = "AUTHORITY_VERIFICATION_PENDING"
    AUTHORITY_VERIFIED = "AUTHORITY_VERIFIED"
    TESTED = "TESTED"
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    RETIRED = "RETIRED"


class AuthorityTier(str, Enum):
    """Hierarchical authority tier governing normative requirements."""

    ORGANIZATIONAL = "ORGANIZATIONAL"
    NATIONAL_STANDARD = "NATIONAL_STANDARD"  # NIST SP 800-77, SP 800-57
    IETF_STANDARD = "IETF_STANDARD"          # RFC 7296, RFC 8221, RFC 8247, RFC 4301
    IANA_REGISTRY = "IANA_REGISTRY"          # IANA IPsec Transform Identifiers
    VENDOR_GUIDANCE = "VENDOR_GUIDANCE"      # strongSwan operational recommendations


class Severity(str, Enum):
    """Severity tier for policy violations."""

    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingCategory(str, Enum):
    """Taxonomic category of security findings."""

    PROTOCOL_VERSION = "PROTOCOL_VERSION"
    CRYPTOGRAPHY = "CRYPTOGRAPHY"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    PFS = "PFS"
    AUTHENTICATION_INTEGRITY = "AUTHENTICATION_INTEGRITY"
    SA_MANAGEMENT = "SA_MANAGEMENT"
    REPLAY_EVIDENCE = "REPLAY_EVIDENCE"
    CIPHER_SUITE = "CIPHER_SUITE"
    TRAFFIC_SELECTOR = "TRAFFIC_SELECTOR"
    METADATA_EXPOSURE = "METADATA_EXPOSURE"


class AuthoritativeReference(BaseModel):
    """Normative standards reference grounding the rule."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: str = Field(..., description="Document identifier, e.g. 'NIST SP 800-77 Rev. 1'")
    section: str = Field(..., description="Exact section, e.g. 'Section 5.1.2'")
    url: str | None = Field(None, description="Official NIST/IETF URL")
    normative_requirement: str = Field(..., description="Mandatory/Recommended requirement text")
    verification_date: str | None = Field(None, description="ISO timestamp of authoritative source verification")
    verified_by: str | None = Field(None, description="Author / Auditor identity")


class RemediationDirective(BaseModel):
    """Deterministic guidance and target configuration directives for remediation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    summary: str = Field(..., description="Human-readable remediation action summary")
    strongswan_directive: str | None = Field(None, description="Target strongSwan 5.9+ / swanctl syntax")
    target_config_key: str | None = Field(None, description="Configuration key, e.g. 'ike', 'esp', 'proposals'")
    guidance: str | None = Field(None, description="Detailed hardening advice")


class RuleAssertion(BaseModel):
    """Declarative assertion against normalized facts.

    Supports simple field-operator checks or compound all_of / any_of / not_condition logic.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    target_field: str | None = Field(None, description="Canonical fact key from FACT_FIELD_REGISTRY")
    operator: Operator | None = Field(None, description="Allowlisted comparison operator")
    expected_value: Any = Field(None, description="Target value or set of values")
    all_of: list[RuleAssertion] | None = Field(None, description="Conjunctive list of sub-assertions")
    any_of: list[RuleAssertion] | None = Field(None, description="Disjunctive list of sub-assertions")
    not_condition: RuleAssertion | None = Field(None, description="Negated sub-assertion")


class RuleApplicability(BaseModel):
    """Filter defining which entities or protocol handshakes the rule applies to."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    target_field: str | None = None
    operator: Operator | None = None
    expected_value: Any = None
    all_of: list[RuleApplicability] | None = None
    any_of: list[RuleApplicability] | None = None


class PolicyRule(BaseModel):
    """Complete, immutable declarative Policy-as-Code specification."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_id: str = Field(..., description="Stable rule identifier, e.g. 'POL-NIST-004'")
    rule_version: str = Field(..., description="Semver version string, e.g. '1.0.0'")
    title: str = Field(..., description="Human-readable short rule title")
    description: str = Field(..., description="Detailed technical explanation")
    category: FindingCategory
    profile: PolicyProfile
    authority_tier: AuthorityTier
    authoritative_reference: AuthoritativeReference
    evidence_requirements: list[str] = Field(..., description="Fact keys required to evaluate this rule")
    applicability: RuleApplicability | None = Field(None, description="Applicability condition")
    assertion: RuleAssertion = Field(..., description="Mandatory assertion that must hold for PASS")
    severity: Severity = Field(..., description="Severity on FAIL")
    root_cause_key: str = Field(..., description="Deduplication key for correlated findings in scoring")
    remediation: RemediationDirective
    threat_mapping_id: str | None = Field(None, description="ID of mapped threat scenario in catalog")
    status: RuleStatus = Field(default=RuleStatus.ACTIVE)

    def validate_field_references(self) -> None:
        """Validate that all target_field and evidence_requirement keys exist in FACT_FIELD_REGISTRY."""
        for req in self.evidence_requirements:
            if not is_known_fact_field(req):
                raise ValueError(f"Rule '{self.rule_id}' specifies unknown evidence requirement '{req}'")

        def check_assertion(ass: RuleAssertion) -> None:
            if ass.target_field and not is_known_fact_field(ass.target_field):
                raise ValueError(f"Rule '{self.rule_id}' asserts unknown fact field '{ass.target_field}'")
            if ass.all_of:
                for sub in ass.all_of:
                    check_assertion(sub)
            if ass.any_of:
                for sub in ass.any_of:
                    check_assertion(sub)
            if ass.not_condition:
                check_assertion(ass.not_condition)

        check_assertion(self.assertion)

    @property
    def authoritative_references(self) -> list[AuthoritativeReference]:
        return [self.authoritative_reference]


class PolicyBundle(BaseModel):
    """Collection of versioned policy rules bound to a specific compliance profile."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    bundle_id: str = Field(..., description="Identifier, e.g. 'bundle_nist_sp800_77'")
    bundle_version: str = Field(..., description="Version string, e.g. '1.0.0'")
    profile: PolicyProfile
    rules: list[PolicyRule]
    manifest_hash: str = Field(..., description="SHA-256 cryptographic digest of canonical rule JSON")

    @property
    def bundle_hash(self) -> str:
        return self.manifest_hash

    @property
    def profile_id(self) -> str:
        return self.profile.value

    @classmethod
    def create(
        cls,
        bundle_id: str,
        bundle_version: str,
        profile: PolicyProfile,
        rules: list[PolicyRule],
    ) -> PolicyBundle:
        """Create bundle computing deterministic manifest hash."""
        # Validate rules
        for r in rules:
            r.validate_field_references()

        # Sort rules by rule_id for determinism
        sorted_rules = sorted(rules, key=lambda x: (x.rule_id, x.rule_version))
        serialized = json.dumps(
            [r.model_dump() for r in sorted_rules],
            sort_keys=True,
            default=str,
        )
        m_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

        return cls(
            bundle_id=bundle_id,
            bundle_version=bundle_version,
            profile=profile,
            rules=sorted_rules,
            manifest_hash=m_hash,
        )
