"""Data Models for Authoritative Threat Catalog and Threat Instances."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.security.facts.models import EvidenceState
from app.security.risk.models import Impact, Likelihood, RiskTier


@dataclass(frozen=True)
class ThreatCatalogEntry:
    """Pre-authored, verified operational threat scenario in the static catalog."""

    threat_id: str
    version: str
    name: str
    description: str
    affected_asset: str
    preconditions: str
    attack_vector: str
    cia_impact: str
    default_likelihood: Likelihood
    default_impact: Impact
    mapped_root_cause_keys: tuple[str, ...]
    authoritative_reference: str
    mitre_attack_id: str | None = None  # None unless strictly verified


@dataclass(frozen=True)
class ThreatInstance:
    """Realized operational threat instance mapped deterministically from an active finding."""

    instance_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    threat_id: str = ""
    threat_version: str = "1.0.0"
    finding_id: str = ""
    rule_id: str = ""
    rule_version: str = "1.0.0"
    threat_name: str = ""
    affected_entity_id: str = ""
    affected_entity: str = ""
    preconditions: str = ""
    exploit_vector: str = ""
    attack_vector: str = ""
    cia_impact: str = ""
    likelihood: Likelihood = Likelihood.MEDIUM
    impact: Impact = Impact.HIGH
    risk_tier: RiskTier = RiskTier.HIGH
    evidence_state: EvidenceState | str = EvidenceState.VERIFIED
    authoritative_reference: str = ""
    mitre_attack_id: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not self.attack_vector and self.exploit_vector:
            object.__setattr__(self, "attack_vector", self.exploit_vector)
        elif not self.exploit_vector and self.attack_vector:
            object.__setattr__(self, "exploit_vector", self.attack_vector)
        if not self.affected_entity and self.affected_entity_id:
            object.__setattr__(self, "affected_entity", self.affected_entity_id)
        elif not self.affected_entity_id and self.affected_entity:
            object.__setattr__(self, "affected_entity_id", self.affected_entity)

    def to_dict(self) -> dict[str, Any]:
        return {
            "instance_id": self.instance_id,
            "threat_id": self.threat_id,
            "threat_version": self.threat_version,
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "threat_name": self.threat_name,
            "affected_entity_id": self.affected_entity_id,
            "preconditions": self.preconditions,
            "exploit_vector": self.exploit_vector,
            "cia_impact": self.cia_impact,
            "likelihood": self.likelihood.value,
            "impact": self.impact.value,
            "risk_tier": self.risk_tier.value,
            "evidence_state": self.evidence_state.value,
            "authoritative_reference": self.authoritative_reference,
            "mitre_attack_id": self.mitre_attack_id,
            "created_at": self.created_at.isoformat(),
        }
