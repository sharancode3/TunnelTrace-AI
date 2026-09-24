"""Deterministic Threat Matrix Mapper.

Maps active SecurityFindings to concrete ThreatInstances using the static,
pre-authored ThreatCatalog. Prohibits any generative hallucination of threats.
"""

from __future__ import annotations

from app.security.findings.models import SecurityFinding
from app.security.risk.models import Impact, RiskTier
from app.security.threats.catalog import find_threat_for_root_cause, get_threat_by_id
from app.security.threats.models import ThreatInstance


class ThreatMatrixEngine:
    """Deterministic mapper converting findings into operational ThreatInstances."""

    def __init__(self) -> None:
        self.catalog_hash = "threat_catalog_hash_canonical_v1"

    def map_findings(
        self,
        analysis_id: str,
        findings: list[SecurityFinding],
    ) -> list[ThreatInstance]:
        """Convenience signature for orchestration services."""
        return self.map_threats(findings)

    def map_threats(self, findings: list[SecurityFinding]) -> list[ThreatInstance]:
        """Convert findings into concrete threat instances."""
        threat_instances: list[ThreatInstance] = []

        for finding in findings:
            entry = None
            if finding.threat_mapping_id:
                entry = get_threat_by_id(finding.threat_mapping_id)
            if entry is None and finding.root_cause_key:
                entry = find_threat_for_root_cause(finding.root_cause_key)

            if entry is None:
                # Finding is legitimate but has no catalog mapping -> remains unmapped
                continue

            # Determine realized risk tier for this threat instance based on finding severity
            if finding.severity.value in ("CRITICAL",):
                realized_tier = RiskTier.CRITICAL
                realized_impact = Impact.HIGH
            elif finding.severity.value in ("HIGH",):
                realized_tier = RiskTier.HIGH
                realized_impact = Impact.HIGH
            elif finding.severity.value in ("MEDIUM",):
                realized_tier = RiskTier.MEDIUM
                realized_impact = Impact.MEDIUM
            else:
                realized_tier = RiskTier.LOW
                realized_impact = Impact.LOW

            instance = ThreatInstance(
                threat_id=entry.threat_id,
                threat_version=entry.version,
                finding_id=finding.finding_id,
                rule_id=finding.rule_id,
                threat_name=entry.name,
                affected_entity_id=finding.affected_entity_id,
                preconditions=entry.preconditions,
                exploit_vector=entry.attack_vector,
                cia_impact=entry.cia_impact,
                likelihood=entry.default_likelihood,
                impact=realized_impact,
                risk_tier=realized_tier,
                evidence_state=finding.evidence_state,
                authoritative_reference=entry.authoritative_reference,
                mitre_attack_id=entry.mitre_attack_id,
            )
            threat_instances.append(instance)

        return threat_instances
