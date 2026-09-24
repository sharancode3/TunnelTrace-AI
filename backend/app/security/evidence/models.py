"""Domain models for the Forensic Evidence & Provenance Graph.

Maintains an unbroken, cryptographically rooted chain of custody:
Capture (SHA-256) -> Frame -> Observation -> Normalized Fact -> Rule ->
Evaluation -> Finding -> Threat / Risk -> Score Deduction -> Remediation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class EvidenceNodeType(str, Enum):
    """Categorical types of nodes in the forensic provenance graph."""

    CAPTURE = "CAPTURE"
    FRAME = "FRAME"
    PROTOCOL_OBSERVATION = "PROTOCOL_OBSERVATION"
    SECURITY_FACT = "SECURITY_FACT"
    IKE_SESSION = "IKE_SESSION"
    IKE_SA = "IKE_SA"
    CHILD_SA = "CHILD_SA"
    ESP_FLOW = "ESP_FLOW"
    ML_PREDICTION = "ML_PREDICTION"
    POLICY_BUNDLE = "POLICY_BUNDLE"
    POLICY_RULE = "POLICY_RULE"
    COMPLIANCE_EVALUATION = "COMPLIANCE_EVALUATION"
    SECURITY_FINDING = "SECURITY_FINDING"
    THREAT = "THREAT"
    RISK_RESULT = "RISK_RESULT"
    SCORE_COMPONENT = "SCORE_COMPONENT"
    FINGERPRINTABILITY_COMPONENT = "FINGERPRINTABILITY_COMPONENT"
    REMEDIATION_REFERENCE = "REMEDIATION_REFERENCE"
    EVIDENCE_GAP = "EVIDENCE_GAP"


class EvidenceRelationType(str, Enum):
    """Defensible relational edges between evidence nodes."""

    OBSERVED_IN = "OBSERVED_IN"          # Observation was observed in Frame/Capture
    DERIVED_FROM = "DERIVED_FROM"        # Fact derived from Observation/Frame
    EVALUATED_AGAINST = "EVALUATED_AGAINST"  # Fact evaluated against Policy Rule
    VIOLATES = "VIOLATES"                # Finding violates Policy Rule
    SATISFIES = "SATISFIES"              # Evaluation satisfies Policy Rule
    MAPS_TO = "MAPS_TO"                  # Finding maps to Threat / Risk Tier
    DEDUCTS = "DEDUCTS"                  # Finding causes Score Deduction
    REMEDIATED_BY = "REMEDIATED_BY"      # Finding addressed by Remediation
    GAP_IDENTIFIED = "GAP_IDENTIFIED"    # Rule evaluation identified Evidence Gap
    MEASURES = "MEASURES"                # Fingerprintability measures ESP Flow
    CONTAINS = "CONTAINS"                # Container relationship (Capture contains Frame)
    REFERENCES = "REFERENCES"            # General reference edge


@dataclass(frozen=True)
class EvidenceNode:
    """Individual vertex in the provenance graph."""

    node_id: str
    node_type: EvidenceNodeType
    label: str
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["node_type"] = self.node_type.value
        return data


@dataclass(frozen=True)
class EvidenceEdge:
    """Directed relationship linking source node to target node."""

    source_node_id: str
    target_node_id: str
    relation: EvidenceRelationType
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["relation"] = self.relation.value
        return data


@dataclass
class EvidenceGraph:
    """Relational provenance graph for an analysis."""

    analysis_id: str
    capture_sha256: str
    nodes: list[EvidenceNode] = field(default_factory=list)
    edges: list[EvidenceEdge] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "analysis_id": self.analysis_id,
            "capture_sha256": self.capture_sha256,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }

    def to_react_flow(self) -> dict[str, list[dict]]:
        """Export nodes and edges formatted for React Flow interactive canvas."""
        rf_nodes = []
        rf_edges = []

        # Simple hierarchical layout tier based on node type
        tier_y = {
            EvidenceNodeType.CAPTURE: 0,
            EvidenceNodeType.FRAME: 100,
            EvidenceNodeType.PROTOCOL_OBSERVATION: 200,
            EvidenceNodeType.SECURITY_FACT: 300,
            EvidenceNodeType.POLICY_RULE: 300,
            EvidenceNodeType.COMPLIANCE_EVALUATION: 400,
            EvidenceNodeType.EVIDENCE_GAP: 400,
            EvidenceNodeType.SECURITY_FINDING: 500,
            EvidenceNodeType.THREAT: 600,
            EvidenceNodeType.RISK_RESULT: 600,
            EvidenceNodeType.SCORE_COMPONENT: 700,
            EvidenceNodeType.REMEDIATION_REFERENCE: 700,
            EvidenceNodeType.FINGERPRINTABILITY_COMPONENT: 450,
            EvidenceNodeType.ESP_FLOW: 250,
        }

        # Track x-offset per tier for clean positioning
        tier_counts: dict[int, int] = {}
        for n in self.nodes:
            y = tier_y.get(n.node_type, 350)
            x_idx = tier_counts.get(y, 0)
            tier_counts[y] = x_idx + 1

            rf_nodes.append({
                "id": n.node_id,
                "type": n.node_type.value.lower(),
                "position": {"x": x_idx * 260 + 50, "y": y},
                "data": {
                    "label": n.label,
                    "nodeType": n.node_type.value,
                    **n.properties,
                },
            })

        for i, e in enumerate(self.edges):
            rf_edges.append({
                "id": f"e-{i}-{e.source_node_id}-{e.target_node_id}",
                "source": e.source_node_id,
                "target": e.target_node_id,
                "label": e.relation.value,
                "animated": e.relation in (EvidenceRelationType.VIOLATES, EvidenceRelationType.DEDUCTS),
                "data": e.properties,
            })

        return {"nodes": rf_nodes, "edges": rf_edges}
