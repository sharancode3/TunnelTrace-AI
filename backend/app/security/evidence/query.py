"""Evidence Provenance Query & Resolver.

Enables interactive analysts to resolve complete upstream packet lineage
and downstream threat/scoring consequences from any given finding or fact.
"""

from __future__ import annotations

from typing import Any

from app.security.evidence.models import (
    EvidenceGraph,
    EvidenceNode,
    EvidenceRelationType,
)


class EvidenceProvenanceResolver:
    """Navigates and resolves specific lineage traces within the evidence graph."""

    def __init__(self, graph: EvidenceGraph) -> None:
        self.graph = graph
        self._nodes_by_id: dict[str, EvidenceNode] = {n.node_id: n for n in graph.nodes}
        self._incoming_edges: dict[str, list[tuple[str, str, dict]]] = {}
        self._outgoing_edges: dict[str, list[tuple[str, str, dict]]] = {}

        for e in graph.edges:
            self._outgoing_edges.setdefault(e.source_node_id, []).append(
                (e.target_node_id, e.relation.value, e.properties)
            )
            self._incoming_edges.setdefault(e.target_node_id, []).append(
                (e.source_node_id, e.relation.value, e.properties)
            )

    def resolve_finding_lineage(self, finding_id: str) -> dict[str, Any]:
        """Resolve full forensic provenance for an individual finding."""
        f_node_id = f"finding:{finding_id}"
        finding_node = self._nodes_by_id.get(f_node_id)
        if not finding_node:
            return {"error": f"Finding '{finding_id}' not found in evidence graph."}

        # 1. Direct Rule
        rules = []
        for src_id, rel, _ in self._incoming_edges.get(f_node_id, []):
            if rel == EvidenceRelationType.VIOLATES.value and src_id in self._nodes_by_id:
                rules.append(self._nodes_by_id[src_id].to_dict())

        # 2. Direct Facts and upstream Frames
        facts = []
        frame_nodes = []
        for src_id, rel, _ in self._incoming_edges.get(f_node_id, []):
            if rel == EvidenceRelationType.DERIVED_FROM.value and src_id in self._nodes_by_id:
                fact_node = self._nodes_by_id[src_id]
                facts.append(fact_node.to_dict())
                # Find frames that contributed to this fact
                for frame_src_id, frame_rel, _ in self._incoming_edges.get(src_id, []):
                    if frame_rel == EvidenceRelationType.DERIVED_FROM.value and frame_src_id in self._nodes_by_id:
                        frame_nodes.append(self._nodes_by_id[frame_src_id].to_dict())

        # 3. Downstream Threats, Deductions, Remediation
        threats = []
        deductions = []
        remediations = []
        for tgt_id, rel, _ in self._outgoing_edges.get(f_node_id, []):
            if tgt_id in self._nodes_by_id:
                tgt_node = self._nodes_by_id[tgt_id]
                if rel == EvidenceRelationType.MAPS_TO.value:
                    threats.append(tgt_node.to_dict())
                elif rel == EvidenceRelationType.DEDUCTS.value:
                    deductions.append(tgt_node.to_dict())
                elif rel == EvidenceRelationType.REMEDIATED_BY.value:
                    remediations.append(tgt_node.to_dict())

        return {
            "finding": finding_node.to_dict(),
            "capture_sha256": self.graph.capture_sha256,
            "policy_rules": rules,
            "security_facts": facts,
            "source_frames": frame_nodes,
            "mapped_threats": threats,
            "score_deductions": deductions,
            "remediation_guidance": remediations,
        }

    def extract_subgraph(self, root_node_id: str, depth: int = 3) -> EvidenceGraph:
        """Extract a local neighborhood subgraph around a specific evidence node."""
        visited_nodes: set[str] = set()
        frontier: set[str] = {root_node_id}

        for _ in range(depth):
            if not frontier:
                break
            next_frontier: set[str] = set()
            for nid in frontier:
                if nid in visited_nodes or nid not in self._nodes_by_id:
                    continue
                visited_nodes.add(nid)
                # Outgoing
                for tgt_id, _, _ in self._outgoing_edges.get(nid, []):
                    if tgt_id not in visited_nodes:
                        next_frontier.add(tgt_id)
                # Incoming
                for src_id, _, _ in self._incoming_edges.get(nid, []):
                    if src_id not in visited_nodes:
                        next_frontier.add(src_id)
            frontier = next_frontier

        sub_nodes = [self._nodes_by_id[nid] for nid in visited_nodes if nid in self._nodes_by_id]
        sub_edges = [
            e for e in self.graph.edges
            if e.source_node_id in visited_nodes and e.target_node_id in visited_nodes
        ]

        return EvidenceGraph(
            analysis_id=self.graph.analysis_id,
            capture_sha256=self.graph.capture_sha256,
            nodes=sub_nodes,
            edges=sub_edges,
        )
