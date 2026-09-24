"""Deterministic Query Intent Router and Entity Resolver for Grounded AI Analyst.

Parses analyst queries to identify targeted forensic entities (finding IDs, rule IDs,
SPIs, frame numbers, SA references) and maps query intent without calling external tools.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class QueryIntent(str, Enum):
    """Categorized intent for bounded retrieval and response formulation."""

    ANALYSIS_EXPLANATION = "ANALYSIS_EXPLANATION"
    FINDING_EXPLANATION = "FINDING_EXPLANATION"
    EVIDENCE_LOOKUP = "EVIDENCE_LOOKUP"
    SCORE_EXPLANATION = "SCORE_EXPLANATION"
    PROTOCOL_EXPLANATION = "PROTOCOL_EXPLANATION"
    TRAFFIC_ML_EXPLANATION = "TRAFFIC_ML_EXPLANATION"
    STANDARD_EXPLANATION = "STANDARD_EXPLANATION"
    REMEDIATION_EXPLANATION = "REMEDIATION_EXPLANATION"
    BEFORE_AFTER_COMPARISON = "BEFORE_AFTER_COMPARISON"
    GENERAL_IPSEC_CONCEPT = "GENERAL_IPSEC_CONCEPT"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"


@dataclass(frozen=True)
class ResolvedEntities:
    """Forensic entities deterministically extracted from analyst query text."""

    finding_ids: tuple[str, ...]
    rule_ids: tuple[str, ...]
    spis: tuple[str, ...]
    standard_codes: tuple[str, ...]


@dataclass(frozen=True)
class QueryRoutingResult:
    """Route decision and parsed entity scope for the query."""

    intent: QueryIntent
    entities: ResolvedEntities
    cleaned_query: str


class QueryRouter:
    """Deterministic, rule-based entity resolver and intent classifier."""

    FINDING_REGEX = re.compile(r"\b(SEC-[A-Z0-9_\-]+)\b", re.IGNORECASE)
    RULE_REGEX = re.compile(r"\b(RULE-[A-Z0-9_\-]+)\b", re.IGNORECASE)
    SPI_REGEX = re.compile(r"\b(0x[0-9a-fA-F]{8})\b")
    STANDARD_REGEX = re.compile(r"\b(RFC\s*\d{4}|NIST\s*SP\s*800-\d+)\b", re.IGNORECASE)

    OUT_OF_SCOPE_KEYWORDS = [
        "weather", "recipe", "stock price", "sports", "python code for",
        "write a poem", "who won", "bitcoin", "movie", "translate to french",
    ]

    @classmethod
    def resolve_entities(cls, query: str) -> ResolvedEntities:
        findings = tuple(m.upper() for m in cls.FINDING_REGEX.findall(query))
        rules = tuple(m.upper() for m in cls.RULE_REGEX.findall(query))
        spis = tuple(m.lower() for m in cls.SPI_REGEX.findall(query))
        standards = tuple(m.upper().replace("  ", " ") for m in cls.STANDARD_REGEX.findall(query))

        return ResolvedEntities(
            finding_ids=findings,
            rule_ids=rules,
            spis=spis,
            standard_codes=standards,
        )

    @classmethod
    def classify_intent(cls, query: str, entities: ResolvedEntities) -> QueryIntent:
        q_lower = query.lower()

        # Check out-of-scope
        for kw in cls.OUT_OF_SCOPE_KEYWORDS:
            if kw in q_lower:
                return QueryIntent.OUT_OF_SCOPE

        # If explicit finding ID present
        if entities.finding_ids:
            if "evidence" in q_lower or "proof" in q_lower or "packet" in q_lower:
                return QueryIntent.EVIDENCE_LOOKUP
            if "fix" in q_lower or "remediat" in q_lower:
                return QueryIntent.REMEDIATION_EXPLANATION
            return QueryIntent.FINDING_EXPLANATION

        # If explicit rule ID present
        if entities.rule_ids:
            return QueryIntent.FINDING_EXPLANATION

        # Before/after comparison
        if "before" in q_lower and "after" in q_lower or "compare" in q_lower:
            return QueryIntent.BEFORE_AFTER_COMPARISON

        # Remediation / Twin / Fix
        if any(w in q_lower for w in ["remediat", "fix", "rollback", "twin", "closed-loop", "applied"]):
            return QueryIntent.REMEDIATION_EXPLANATION

        # Score / Posture / Deductions
        if any(w in q_lower for w in ["score", "posture", "deduction", "points", "grade"]):
            return QueryIntent.SCORE_EXPLANATION

        # Traffic / Flow / ML / Application
        if any(w in q_lower for w in ["traffic", "classify", "flow", "xgboost", "cnn", "shap", "entropy", "ood"]):
            return QueryIntent.TRAFFIC_ML_EXPLANATION

        # Evidence / Packet / Frame
        if any(w in q_lower for w in ["evidence", "packet", "frame", "pcap", "hex"]):
            return QueryIntent.EVIDENCE_LOOKUP

        # Protocol / SA / IKE / Transforms
        if any(w in q_lower for w in ["ike", "ikev1", "ikev2", "child sa", "transform", "cipher", "pfs", "dh group", "spi"]):
            return QueryIntent.PROTOCOL_EXPLANATION

        # Standard / RFC / NIST
        if any(w in q_lower for w in ["rfc", "nist", "standard", "normative", "requirement"]):
            return QueryIntent.STANDARD_EXPLANATION

        return QueryIntent.ANALYSIS_EXPLANATION

    @classmethod
    def route(cls, query: str) -> QueryRoutingResult:
        entities = cls.resolve_entities(query)
        intent = cls.classify_intent(query, entities)
        return QueryRoutingResult(
            intent=intent,
            entities=entities,
            cleaned_query=query.strip(),
        )
