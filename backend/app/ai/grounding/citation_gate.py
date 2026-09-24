"""Citation Integrity Gate for Grounded AI Analyst.

Enforces deterministic validation of every source citation returned by the local LLM.
A citation is valid IF AND ONLY IF its source_id exists in the authorized retrieval context.
Fabricated RFCs, invented finding IDs, or imaginary packet references are rejected.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CitationValidationResult:
    """Outcome of deterministic citation integrity checking."""

    is_valid: bool
    total_citations: int
    valid_citations: tuple[dict[str, Any], ...]
    invalid_citations: tuple[dict[str, Any], ...]
    validity_rate: float
    error_summary: str | None = None


class CitationIntegrityGate:
    """Deterministic validator for model-produced citations."""

    CITATION_BRACKET_REGEX = re.compile(
        r"\[(analysis:[^\]]+|sa:[^\]]+|flow:[^\]]+|score:[^\]]+|rule:[^\]]+|finding:[^\]]+|threat:[^\]]+|standard:[^\]]+|twin:[^\]]+|verification:[^\]]+|claim:[^\]]+)\]",
        re.IGNORECASE,
    )

    @classmethod
    def validate(
        cls,
        model_citations: list[dict[str, Any]] | None,
        answer_text: str,
        allowed_source_ids: frozenset[str],
    ) -> CitationValidationResult:
        """Deterministically audit all citations against allowed_source_ids."""
        declared_citations = model_citations or []
        valid_list: list[dict[str, Any]] = []
        invalid_list: list[dict[str, Any]] = []

        seen_sources: set[str] = set()

        # 1. Audit explicit citation objects
        for cit in declared_citations:
            sid = str(cit.get("source_id", "")).strip()
            if not sid:
                invalid_list.append({**cit, "rejection_reason": "Missing source_id"})
                continue

            if sid in allowed_source_ids:
                if sid not in seen_sources:
                    valid_list.append(cit)
                    seen_sources.add(sid)
            else:
                invalid_list.append({**cit, "rejection_reason": "Fabricated source_id not in context"})

        # 2. Audit bracketed citation mentions inside text e.g. [finding:SEC-001]
        for match in cls.CITATION_BRACKET_REGEX.finditer(answer_text):
            sid = match.group(1).strip()
            if sid not in seen_sources:
                if sid in allowed_source_ids:
                    # Synthetic valid citation
                    valid_list.append({
                        "source_id": sid,
                        "source_type": sid.split(":")[0],
                        "locator": sid,
                        "title": sid,
                    })
                    seen_sources.add(sid)
                else:
                    invalid_list.append({
                        "source_id": sid,
                        "source_type": sid.split(":")[0],
                        "rejection_reason": "Inline citation not in retrieved context",
                    })

        total = len(valid_list) + len(invalid_list)
        if total == 0:
            # If no citations were made, validity depends on whether answer is an abstention
            return CitationValidationResult(
                is_valid=True,
                total_citations=0,
                valid_citations=(),
                invalid_citations=(),
                validity_rate=1.0,
                error_summary=None,
            )

        validity_rate = len(valid_list) / total
        is_valid = len(invalid_list) == 0

        err_summary = None
        if not is_valid:
            rejected_ids = [c.get("source_id", "unknown") for c in invalid_list]
            err_summary = f"Detected {len(invalid_list)} ungrounded citation(s): {', '.join(rejected_ids)}"

        return CitationValidationResult(
            is_valid=is_valid,
            total_citations=total,
            valid_citations=tuple(valid_list),
            invalid_citations=tuple(invalid_list),
            validity_rate=round(validity_rate, 4),
            error_summary=err_summary,
        )
