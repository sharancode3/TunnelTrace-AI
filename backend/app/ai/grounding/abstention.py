"""Canonical Abstention Module for Grounded AI Analyst.

Enforces TunnelTrace AI's non-negotiable principle:
"I cannot verify this from the evidence currently available for this analysis."
If the retrieved evidence or standards do not support a factual answer,
the system MUST abstain rather than guess or invent facts.
"""

from __future__ import annotations

CANONICAL_ABSTENTION_MESSAGE = (
    "I cannot verify this from the evidence currently available for this analysis."
)

ABSTENTION_TRIGGER_KEYWORDS = [
    "cannot verify",
    "insufficient evidence",
    "not available in the passive capture",
    "evidence does not contain",
    "unsupported by the available capture",
    "cannot be determined from the provided",
]


class AbstentionDetector:
    """Detects whether model response is a legitimate grounded abstention."""

    @classmethod
    def is_abstention(cls, text: str) -> bool:
        t_lower = text.lower()
        return any(trigger in t_lower for trigger in ABSTENTION_TRIGGER_KEYWORDS)

    @classmethod
    def build_abstention_response(
        cls, reason: str = "Insufficient passive capture evidence"
    ) -> dict:
        return {
            "status": "INSUFFICIENT_EVIDENCE",
            "answer": CANONICAL_ABSTENTION_MESSAGE,
            "claims": [],
            "citations": [],
            "limitations": [f"Abstention invoked: {reason}"],
        }
