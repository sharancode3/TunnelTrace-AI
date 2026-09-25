"""Schemas for Offline-First Threat Intelligence Context (CISA KEV & FIRST EPSS).

Strictly isolates supplemental external context from deterministic policy findings.
Enforces explicit status codes (PRESENT, NOT_PRESENT_IN_THIS_SNAPSHOT, STALE, UNAVAILABLE, NOT_CHECKED).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class FeedStatus(str, Enum):
    """Explicit status of a CVE in a threat intelligence feed snapshot."""

    PRESENT = "PRESENT"
    NOT_PRESENT_IN_THIS_SNAPSHOT = "NOT_PRESENT_IN_THIS_SNAPSHOT"
    NOT_CHECKED = "NOT_CHECKED"
    STALE = "STALE"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True)
class CisaKevRecord:
    """Official CISA Known Exploited Vulnerabilities (KEV) entry."""

    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str
    required_action: str
    due_date: str
    known_ransomware_campaign_use: str = "Unknown"
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "vendor_project": self.vendor_project,
            "product": self.product,
            "vulnerability_name": self.vulnerability_name,
            "date_added": self.date_added,
            "short_description": self.short_description,
            "required_action": self.required_action,
            "due_date": self.due_date,
            "known_ransomware_campaign_use": self.known_ransomware_campaign_use,
            "notes": self.notes,
        }


@dataclass(frozen=True)
class EpssRecord:
    """Official FIRST Exploit Prediction Scoring System (EPSS) entry."""

    cve_id: str
    epss_score: float  # [0.0, 1.0] probability of exploitation activity in next 30 days
    epss_percentile: float  # [0.0, 1.0] percentile rank relative to all scored CVEs
    model_version: str
    date: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "epss_score": round(self.epss_score, 5),
            "epss_percentile": round(self.epss_percentile, 4),
            "model_version": self.model_version,
            "date": self.date,
        }


@dataclass(frozen=True)
class ThreatIntelLookupResult:
    """Composite lookup result binding source lineage and epistemic non-proof disclaimers."""

    cve_id: str
    cisa_kev_status: FeedStatus
    cisa_kev_record: CisaKevRecord | None = None
    cisa_kev_as_of: str | None = None
    cisa_kev_digest: str | None = None
    epss_status: FeedStatus = FeedStatus.NOT_CHECKED
    epss_record: EpssRecord | None = None
    epss_as_of: str | None = None
    epss_digest: str | None = None
    disclaimer: str = (
        "External threat intelligence is supplemental context only. CISA KEV membership indicates "
        "evidence of active exploitation in the wild, NOT that this observed gateway is affected or compromised. "
        "FIRST EPSS is an empirical population-level probability estimate of observed exploitation activity "
        "within 30 days, NOT target-specific vulnerability probability. Neither metric modifies deterministic policy scores."
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "cisa_kev_status": self.cisa_kev_status.value,
            "cisa_kev_record": self.cisa_kev_record.to_dict() if self.cisa_kev_record else None,
            "cisa_kev_as_of": self.cisa_kev_as_of,
            "cisa_kev_digest": self.cisa_kev_digest,
            "epss_status": self.epss_status.value,
            "epss_record": self.epss_record.to_dict() if self.epss_record else None,
            "epss_as_of": self.epss_as_of,
            "epss_digest": self.epss_digest,
            "disclaimer": self.disclaimer,
        }
