"""Offline-First Threat Intelligence Ingestion and Context Service.

Maintains local verified snapshots of CISA KEV and FIRST EPSS data.
Provides explicit status reporting (PRESENT, NOT_PRESENT_IN_THIS_SNAPSHOT, STALE, UNAVAILABLE)
with SHA-256 integrity digests and strict non-proof boundaries.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.security.threat_intel.schemas import (
    CisaKevRecord,
    EpssRecord,
    FeedStatus,
    ThreatIntelLookupResult,
)

logger = logging.getLogger(__name__)


class ThreatIntelService:
    """Service providing offline-first threat intelligence context."""

    def __init__(self, data_dir: Path | str | None = None, stale_threshold_days: int = 90) -> None:
        if data_dir:
            self.data_dir = Path(data_dir)
        else:
            self.data_dir = Path(__file__).resolve().parent / "data"

        self.stale_threshold_days = stale_threshold_days
        self._cisa_kev_records: dict[str, CisaKevRecord] = {}
        self._epss_records: dict[str, EpssRecord] = {}

        self.cisa_kev_as_of: str | None = None
        self.cisa_kev_digest: str | None = None
        self.epss_as_of: str | None = None
        self.epss_digest: str | None = None

        self._cisa_kev_loaded = False
        self._epss_loaded = False

        self._load_snapshots()

    def _load_snapshots(self) -> None:
        """Load and digest local snapshot files."""
        kev_path = self.data_dir / "cisa_kev_snapshot.json"
        if kev_path.exists():
            try:
                raw_bytes = kev_path.read_bytes()
                self.cisa_kev_digest = hashlib.sha256(raw_bytes).hexdigest()
                payload = json.loads(raw_bytes.decode("utf-8"))
                self.cisa_kev_as_of = payload.get("dateReleased")

                for item in payload.get("vulnerabilities", []):
                    cve = item.get("cveID", "").strip().upper()
                    if cve:
                        self._cisa_kev_records[cve] = CisaKevRecord(
                            cve_id=cve,
                            vendor_project=item.get("vendorProject", "Unknown"),
                            product=item.get("product", "Unknown"),
                            vulnerability_name=item.get("vulnerabilityName", ""),
                            date_added=item.get("dateAdded", ""),
                            short_description=item.get("shortDescription", ""),
                            required_action=item.get("requiredAction", ""),
                            due_date=item.get("dueDate", ""),
                            known_ransomware_campaign_use=item.get("knownRansomwareCampaignUse", "Unknown"),
                            notes=item.get("notes", ""),
                        )
                self._cisa_kev_loaded = True
                logger.info("Loaded %d CISA KEV records (digest=%s).", len(self._cisa_kev_records), self.cisa_kev_digest[:8])
            except Exception as e:
                logger.error("Failed to load CISA KEV snapshot: %s", e)
                self._cisa_kev_loaded = False
        else:
            logger.warning("CISA KEV snapshot file not found at %s", kev_path)

        epss_path = self.data_dir / "epss_snapshot.json"
        if epss_path.exists():
            try:
                raw_bytes = epss_path.read_bytes()
                self.epss_digest = hashlib.sha256(raw_bytes).hexdigest()
                payload = json.loads(raw_bytes.decode("utf-8"))
                self.epss_as_of = payload.get("score_date")
                model_ver = payload.get("model_version", "v2023.03.01")

                for item in payload.get("data", []):
                    cve = item.get("cve", "").strip().upper()
                    if cve:
                        try:
                            score = float(item.get("epss", 0.0))
                            perc = float(item.get("percentile", 0.0))
                        except (ValueError, TypeError):
                            score, perc = 0.0, 0.0
                        self._epss_records[cve] = EpssRecord(
                            cve_id=cve,
                            epss_score=score,
                            epss_percentile=perc,
                            model_version=model_ver,
                            date=self.epss_as_of or "",
                        )
                self._epss_loaded = True
                logger.info("Loaded %d EPSS records (digest=%s).", len(self._epss_records), self.epss_digest[:8])
            except Exception as e:
                logger.error("Failed to load EPSS snapshot: %s", e)
                self._epss_loaded = False
        else:
            logger.warning("EPSS snapshot file not found at %s", epss_path)

    def _is_date_stale(self, date_str: str | None) -> bool:
        """Check if an ISO/RFC date string exceeds the staleness threshold."""
        if not date_str:
            return True
        try:
            # Parse prefix YYYY-MM-DD
            clean_date = date_str[:10]
            dt = datetime.strptime(clean_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            delta = now - dt
            return delta.days > self.stale_threshold_days
        except Exception:
            return False

    def lookup_cve(self, cve_id: str) -> ThreatIntelLookupResult:
        """Look up threat intelligence context for a given CVE with explicit lineage."""
        cve_clean = cve_id.strip().upper()

        # 1. CISA KEV evaluation
        if not self._cisa_kev_loaded:
            kev_status = FeedStatus.UNAVAILABLE
            kev_record = None
        elif cve_clean in self._cisa_kev_records:
            if self._is_date_stale(self.cisa_kev_as_of):
                kev_status = FeedStatus.STALE
            else:
                kev_status = FeedStatus.PRESENT
            kev_record = self._cisa_kev_records[cve_clean]
        else:
            kev_status = FeedStatus.NOT_PRESENT_IN_THIS_SNAPSHOT
            kev_record = None

        # 2. FIRST EPSS evaluation
        if not self._epss_loaded:
            epss_status = FeedStatus.UNAVAILABLE
            epss_record = None
        elif cve_clean in self._epss_records:
            if self._is_date_stale(self.epss_as_of):
                epss_status = FeedStatus.STALE
            else:
                epss_status = FeedStatus.PRESENT
            epss_record = self._epss_records[cve_clean]
        else:
            epss_status = FeedStatus.NOT_PRESENT_IN_THIS_SNAPSHOT
            epss_record = None

        return ThreatIntelLookupResult(
            cve_id=cve_clean,
            cisa_kev_status=kev_status,
            cisa_kev_record=kev_record,
            cisa_kev_as_of=self.cisa_kev_as_of,
            cisa_kev_digest=self.cisa_kev_digest,
            epss_status=epss_status,
            epss_record=epss_record,
            epss_as_of=self.epss_as_of,
            epss_digest=self.epss_digest,
        )

    def lookup_multiple_cves(self, cve_ids: list[str]) -> list[ThreatIntelLookupResult]:
        """Look up multiple CVEs in sequence."""
        return [self.lookup_cve(cve) for cve in cve_ids]
