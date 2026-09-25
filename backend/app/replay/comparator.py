"""Deterministic and Semantic Comparators for Replay and Evidence Chain.

Enforces strict separation between:
1. Forensic Re-Analysis: Exact deterministic comparison of protocol facts, reconstructed
   entities, security findings, and score invariants over identical capture bytes,
   normalizing volatile fields (database UUIDs, wall-clock timestamps, worker task IDs).
2. Scenario Replay: Semantic assertion comparison over live strongSwan testbed executions,
   explicitly accounting for runtime variance (ephemeral SPIs, nonces, timestamps, jitter).
"""

from __future__ import annotations

from enum import Enum
import logging
from typing import Any

logger = logging.getLogger(__name__)


class ReplayStatus(str, Enum):
    """Execution and verification status for forensic and scenario replays."""

    EXACT_MATCH = "EXACT_MATCH"
    SEMANTIC_MATCH = "SEMANTIC_MATCH"
    DISCREPANCY_DETECTED = "DISCREPANCY_DETECTED"
    ENVIRONMENT_MISMATCH = "ENVIRONMENT_MISMATCH"


# Documented volatile metadata fields excluded from forensic semantic comparison
VOLATILE_FIELDS = {
    "id",
    "analysis_id",
    "capture_id",
    "created_at",
    "started_at",
    "completed_at",
    "frame_offset",  # Can vary if capture file header packaging differs slightly across tools
    "task_id",
    "job_id",
}


class ForensicReplayComparator:
    """Compares two forensic analysis runs performed over the exact same packet capture artifact."""

    @classmethod
    def compare_runs(
        cls,
        parent_data: dict[str, Any],
        child_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Performs itemized deterministic comparison between parent and child forensic analyses.

        Args:
            parent_data: Extracted parent facts, reconstruction, findings, and scores.
            child_data: Extracted child facts, reconstruction, findings, and scores.

        Returns:
            dict containing:
            - comparison_status: "EXACT_MATCH" or "DISCREPANCY_DETECTED"
            - differences: dict of discrepancies broken down by component
            - summary: text summary
            - metrics: matching counters and percentages
        """
        differences: dict[str, list[dict[str, Any]]] = {
            "protocol_facts": [],
            "ike_sessions": [],
            "child_sas": [],
            "esp_flows": [],
            "compliance_evaluations": [],
            "security_findings": [],
            "score_assessment": [],
        }

        # 1. Compare Protocol Observations / Facts
        parent_facts = parent_data.get("observations", [])
        child_facts = child_data.get("observations", [])

        # Index by (frame_number, category, field_name)
        def fact_key(f: dict[str, Any]) -> tuple:
            return (
                f.get("frame_number"),
                f.get("protocol"),
                f.get("category"),
                f.get("field_name"),
            )

        p_fact_map = {fact_key(f): f for f in parent_facts}
        c_fact_map = {fact_key(f): f for f in child_facts}

        all_fact_keys = sorted(set(p_fact_map.keys()) | set(c_fact_map.keys()), key=lambda x: (x[0] or 0, str(x[1]), str(x[2]), str(x[3])))

        facts_matched = 0
        for k in all_fact_keys:
            p_val = p_fact_map.get(k)
            c_val = c_fact_map.get(k)
            if not p_val or not c_val:
                differences["protocol_facts"].append({
                    "key": list(k),
                    "parent_present": bool(p_val),
                    "child_present": bool(c_val),
                    "reason": "Fact missing in one run",
                })
            else:
                # Compare normalized value and evidence state
                if (p_val.get("normalized_value") != c_val.get("normalized_value") or
                        p_val.get("evidence_state") != c_val.get("evidence_state")):
                    differences["protocol_facts"].append({
                        "key": list(k),
                        "parent_value": p_val.get("normalized_value"),
                        "child_value": c_val.get("normalized_value"),
                        "parent_state": p_val.get("evidence_state"),
                        "child_state": c_val.get("evidence_state"),
                        "reason": "Normalized fact value or evidence state discrepancy",
                    })
                else:
                    facts_matched += 1

        # 2. Compare IKE Sessions
        p_ike = parent_data.get("ike_sessions", [])
        c_ike = child_data.get("ike_sessions", [])
        if len(p_ike) != len(c_ike):
            differences["ike_sessions"].append({
                "reason": "IKE session count mismatch",
                "parent_count": len(p_ike),
                "child_count": len(c_ike),
            })
        else:
            for i, (p_s, c_s) in enumerate(zip(p_ike, c_ike)):
                for check_field in ("initiator_spi", "responder_spi", "version", "chosen_encryption", "chosen_integrity", "chosen_dh_group", "chosen_prf"):
                    if p_s.get(check_field) != c_s.get(check_field):
                        differences["ike_sessions"].append({
                            "session_index": i,
                            "field": check_field,
                            "parent": p_s.get(check_field),
                            "child": c_s.get(check_field),
                        })

        # 3. Compare Child SAs
        p_sa = parent_data.get("child_sas", [])
        c_sa = child_data.get("child_sas", [])
        if len(p_sa) != len(c_sa):
            differences["child_sas"].append({
                "reason": "Child SA count mismatch",
                "parent_count": len(p_sa),
                "child_count": len(c_sa),
            })
        else:
            for i, (p_c, c_c) in enumerate(zip(p_sa, c_sa)):
                for check_field in ("inbound_spi", "outbound_spi", "mode", "protocol", "encryption_algorithm", "integrity_algorithm"):
                    if p_c.get(check_field) != c_c.get(check_field):
                        differences["child_sas"].append({
                            "sa_index": i,
                            "field": check_field,
                            "parent": p_c.get(check_field),
                            "child": c_c.get(check_field),
                        })

        # 4. Compare ESP Flows
        p_flows = parent_data.get("flows", [])
        c_flows = child_data.get("flows", [])
        if len(p_flows) != len(c_flows):
            differences["esp_flows"].append({
                "reason": "ESP flow count mismatch",
                "parent_count": len(p_flows),
                "child_count": len(c_flows),
            })
        else:
            for i, (p_f, c_f) in enumerate(zip(p_flows, c_flows)):
                for check_field in ("spi", "reverse_spi", "packet_count", "byte_count"):
                    if p_f.get(check_field) != c_f.get(check_field):
                        differences["esp_flows"].append({
                            "flow_index": i,
                            "field": check_field,
                            "parent": p_f.get(check_field),
                            "child": c_f.get(check_field),
                        })

        # 5. Compare Compliance Evaluations
        p_eval = parent_data.get("evaluations", [])
        c_eval = child_data.get("evaluations", [])
        p_eval_map = {(e.get("rule_id"), e.get("subject_id")): e.get("compliance_state") for e in p_eval}
        c_eval_map = {(e.get("rule_id"), e.get("subject_id")): e.get("compliance_state") for e in c_eval}
        for k, p_state in p_eval_map.items():
            c_state = c_eval_map.get(k)
            if p_state != c_state:
                differences["compliance_evaluations"].append({
                    "rule_id": k[0],
                    "subject_id": k[1],
                    "parent_state": p_state,
                    "child_state": c_state,
                })

        # 6. Compare Security Findings
        p_find = parent_data.get("findings", [])
        c_find = child_data.get("findings", [])
        p_find_hashes = sorted([f.get("record_hash") for f in p_find if f.get("record_hash")])
        c_find_hashes = sorted([f.get("record_hash") for f in c_find if f.get("record_hash")])
        if p_find_hashes != c_find_hashes:
            differences["security_findings"].append({
                "reason": "Finding record hashes mismatch",
                "parent_hashes": p_find_hashes,
                "child_hashes": c_find_hashes,
            })

        # 7. Compare Score Posture
        p_score = parent_data.get("score", {})
        c_score = child_data.get("score", {})
        if p_score and c_score:
            if p_score.get("overall_score") != c_score.get("overall_score"):
                differences["score_assessment"].append({
                    "field": "overall_score",
                    "parent": p_score.get("overall_score"),
                    "child": c_score.get("overall_score"),
                })
            if p_score.get("raw_score") != c_score.get("raw_score"):
                differences["score_assessment"].append({
                    "field": "raw_score",
                    "parent": p_score.get("raw_score"),
                    "child": c_score.get("raw_score"),
                })

        # Filter empty difference categories
        active_diffs = {k: v for k, v in differences.items() if v}
        has_discrepancy = len(active_diffs) > 0

        status = "DISCREPANCY_DETECTED" if has_discrepancy else "EXACT_MATCH"
        summary = (
            f"Forensic re-analysis verified exact match across {facts_matched} protocol facts, "
            f"{len(p_sa)} Child SAs, {len(p_find)} findings, and posture score {p_score.get('overall_score')}."
            if not has_discrepancy
            else f"Forensic re-analysis detected discrepancies in: {', '.join(active_diffs.keys())}."
        )

        return {
            "comparison_status": status,
            "differences": active_diffs if has_discrepancy else None,
            "summary": summary,
            "metrics": {
                "parent_fact_count": len(parent_facts),
                "child_fact_count": len(child_facts),
                "matched_facts": facts_matched,
                "parent_findings_count": len(p_find),
                "child_findings_count": len(c_find),
                "overall_score_parent": p_score.get("overall_score"),
                "overall_score_child": c_score.get("overall_score"),
            },
        }


class ScenarioReplayComparator:
    """Compares two live strongSwan lab executions of the same scenario definition."""

    @classmethod
    def compare_manifests(
        cls,
        parent_manifest: dict[str, Any],
        child_manifest: dict[str, Any],
    ) -> dict[str, Any]:
        """Compares documented semantic assertions between two lab testbed runs.

        Understands that live executions naturally differ in:
        - Wall-clock timestamps (started_at_utc, ended_at_utc)
        - Ephemeral runtime nonces and SPIs
        - Packet arrival timings and wire jitter

        Asserts that:
        - scenario_id and scenario_version match exactly.
        - scenario_sha256 matches.
        - canonical_redacted_config_digest matches.
        - sa_established state matches.
        - traffic_probe_passed matches.
        - validation_status matches.
        """
        discrepancies: list[str] = []

        # Scenario specification
        if parent_manifest.get("scenario_id") != child_manifest.get("scenario_id"):
            discrepancies.append(
                f"Scenario ID mismatch: parent '{parent_manifest.get('scenario_id')}' vs child '{child_manifest.get('scenario_id')}'"
            )

        if parent_manifest.get("scenario_version") != child_manifest.get("scenario_version"):
            discrepancies.append(
                f"Scenario version mismatch: parent '{parent_manifest.get('scenario_version')}' vs child '{child_manifest.get('scenario_version')}'"
            )

        if parent_manifest.get("scenario_sha256") and child_manifest.get("scenario_sha256"):
            if parent_manifest.get("scenario_sha256") != child_manifest.get("scenario_sha256"):
                discrepancies.append("Scenario specification SHA-256 differs between parent and child")

        # Effective configuration digest
        p_cfg = parent_manifest.get("canonical_config_digest") or parent_manifest.get("config_hashes")
        c_cfg = child_manifest.get("canonical_config_digest") or child_manifest.get("config_hashes")
        if p_cfg and c_cfg and p_cfg != c_cfg:
            discrepancies.append("Effective canonical configuration digest differs")

        # Semantic SA and traffic outcomes
        if parent_manifest.get("sa_established") != child_manifest.get("sa_established"):
            discrepancies.append(
                f"SA establishment mismatch: parent sa_established={parent_manifest.get('sa_established')} "
                f"vs child sa_established={child_manifest.get('sa_established')}"
            )

        if parent_manifest.get("traffic_probe_passed") != child_manifest.get("traffic_probe_passed"):
            discrepancies.append(
                f"Traffic probe mismatch: parent probe={parent_manifest.get('traffic_probe_passed')} "
                f"vs child probe={child_manifest.get('traffic_probe_passed')}"
            )

        if parent_manifest.get("validation_status") != child_manifest.get("validation_status"):
            discrepancies.append(
                f"Validation status mismatch: parent status={parent_manifest.get('validation_status')} "
                f"vs child status={child_manifest.get('validation_status')}"
            )

        # Check for environment failure / mismatch
        child_status = child_manifest.get("validation_status")
        is_incompatible = child_manifest.get("environment_compatibility", {}).get("is_compatible") is False
        if child_status == "BLOCKED" or is_incompatible or "environment" in str(child_manifest.get("status_summary", "")).lower():
            return {
                "comparison_status": ReplayStatus.ENVIRONMENT_MISMATCH.value,
                "differences": {"errors": discrepancies or ["Testbed environment prerequisites missing or failed."]},
                "summary": f"Scenario replay blocked by environment mismatch: {child_manifest.get('status_summary')}",
                "metrics": {
                    "sa_established_parent": parent_manifest.get("sa_established"),
                    "sa_established_child": child_manifest.get("sa_established"),
                    "traffic_passed_parent": parent_manifest.get("traffic_probe_passed"),
                    "traffic_passed_child": child_manifest.get("traffic_probe_passed"),
                },
            }

        is_match = len(discrepancies) == 0
        status = "SEMANTIC_MATCH" if is_match else "DISCREPANCY_DETECTED"
        summary = (
            f"Scenario replay semantically reproduced parent run: SA established={child_manifest.get('sa_established')}, "
            f"Traffic passed={child_manifest.get('traffic_probe_passed')}, Status={child_manifest.get('validation_status')}."
            if is_match
            else f"Scenario replay discrepancy: {'; '.join(discrepancies)}."
        )

        return {
            "comparison_status": status,
            "differences": {"semantic_mismatches": discrepancies} if discrepancies else None,
            "summary": summary,
            "metrics": {
                "sa_established_parent": parent_manifest.get("sa_established"),
                "sa_established_child": child_manifest.get("sa_established"),
                "traffic_passed_parent": parent_manifest.get("traffic_probe_passed"),
                "traffic_passed_child": child_manifest.get("traffic_probe_passed"),
            },
        }
