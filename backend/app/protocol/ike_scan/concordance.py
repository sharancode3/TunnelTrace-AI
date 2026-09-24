"""Evidence concordance engine triangulating passive TShark dissection and active IKE probes."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class ConcordanceEvaluation:
    target_ip: str
    concordance_status: str  # "CONSISTENT", "CONFLICT", "INSUFFICIENT_EVIDENCE", "NOT_COMPARABLE"
    passive_ike_versions: list[str]
    active_ike_versions: list[str]
    passive_selected_cipher: str | None
    active_accepted_cipher: str | None
    details: dict[str, Any] = field(default_factory=dict)
    summary: str = ""


def evaluate_ike_concordance(
    *,
    target_ip: str,
    passive_ike_sas: list[dict[str, Any]] | None = None,
    passive_observations: list[dict[str, Any]] | None = None,
    active_probe_results: list[dict[str, Any]] | None = None,
    lab_ground_truth: dict[str, Any] | None = None,
) -> ConcordanceEvaluation:
    """Evaluate agreement/conflict between passive packet dissection and active IKE-scan probes.

    Lanes:
    1. Passive Lane (TShark): Observed negotiated proposals from initial exchanges.
    2. Active Lane (IKE-scan): Probed response capability and accepted transforms.
    3. Lab Ground Truth Lane (Optional): Known strongSwan configuration in isolated testbed.

    Epistemic states:
    - CONSISTENT: Passive and active observations are in agreement on version and transform family.
    - CONFLICT: Observable disagreement (e.g. passive handshake selected AES-GCM, active accepted 3DES only).
    - INSUFFICIENT_EVIDENCE: Capture lacks initial IKE negotiation frames, or active probe timed out / tool unavailable.
    - NOT_COMPARABLE: No relevant observation exists for the specified target.
    """
    passive_sas = passive_ike_sas or []
    passive_obs = passive_observations or []
    active_results = active_probe_results or []

    # 1. Extract passive facts
    passive_versions: set[str] = set()
    passive_cipher: str | None = None
    passive_frames: list[int] = []

    for sa in passive_sas:
        ver = sa.get("ike_version") or sa.get("version")
        if ver:
            passive_versions.add(str(ver))
        encr = sa.get("encryption_algorithm") or sa.get("encr")
        if encr and not passive_cipher:
            passive_cipher = str(encr)

    for obs in passive_obs:
        fn = obs.get("frame_number")
        if fn and fn not in passive_frames:
            passive_frames.append(fn)
        if obs.get("category") == "CRYPTO" and not passive_cipher:
            val = obs.get("normalized_value")
            if val and "ENCR" in str(obs.get("field_name", "")):
                passive_cipher = str(val)

    # 2. Extract active facts
    active_versions: set[str] = set()
    active_cipher: str | None = None
    active_categories: list[str] = []
    active_rtt: float | None = None
    is_experimental = False

    for res in active_results:
        cat = res.get("response_category", "UNKNOWN")
        active_categories.append(cat)
        ver = res.get("ike_version")
        if ver:
            active_versions.add(str(ver))
        if res.get("is_experimental"):
            is_experimental = True

        transforms = res.get("transforms_returned") or []
        for tf in transforms:
            if isinstance(tf, dict) and "encr" in tf and not active_cipher:
                active_cipher = tf["encr"]

        rtt = res.get("rtt_ms")
        if rtt is not None and active_rtt is None:
            active_rtt = rtt

    passive_ver_list = sorted(list(passive_versions))
    active_ver_list = sorted(list(active_versions))

    # Lane details dictionary
    lanes: dict[str, Any] = {
        "passive_lane": {
            "ike_versions": passive_ver_list,
            "selected_cipher": passive_cipher,
            "associated_frames": passive_frames,
            "has_initial_negotiation": bool(passive_ver_list or passive_cipher),
        },
        "active_lane": {
            "ike_versions": active_ver_list,
            "accepted_cipher": active_cipher,
            "response_categories": active_categories,
            "is_experimental": is_experimental,
            "rtt_ms": active_rtt,
        },
        "lab_ground_truth_lane": lab_ground_truth,
    }

    # 3. Determine concordance status
    # Case A: Neither active nor passive data exists
    if not passive_ver_list and not active_categories:
        return ConcordanceEvaluation(
            target_ip=target_ip,
            concordance_status="NOT_COMPARABLE",
            passive_ike_versions=[],
            active_ike_versions=[],
            passive_selected_cipher=None,
            active_accepted_cipher=None,
            details=lanes,
            summary=f"No passive capture or active probe evidence recorded for {target_ip}",
        )

    # Case B: Passive capture has no initial negotiation, or active probe got no response / tool unavailable
    active_has_response = any(
        c in ("RESPONDED_HANDSHAKE", "RESPONDED_NOTIFY") for c in active_categories
    )
    passive_has_negotiation = bool(passive_ver_list)

    if not passive_has_negotiation or not active_has_response:
        reasons: list[str] = []
        if not passive_has_negotiation:
            reasons.append("passive capture lacks initial IKE negotiation frames")
        if not active_has_response:
            if "TOOL_UNAVAILABLE" in active_categories:
                reasons.append("active probe tool was unavailable")
            elif "NO_RESPONSE" in active_categories:
                reasons.append("active probe received no response within timeout/retry limits")
            else:
                reasons.append("no active probe response")

        return ConcordanceEvaluation(
            target_ip=target_ip,
            concordance_status="INSUFFICIENT_EVIDENCE",
            passive_ike_versions=passive_ver_list,
            active_ike_versions=active_ver_list,
            passive_selected_cipher=passive_cipher,
            active_accepted_cipher=active_cipher,
            details=lanes,
            summary=f"Insufficient evidence for concordance on {target_ip}: {'; '.join(reasons)}",
        )

    # Case C: Both active and passive have data - compare versions and ciphers
    version_match = bool(set(passive_ver_list) & set(active_ver_list))

    cipher_match = True
    if passive_cipher and active_cipher:
        p_clean = passive_cipher.upper().replace("-", "").replace("_", "")
        a_clean = active_cipher.upper().replace("-", "").replace("_", "")
        cipher_match = (p_clean in a_clean) or (a_clean in p_clean)

    if version_match and cipher_match:
        summary = (
            f"Passive and active evidence are consistent for {target_ip}: "
            f"agreed on version(s) {passive_ver_list} and cipher '{passive_cipher or active_cipher}'"
        )
        return ConcordanceEvaluation(
            target_ip=target_ip,
            concordance_status="CONSISTENT",
            passive_ike_versions=passive_ver_list,
            active_ike_versions=active_ver_list,
            passive_selected_cipher=passive_cipher,
            active_accepted_cipher=active_cipher,
            details=lanes,
            summary=summary,
        )
    else:
        conflicts: list[str] = []
        if not version_match:
            conflicts.append(
                f"IKE version mismatch (passive observed {passive_ver_list}, active observed {active_ver_list})"
            )
        if not cipher_match:
            conflicts.append(
                f"Cipher mismatch (passive observed '{passive_cipher}', active accepted '{active_cipher}')"
            )

        summary = f"Concordance conflict for {target_ip}: {'; '.join(conflicts)}"
        return ConcordanceEvaluation(
            target_ip=target_ip,
            concordance_status="CONFLICT",
            passive_ike_versions=passive_ver_list,
            active_ike_versions=active_ver_list,
            passive_selected_cipher=passive_cipher,
            active_accepted_cipher=active_cipher,
            details=lanes,
            summary=summary,
        )
