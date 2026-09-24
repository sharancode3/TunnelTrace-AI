"""Deterministic strongSwan swanctl.conf renderer and semantic diff engine."""

from __future__ import annotations

import difflib
from typing import Any

from app.remediation.ir import (
    ConfigurationIR,
    ConnectionConfigurationIR,
    CurrentConfigurationSnapshot,
    EpistemicState,
)


class SwanctlRenderer:
    """Renders typed ConfigurationIR into valid strongSwan swanctl.conf syntax."""

    @classmethod
    def render(cls, ir: ConfigurationIR, psk_secret: str = "tunneltrace_lab_test_psk_9921") -> str:
        """Render ConfigurationIR into standard swanctl.conf format."""
        lines: list[str] = [
            "# ==============================================================================",
            "# TunnelTrace AI — strongSwan swanctl.conf (Deterministic Remediation Template)",
            f"# Format: {ir.raw_syntax_format} | Managed by Stage 10 Security Twin",
            "# ==============================================================================",
            "",
            "connections {",
        ]

        for conn in ir.connections:
            lines.extend(cls._render_connection(conn))

        lines.append("}")
        lines.append("")

        # Render secrets section with lab PSK
        lines.append("secrets {")
        for s in ir.secrets:
            lines.append(f"    {s.secret_id} {{")
            lines.append(f"        id = {s.remote_id}")
            lines.append(f'        secret = "{psk_secret}"')
            lines.append("    }")
        lines.append("}")
        lines.append("")

        return "\n".join(lines)

    @classmethod
    def _render_connection(cls, conn: ConnectionConfigurationIR) -> list[str]:
        lines: list[str] = []
        lines.append(f"    {conn.name} {{")
        lines.append(f"        version = {conn.ike_version}")
        lines.append(f"        local_addrs = {conn.local_addrs}")
        lines.append(f"        remote_addrs = {conn.remote_addrs}")

        # Render IKE proposals
        if conn.ike_proposals:
            ike_str = ",".join(p.to_strongswan_string(is_ike=True) for p in conn.ike_proposals)
            lines.append(f"        proposals = {ike_str}")

        lines.append(f"        encap = {'yes' if conn.encap else 'no'}")
        lines.append(f"        rekey_time = {conn.rekey_time}")
        lines.append("")

        # Local & Remote IDs
        lines.append("        local {")
        lines.append("            auth = psk")
        lines.append(f"            id = {conn.local_id}")
        lines.append("        }")
        lines.append("        remote {")
        lines.append("            auth = psk")
        lines.append(f"            id = {conn.remote_id}")
        lines.append("        }")
        lines.append("")

        # Children
        lines.append("        children {")
        for child in conn.children:
            lines.append(f"            {child.name} {{")
            lines.append(f"                local_ts = {child.local_ts}")
            lines.append(f"                remote_ts = {child.remote_ts}")
            lines.append(f"                mode = {child.mode}")

            if child.esp_proposals:
                esp_str = ",".join(p.to_strongswan_string(is_ike=False) for p in child.esp_proposals)
                lines.append(f"                esp_proposals = {esp_str}")

            lines.append(f"                start_action = {child.start_action}")
            lines.append(f"                rekey_time = {child.rekey_time}")
            lines.append(f"                replay_window = {child.replay_window}")
            lines.append("            }")
        lines.append("        }")
        lines.append("    }")
        return lines


class ConfigurationDiffEngine:
    """Generates both Security Semantic Diffs and Unified Text Diffs between configurations."""

    @classmethod
    def compute_semantic_diff(
        cls,
        current_snapshot: CurrentConfigurationSnapshot,
        proposed_ir: ConfigurationIR,
    ) -> list[dict[str, Any]]:
        """Compute structured semantic differences across security properties.

        Returns list of property changes:
        - field: property identifier (e.g. 'ike_encryption', 'dh_group', 'child_pfs')
        - current_value: value from current observed facts
        - current_evidence_state: VERIFIED / INFERRED / UNKNOWN
        - proposed_value: proposed value from hardened IR
        - policy_impact: explanation of security rationale
        - is_changed: boolean
        """
        changes: list[dict[str, Any]] = []

        # Find first connection and child for comparison
        prop_conn = proposed_ir.connections[0] if proposed_ir.connections else None
        prop_child = prop_conn.children[0] if prop_conn and prop_conn.children else None

        prop_ike_prop = prop_conn.ike_proposals[0] if prop_conn and prop_conn.ike_proposals else None
        prop_esp_prop = prop_child.esp_proposals[0] if prop_child and prop_child.esp_proposals else None

        # 1. IKE Version
        curr_ver = current_snapshot.ike_version.value or "UNKNOWN"
        prop_ver = f"IKEv{prop_conn.ike_version}" if prop_conn else "UNKNOWN"
        changes.append(
            {
                "field": "ike_version",
                "label": "IKE Protocol Version",
                "current_value": curr_ver,
                "current_evidence_state": current_snapshot.ike_version.state.value,
                "proposed_value": prop_ver,
                "is_changed": str(curr_ver).lower() != str(prop_ver).lower(),
                "policy_impact": "Enforces modern IKEv2 RFC 7296 standard, eliminating legacy IKEv1 vulnerabilities."
                if str(curr_ver).lower() != str(prop_ver).lower()
                else "Unchanged",
            }
        )

        # 2. IKE Encryption
        curr_enc = current_snapshot.ike_encryption.value or "UNKNOWN"
        prop_enc = prop_ike_prop.encryption.upper() if prop_ike_prop else "UNKNOWN"
        changes.append(
            {
                "field": "ike_encryption",
                "label": "IKE SA Encryption Algorithm",
                "current_value": curr_enc,
                "current_evidence_state": current_snapshot.ike_encryption.state.value,
                "proposed_value": prop_enc,
                "is_changed": str(curr_enc).upper() != str(prop_enc).upper(),
                "policy_impact": "Disallows weak/legacy ciphers (3DES/DES) and mandates strong AES-GCM / AES-CBC."
                if str(curr_enc).upper() != str(prop_enc).upper()
                else "Unchanged",
            }
        )

        # 3. IKE Key Length
        curr_klen = current_snapshot.ike_key_length.value or "UNKNOWN"
        prop_klen = prop_ike_prop.key_length or 256 if prop_ike_prop else "UNKNOWN"
        changes.append(
            {
                "field": "ike_key_length",
                "label": "IKE Cipher Key Length (bits)",
                "current_value": curr_klen,
                "current_evidence_state": current_snapshot.ike_key_length.state.value,
                "proposed_value": prop_klen,
                "is_changed": str(curr_klen) != str(prop_klen),
                "policy_impact": "Ensures minimum 128-bit / 256-bit symmetric security strength per NIST SP 800-77."
                if str(curr_klen) != str(prop_klen)
                else "Unchanged",
            }
        )

        # 4. IKE DH Group
        curr_dh = current_snapshot.ike_dh_group.value or "UNKNOWN"
        prop_dh = prop_ike_prop.dh_group if prop_ike_prop else "UNKNOWN"
        changes.append(
            {
                "field": "ike_dh_group",
                "label": "IKE Diffie-Hellman Key Exchange Group",
                "current_value": curr_dh,
                "current_evidence_state": current_snapshot.ike_dh_group.state.value,
                "proposed_value": prop_dh,
                "is_changed": str(curr_dh) != str(prop_dh),
                "policy_impact": "Upgrades weak DH groups (MODP-1024 / Group 2) to MODP-2048+ or ECP-256+ to prevent Logjam precomputation."
                if str(curr_dh) != str(prop_dh)
                else "Unchanged",
            }
        )

        # 5. Child SA Encryption
        curr_c_enc = current_snapshot.child_encryption.value or "UNKNOWN"
        prop_c_enc = prop_esp_prop.encryption.upper() if prop_esp_prop else "UNKNOWN"
        changes.append(
            {
                "field": "child_encryption",
                "label": "ESP Data Plane Cipher",
                "current_value": curr_c_enc,
                "current_evidence_state": current_snapshot.child_encryption.state.value,
                "proposed_value": prop_c_enc,
                "is_changed": str(curr_c_enc).upper() != str(prop_c_enc).upper(),
                "policy_impact": "Replaces insecure NULL or legacy ciphers with authenticated encryption (AES-GCM-16)."
                if str(curr_c_enc).upper() != str(prop_c_enc).upper()
                else "Unchanged",
            }
        )

        # 6. Child SA PFS
        curr_pfs = current_snapshot.child_pfs_status.value or "UNKNOWN"
        prop_pfs = "ENABLED" if (prop_child and prop_child.pfs_dh_group is not None) else "DISABLED"
        changes.append(
            {
                "field": "child_pfs_status",
                "label": "Child SA Perfect Forward Secrecy (PFS)",
                "current_value": curr_pfs,
                "current_evidence_state": current_snapshot.child_pfs_status.state.value,
                "proposed_value": prop_pfs,
                "is_changed": str(curr_pfs).upper() != str(prop_pfs).upper(),
                "policy_impact": "Mandates ephemeral DH exchanges during Child SA rekeying to prevent retrospective decryption."
                if str(curr_pfs).upper() != str(prop_pfs).upper()
                else "Unchanged",
            }
        )

        # 7. Child SA Replay Window
        curr_rw = current_snapshot.child_replay_window.value or "UNKNOWN"
        prop_rw = prop_child.replay_window if prop_child else 64
        changes.append(
            {
                "field": "child_replay_window",
                "label": "Anti-Replay Window Size",
                "current_value": curr_rw,
                "current_evidence_state": current_snapshot.child_replay_window.state.value,
                "proposed_value": prop_rw,
                "is_changed": str(curr_rw) != str(prop_rw),
                "policy_impact": "Enforces anti-replay window sizing to mitigate packet injection and reordering attacks."
                if str(curr_rw) != str(prop_rw)
                else "Unchanged",
            }
        )

        return changes

    @classmethod
    def compute_text_diff(cls, current_text: str, proposed_text: str) -> str:
        """Compute unified text diff between rendered current and proposed configurations."""
        curr_lines = current_text.splitlines(keepends=True)
        prop_lines = proposed_text.splitlines(keepends=True)

        diff = difflib.unified_diff(
            curr_lines,
            prop_lines,
            fromfile="Current (Observed / Active Lab)",
            tofile="Proposed (Hardened Security Twin)",
            n=3,
        )
        return "".join(diff)
