"""Versioned Remediation Template Registry.

Deterministic mapping from active Stage-8 policy rules and root causes to validated
Configuration IR transformations and strongSwan rendering logic.
Explicitly avoids any LLM or heuristic code generation.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from app.remediation.ir import (
    ChildSAConfigurationIR,
    ConfigurationIR,
    ConnectionConfigurationIR,
    TransformIR,
)
from app.remediation.proof import VerificationProofObligation
from app.security.findings.models import SecurityFinding


@dataclass(frozen=True)
class RemediationTemplate:
    """Deterministic rule-to-IR transformation specification."""

    template_id: str
    rule_id: str
    root_cause_key: str
    version: str
    title: str
    description: str
    authoritative_reference: str
    strongswan_directive: str
    target_config_key: str
    transformer: Callable[[ConfigurationIR], ConfigurationIR]
    proof_obligation_factory: Callable[[SecurityFinding], VerificationProofObligation]
    preconditions: tuple[str, ...] = field(default_factory=tuple)
    compatibility_constraints: tuple[str, ...] = field(default_factory=tuple)


class RemediationTemplateRegistry:
    """Registry maintaining tested, auditable remediation templates."""

    def __init__(self) -> None:
        self._templates_by_rule: dict[str, RemediationTemplate] = {}
        self._templates_by_root_cause: dict[str, RemediationTemplate] = {}
        self._register_canonical_templates()

    def get_template_for_rule(self, rule_id: str) -> RemediationTemplate | None:
        return self._templates_by_rule.get(rule_id)

    def get_template_for_root_cause(self, root_cause_key: str) -> RemediationTemplate | None:
        return self._templates_by_root_cause.get(root_cause_key)

    def list_templates(self) -> list[RemediationTemplate]:
        return list(self._templates_by_rule.values())

    def _register(self, tmpl: RemediationTemplate) -> None:
        self._templates_by_rule[tmpl.rule_id] = tmpl
        self._templates_by_root_cause[tmpl.root_cause_key] = tmpl

    def _register_canonical_templates(self) -> None:
        # 1. POL-NIST-001 / CIPHER_DEPRECATED_DES
        def _transform_des(ir: ConfigurationIR) -> ConfigurationIR:
            new_conns = []
            for c in ir.connections:
                # Upgrade IKE proposal if weak
                new_ike_props = []
                for p in c.ike_proposals:
                    if any(w in p.encryption.lower() for w in ("3des", "des")):
                        new_ike_props.append(
                            TransformIR(
                                encryption="aes256gcm16",
                                key_length=256,
                                prf="prfsha256",
                                dh_group=p.dh_group or 19,
                            )
                        )
                    else:
                        new_ike_props.append(p)
                if not new_ike_props:
                    new_ike_props.append(TransformIR(encryption="aes256gcm16", key_length=256, prf="prfsha256", dh_group=19))

                new_children = []
                for ch in c.children:
                    new_esp_props = []
                    for ep in ch.esp_proposals:
                        if any(w in ep.encryption.lower() for w in ("3des", "des")):
                            new_esp_props.append(
                                TransformIR(
                                    encryption="aes256gcm16",
                                    key_length=256,
                                    dh_group=ep.dh_group or ch.pfs_dh_group or 19,
                                )
                            )
                        else:
                            new_esp_props.append(ep)
                    if not new_esp_props:
                        new_esp_props.append(TransformIR(encryption="aes256gcm16", key_length=256, dh_group=19))
                    new_children.append(
                        ChildSAConfigurationIR(
                            name=ch.name,
                            mode=ch.mode,
                            esp_proposals=tuple(new_esp_props),
                            local_ts=ch.local_ts,
                            remote_ts=ch.remote_ts,
                            pfs_dh_group=ch.pfs_dh_group or 19,
                            start_action=ch.start_action,
                            rekey_time=ch.rekey_time,
                            replay_window=ch.replay_window,
                        )
                    )
                new_conns.append(
                    ConnectionConfigurationIR(
                        name=c.name,
                        ike_version=c.ike_version,
                        local_addrs=c.local_addrs,
                        remote_addrs=c.remote_addrs,
                        local_id=c.local_id,
                        remote_id=c.remote_id,
                        ike_proposals=tuple(new_ike_props),
                        encap=c.encap,
                        rekey_time=c.rekey_time,
                        children=tuple(new_children),
                    )
                )
            return ConfigurationIR(connections=tuple(new_conns), secrets=ir.secrets, raw_syntax_format="SWANCTL")

        def _proof_des(finding: SecurityFinding) -> VerificationProofObligation:
            return VerificationProofObligation(
                obligation_id=f"proof-obl-{uuid.uuid4().hex[:8]}",
                target_finding_id=finding.finding_id,
                target_rule_id="POL-NIST-001",
                target_rule_version="1.0.0",
                root_cause_key="CIPHER_DEPRECATED_DES",
                baseline_observed_fact_key="ike_sa.encryption_algorithm",
                baseline_observed_value=finding.observed_value,
                proposed_expected_value="AES256-GCM / AES-CBC",
                assertion_operator="not_in_set",
                resolution_criteria="Post-remediation capture shows negotiated IKE and Child SA ciphers are modern AES-GCM or AES-CBC; 3DES and DES are completely absent.",
                non_resolution_criteria="Post-remediation capture observes continued negotiation of 3DES or DES.",
                insufficient_evidence_criteria="Post-remediation capture does not observe completed SA negotiation.",
            )

        self._register(
            RemediationTemplate(
                template_id="TPL-NIST-001",
                rule_id="POL-NIST-001",
                root_cause_key="CIPHER_DEPRECATED_DES",
                version="1.0.0",
                title="Upgrade 3DES/DES to AES-GCM-256",
                description="Removes deprecated 64-bit block ciphers vulnerable to Sweet32 attacks and configures AES-GCM-256.",
                authoritative_reference="NIST SP 800-77 Rev. 1 Section 5.1.1",
                strongswan_directive="esp = aes256gcm16-ecp256!",
                target_config_key="esp",
                transformer=_transform_des,
                proof_obligation_factory=_proof_des,
                preconditions=("strongswan_daemon_active",),
                compatibility_constraints=("kernel_aes_gcm_support",),
            )
        )

        # 2. POL-NIST-002 / KEY_LENGTH_INSUFFICIENT
        def _transform_keylen(ir: ConfigurationIR) -> ConfigurationIR:
            new_conns = []
            for c in ir.connections:
                new_ike_props = []
                for p in c.ike_proposals:
                    new_ike_props.append(
                        TransformIR(
                            encryption="aes256gcm16",
                            key_length=256,
                            integrity=p.integrity,
                            prf=p.prf or "prfsha256",
                            dh_group=p.dh_group or 19,
                        )
                    )
                new_conns.append(
                    ConnectionConfigurationIR(
                        name=c.name,
                        ike_version=c.ike_version,
                        local_addrs=c.local_addrs,
                        remote_addrs=c.remote_addrs,
                        local_id=c.local_id,
                        remote_id=c.remote_id,
                        ike_proposals=tuple(new_ike_props),
                        encap=c.encap,
                        rekey_time=c.rekey_time,
                        children=c.children,
                    )
                )
            return ConfigurationIR(connections=tuple(new_conns), secrets=ir.secrets, raw_syntax_format="SWANCTL")

        def _proof_keylen(finding: SecurityFinding) -> VerificationProofObligation:
            return VerificationProofObligation(
                obligation_id=f"proof-obl-{uuid.uuid4().hex[:8]}",
                target_finding_id=finding.finding_id,
                target_rule_id="POL-NIST-002",
                target_rule_version="1.0.0",
                root_cause_key="KEY_LENGTH_INSUFFICIENT",
                baseline_observed_fact_key="ike_sa.key_length_bits",
                baseline_observed_value=finding.observed_value,
                proposed_expected_value=256,
                assertion_operator="greater_or_equal",
                resolution_criteria="Post-remediation capture shows negotiated symmetric key length is >= 128 bits (verified 256 bits).",
                non_resolution_criteria="Post-remediation capture observes key length < 128 bits.",
                insufficient_evidence_criteria="Post-remediation capture lacks negotiated IKE SA key length fact.",
            )

        self._register(
            RemediationTemplate(
                template_id="TPL-NIST-002",
                rule_id="POL-NIST-002",
                root_cause_key="KEY_LENGTH_INSUFFICIENT",
                version="1.0.0",
                title="Enforce 256-bit Cipher Key Strength",
                description="Upgrades symmetric encryption keys to 256 bits to satisfy NIST SP 800-77 Rev. 1 requirements.",
                authoritative_reference="NIST SP 800-77 Rev. 1 Section 5.1.1",
                strongswan_directive="ike = aes256gcm16-prfsha256-ecp256!",
                target_config_key="ike",
                transformer=_transform_keylen,
                proof_obligation_factory=_proof_keylen,
            )
        )

        # 3. POL-NIST-003 / INTEGRITY_DEPRECATED_HASH
        def _transform_integ(ir: ConfigurationIR) -> ConfigurationIR:
            new_conns = []
            for c in ir.connections:
                new_ike_props = []
                for p in c.ike_proposals:
                    new_ike_props.append(
                        TransformIR(
                            encryption="aes256",
                            key_length=256,
                            integrity="sha256",
                            prf="prfsha256",
                            dh_group=p.dh_group or 19,
                        )
                    )
                new_conns.append(
                    ConnectionConfigurationIR(
                        name=c.name,
                        ike_version=c.ike_version,
                        local_addrs=c.local_addrs,
                        remote_addrs=c.remote_addrs,
                        local_id=c.local_id,
                        remote_id=c.remote_id,
                        ike_proposals=tuple(new_ike_props),
                        encap=c.encap,
                        rekey_time=c.rekey_time,
                        children=c.children,
                    )
                )
            return ConfigurationIR(connections=tuple(new_conns), secrets=ir.secrets, raw_syntax_format="SWANCTL")

        def _proof_integ(finding: SecurityFinding) -> VerificationProofObligation:
            return VerificationProofObligation(
                obligation_id=f"proof-obl-{uuid.uuid4().hex[:8]}",
                target_finding_id=finding.finding_id,
                target_rule_id="POL-NIST-003",
                target_rule_version="1.0.0",
                root_cause_key="INTEGRITY_DEPRECATED_HASH",
                baseline_observed_fact_key="ike_sa.integrity_algorithm",
                baseline_observed_value=finding.observed_value,
                proposed_expected_value="SHA256 / AEAD-INTEGRATED",
                assertion_operator="not_in_set",
                resolution_criteria="Post-remediation capture shows HMAC-SHA-256 or AEAD; MD5 and SHA-1 are absent.",
                non_resolution_criteria="Post-remediation capture observes HMAC-MD5 or HMAC-SHA-1.",
                insufficient_evidence_criteria="Post-remediation capture lacks IKE integrity fact.",
            )

        self._register(
            RemediationTemplate(
                template_id="TPL-NIST-003",
                rule_id="POL-NIST-003",
                root_cause_key="INTEGRITY_DEPRECATED_HASH",
                version="1.0.0",
                title="Upgrade Integrity Transform to SHA-256 / AEAD",
                description="Replaces vulnerable MD5 / SHA-1 hashes with secure SHA-256 or integrated AEAD authentication.",
                authoritative_reference="NIST SP 800-77 Rev. 1 Section 5.1.1",
                strongswan_directive="ike = aes256-sha256-ecp256!",
                target_config_key="ike",
                transformer=_transform_integ,
                proof_obligation_factory=_proof_integ,
            )
        )

        # 4. POL-NIST-004 / DH_GROUP_WEAK_LOGJAM
        def _transform_dh(ir: ConfigurationIR) -> ConfigurationIR:
            new_conns = []
            for c in ir.connections:
                new_ike_props = []
                for p in c.ike_proposals:
                    new_ike_props.append(
                        TransformIR(
                            encryption=p.encryption,
                            key_length=p.key_length or 256,
                            integrity=p.integrity,
                            prf=p.prf or "prfsha256",
                            dh_group=19,  # ECP-256 (Group 19)
                        )
                    )
                new_conns.append(
                    ConnectionConfigurationIR(
                        name=c.name,
                        ike_version=c.ike_version,
                        local_addrs=c.local_addrs,
                        remote_addrs=c.remote_addrs,
                        local_id=c.local_id,
                        remote_id=c.remote_id,
                        ike_proposals=tuple(new_ike_props),
                        encap=c.encap,
                        rekey_time=c.rekey_time,
                        children=c.children,
                    )
                )
            return ConfigurationIR(connections=tuple(new_conns), secrets=ir.secrets, raw_syntax_format="SWANCTL")

        def _proof_dh(finding: SecurityFinding) -> VerificationProofObligation:
            return VerificationProofObligation(
                obligation_id=f"proof-obl-{uuid.uuid4().hex[:8]}",
                target_finding_id=finding.finding_id,
                target_rule_id="POL-NIST-004",
                target_rule_version="1.0.0",
                root_cause_key="DH_GROUP_WEAK_LOGJAM",
                baseline_observed_fact_key="ike_sa.diffie_hellman_group",
                baseline_observed_value=finding.observed_value,
                proposed_expected_value=19,
                assertion_operator="in_set",
                resolution_criteria="Post-remediation capture proves negotiated DH group is MODP-2048+ (Group 14+) or ECP-256+ (Group 19+).",
                non_resolution_criteria="Post-remediation capture shows DH group < 14 (e.g. MODP-1024 / Group 2).",
                insufficient_evidence_criteria="Post-remediation capture lacks observable IKE DH exchange evidence.",
            )

        self._register(
            RemediationTemplate(
                template_id="TPL-NIST-004",
                rule_id="POL-NIST-004",
                root_cause_key="DH_GROUP_WEAK_LOGJAM",
                version="1.0.0",
                title="Upgrade DH Group to ECP-256 (Group 19)",
                description="Upgrades weak Diffie-Hellman groups susceptible to Logjam discrete-log precomputation to ECP-256.",
                authoritative_reference="NIST SP 800-77 Rev. 1 Section 5.1.2",
                strongswan_directive="ike = aes256gcm16-prfsha256-ecp256!",
                target_config_key="ike",
                transformer=_transform_dh,
                proof_obligation_factory=_proof_dh,
            )
        )

        # 5. POL-PFS-001 / PFS_DISABLED
        def _transform_pfs(ir: ConfigurationIR) -> ConfigurationIR:
            new_conns = []
            for c in ir.connections:
                new_children = []
                for ch in c.children:
                    new_esp_props = []
                    for ep in ch.esp_proposals:
                        new_esp_props.append(
                            TransformIR(
                                encryption=ep.encryption,
                                key_length=ep.key_length,
                                integrity=ep.integrity,
                                dh_group=19,
                            )
                        )
                    if not new_esp_props:
                        new_esp_props.append(TransformIR(encryption="aes256gcm16", dh_group=19))
                    new_children.append(
                        ChildSAConfigurationIR(
                            name=ch.name,
                            mode=ch.mode,
                            esp_proposals=tuple(new_esp_props),
                            local_ts=ch.local_ts,
                            remote_ts=ch.remote_ts,
                            pfs_dh_group=19,
                            start_action=ch.start_action,
                            rekey_time=ch.rekey_time,
                            replay_window=ch.replay_window,
                        )
                    )
                new_conns.append(
                    ConnectionConfigurationIR(
                        name=c.name,
                        ike_version=c.ike_version,
                        local_addrs=c.local_addrs,
                        remote_addrs=c.remote_addrs,
                        local_id=c.local_id,
                        remote_id=c.remote_id,
                        ike_proposals=c.ike_proposals,
                        encap=c.encap,
                        rekey_time=c.rekey_time,
                        children=tuple(new_children),
                    )
                )
            return ConfigurationIR(connections=tuple(new_conns), secrets=ir.secrets, raw_syntax_format="SWANCTL")

        def _proof_pfs(finding: SecurityFinding) -> VerificationProofObligation:
            return VerificationProofObligation(
                obligation_id=f"proof-obl-{uuid.uuid4().hex[:8]}",
                target_finding_id=finding.finding_id,
                target_rule_id="POL-PFS-001",
                target_rule_version="1.0.0",
                root_cause_key="PFS_DISABLED",
                baseline_observed_fact_key="child_sa.pfs_status",
                baseline_observed_value=finding.observed_value,
                proposed_expected_value="ENABLED",
                assertion_operator="equals",
                resolution_criteria="Post-remediation capture proves Child SA negotiated ephemeral DH exchange during rekeying (PFS ENABLED).",
                non_resolution_criteria="Post-remediation capture shows Child SA PFS remains DISABLED.",
                insufficient_evidence_criteria="Post-remediation capture does not observe Child SA rekeying or CREATE_CHILD_SA exchange.",
            )

        self._register(
            RemediationTemplate(
                template_id="TPL-PFS-001",
                rule_id="POL-PFS-001",
                root_cause_key="PFS_DISABLED",
                version="1.0.0",
                title="Enable Child SA Perfect Forward Secrecy (PFS)",
                description="Appends DH group 19 (ECP-256) to Child SA ESP proposals to enforce ephemeral key re-negotiation.",
                authoritative_reference="NIST SP 800-77 Rev. 1 Section 5.1.2",
                strongswan_directive="esp = aes256gcm16-ecp256!",
                target_config_key="esp",
                transformer=_transform_pfs,
                proof_obligation_factory=_proof_pfs,
            )
        )

        # 6. POL-REPLAY-001 / REPLAY_SEQUENCE_NON_MONOTONIC
        def _transform_replay(ir: ConfigurationIR) -> ConfigurationIR:
            new_conns = []
            for c in ir.connections:
                new_children = []
                for ch in c.children:
                    new_children.append(
                        ChildSAConfigurationIR(
                            name=ch.name,
                            mode=ch.mode,
                            esp_proposals=ch.esp_proposals,
                            local_ts=ch.local_ts,
                            remote_ts=ch.remote_ts,
                            pfs_dh_group=ch.pfs_dh_group,
                            start_action=ch.start_action,
                            rekey_time=ch.rekey_time,
                            replay_window=64,
                        )
                    )
                new_conns.append(
                    ConnectionConfigurationIR(
                        name=c.name,
                        ike_version=c.ike_version,
                        local_addrs=c.local_addrs,
                        remote_addrs=c.remote_addrs,
                        local_id=c.local_id,
                        remote_id=c.remote_id,
                        ike_proposals=c.ike_proposals,
                        encap=c.encap,
                        rekey_time=c.rekey_time,
                        children=tuple(new_children),
                    )
                )
            return ConfigurationIR(connections=tuple(new_conns), secrets=ir.secrets, raw_syntax_format="SWANCTL")

        def _proof_replay(finding: SecurityFinding) -> VerificationProofObligation:
            return VerificationProofObligation(
                obligation_id=f"proof-obl-{uuid.uuid4().hex[:8]}",
                target_finding_id=finding.finding_id,
                target_rule_id="POL-REPLAY-001",
                target_rule_version="1.0.0",
                root_cause_key="REPLAY_SEQUENCE_NON_MONOTONIC",
                baseline_observed_fact_key="esp_flow.sequence_monotonic",
                baseline_observed_value=finding.observed_value,
                proposed_expected_value=True,
                assertion_operator="equals",
                resolution_criteria="Post-remediation capture verifies that all ESP packet sequence numbers advance strictly monotonically.",
                non_resolution_criteria="Post-remediation capture detects duplicate or out-of-order sequence numbers outside window.",
                insufficient_evidence_criteria="Post-remediation capture contains insufficient ESP packet volume (< 10 packets).",
            )

        self._register(
            RemediationTemplate(
                template_id="TPL-REPLAY-001",
                rule_id="POL-REPLAY-001",
                root_cause_key="REPLAY_SEQUENCE_NON_MONOTONIC",
                version="1.0.0",
                title="Enforce 64-Packet Anti-Replay Window",
                description="Configures replay_window = 64 on Child SAs to enforce monotonic packet sequence validation.",
                authoritative_reference="RFC 4303 Section 3.3.3",
                strongswan_directive="replay_window = 64",
                target_config_key="replay_window",
                transformer=_transform_replay,
                proof_obligation_factory=_proof_replay,
            )
        )

        # 7. POL-RFC-7296-01 / PROTOCOL_LEGACY_IKEV1
        def _transform_ikev2(ir: ConfigurationIR) -> ConfigurationIR:
            new_conns = []
            for c in ir.connections:
                new_conns.append(
                    ConnectionConfigurationIR(
                        name=c.name,
                        ike_version=2,
                        local_addrs=c.local_addrs,
                        remote_addrs=c.remote_addrs,
                        local_id=c.local_id,
                        remote_id=c.remote_id,
                        ike_proposals=c.ike_proposals,
                        encap=c.encap,
                        rekey_time=c.rekey_time,
                        children=c.children,
                    )
                )
            return ConfigurationIR(connections=tuple(new_conns), secrets=ir.secrets, raw_syntax_format="SWANCTL")

        def _proof_ikev2(finding: SecurityFinding) -> VerificationProofObligation:
            return VerificationProofObligation(
                obligation_id=f"proof-obl-{uuid.uuid4().hex[:8]}",
                target_finding_id=finding.finding_id,
                target_rule_id="POL-RFC-7296-01",
                target_rule_version="1.0.0",
                root_cause_key="PROTOCOL_LEGACY_IKEV1",
                baseline_observed_fact_key="ike_session.ike_version",
                baseline_observed_value=finding.observed_value,
                proposed_expected_value="IKEv2",
                assertion_operator="equals",
                resolution_criteria="Post-remediation capture observes successful IKEv2 (version 2) handshake.",
                non_resolution_criteria="Post-remediation capture shows negotiation with legacy IKEv1.",
                insufficient_evidence_criteria="Post-remediation capture does not observe initial IKE exchange headers.",
            )

        self._register(
            RemediationTemplate(
                template_id="TPL-RFC-7296-01",
                rule_id="POL-RFC-7296-01",
                root_cause_key="PROTOCOL_LEGACY_IKEV1",
                version="1.0.0",
                title="Migrate Gateway to IKEv2",
                description="Sets version = 2 to mandate RFC 7296 IKEv2 and prevent fallback to legacy IKEv1.",
                authoritative_reference="RFC 7296 Section 1.2",
                strongswan_directive="version = 2",
                target_config_key="version",
                transformer=_transform_ikev2,
                proof_obligation_factory=_proof_ikev2,
            )
        )

        # 8. POL-RFC-8221-01 / CIPHER_NULL_CLEARTEXT
        def _transform_null(ir: ConfigurationIR) -> ConfigurationIR:
            new_conns = []
            for c in ir.connections:
                new_children = []
                for ch in c.children:
                    new_esp_props = []
                    for ep in ch.esp_proposals:
                        if "null" in ep.encryption.lower():
                            new_esp_props.append(
                                TransformIR(
                                    encryption="aes256gcm16",
                                    key_length=256,
                                    dh_group=ep.dh_group or 19,
                                )
                            )
                        else:
                            new_esp_props.append(ep)
                    if not new_esp_props:
                        new_esp_props.append(TransformIR(encryption="aes256gcm16", key_length=256, dh_group=19))
                    new_children.append(
                        ChildSAConfigurationIR(
                            name=ch.name,
                            mode=ch.mode,
                            esp_proposals=tuple(new_esp_props),
                            local_ts=ch.local_ts,
                            remote_ts=ch.remote_ts,
                            pfs_dh_group=ch.pfs_dh_group or 19,
                            start_action=ch.start_action,
                            rekey_time=ch.rekey_time,
                            replay_window=ch.replay_window,
                        )
                    )
                new_conns.append(
                    ConnectionConfigurationIR(
                        name=c.name,
                        ike_version=c.ike_version,
                        local_addrs=c.local_addrs,
                        remote_addrs=c.remote_addrs,
                        local_id=c.local_id,
                        remote_id=c.remote_id,
                        ike_proposals=c.ike_proposals,
                        encap=c.encap,
                        rekey_time=c.rekey_time,
                        children=tuple(new_children),
                    )
                )
            return ConfigurationIR(connections=tuple(new_conns), secrets=ir.secrets, raw_syntax_format="SWANCTL")

        def _proof_null(finding: SecurityFinding) -> VerificationProofObligation:
            return VerificationProofObligation(
                obligation_id=f"proof-obl-{uuid.uuid4().hex[:8]}",
                target_finding_id=finding.finding_id,
                target_rule_id="POL-RFC-8221-01",
                target_rule_version="1.0.0",
                root_cause_key="CIPHER_NULL_CLEARTEXT",
                baseline_observed_fact_key="child_sa.encryption_algorithm",
                baseline_observed_value=finding.observed_value,
                proposed_expected_value="AES256-GCM / AES-CBC",
                assertion_operator="not_in_set",
                resolution_criteria="Post-remediation capture proves ESP encryption is non-NULL (verified AES-GCM or AES-CBC).",
                non_resolution_criteria="Post-remediation capture shows continued negotiation of NULL encryption.",
                insufficient_evidence_criteria="Post-remediation capture does not observe Child SA cipher negotiation.",
            )

        self._register(
            RemediationTemplate(
                template_id="TPL-RFC-8221-01",
                rule_id="POL-RFC-8221-01",
                root_cause_key="CIPHER_NULL_CLEARTEXT",
                version="1.0.0",
                title="Enforce Authenticated Encryption (Disallow NULL)",
                description="Replaces unencrypted cleartext NULL proposals with AES-GCM-256 per RFC 8221 mandates.",
                authoritative_reference="RFC 8221 Section 4",
                strongswan_directive="esp = aes256gcm16-ecp256!",
                target_config_key="esp",
                transformer=_transform_null,
                proof_obligation_factory=_proof_null,
            )
        )
