"""Hardened, bounded strongSwan swanctl.conf parser with strict secret redaction.

Parses strongSwan configuration files into normalized, semantic intermediate
representations while strictly scrubbing secrets and recording unsupported directives.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any


class ConfigurationParseError(Exception):
    """Raised when configuration text violates safety bounds or contains malformed syntax."""


@dataclass(frozen=True)
class NormalizedProposal:
    """Parsed single cryptographic proposal (e.g. aes256gcm16-prfsha256-ecp256)."""

    encryption: str
    key_length: int | None = None
    integrity: str | None = None
    prf: str | None = None
    dh_group: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "encryption": self.encryption,
            "key_length": self.key_length,
            "integrity": self.integrity,
            "prf": self.prf,
            "dh_group": self.dh_group,
        }


def parse_proposal_string(prop_str: str) -> NormalizedProposal:
    """Parse a single transform token sequence."""
    tokens = [t.strip().rstrip("!") for t in prop_str.strip().split("-") if t.strip()]
    if not tokens:
        return NormalizedProposal(encryption="unknown")

    encryption = tokens[0]
    key_length: int | None = None
    integrity: str | None = None
    prf: str | None = None
    dh_group: str | None = None

    enc_digits = re.findall(r"\d+", encryption)
    if enc_digits:
        for d in (256, 192, 128):
            if str(d) in encryption:
                key_length = d
                break

    for tok in tokens[1:]:
        tok_lower = tok.lower()
        if any(tok_lower.startswith(prefix) for prefix in ("modp", "ecp", "curve", "x25519", "x448")):
            dh_group = tok_lower
        elif tok_lower.startswith("prf"):
            prf = tok_lower
        elif any(h in tok_lower for h in ("sha", "md5", "aesxcbc")):
            integrity = tok_lower
        elif tok_lower.isdigit():
            # Could be DH group number (e.g. 14, 19)
            dh_group = tok_lower

    return NormalizedProposal(
        encryption=encryption,
        key_length=key_length,
        integrity=integrity,
        prf=prf,
        dh_group=dh_group,
    )


def parse_proposals_list(props_str: str) -> list[dict[str, Any]]:
    """Parse comma- or whitespace-separated strongSwan proposals."""
    proposals: list[dict[str, Any]] = []
    tokens = [p.strip() for p in re.split(r"[,;]", props_str) if p.strip()]
    for tok in tokens:
        proposals.append(parse_proposal_string(tok).to_dict())
    return proposals


class SafeSwanctlParser:
    """Safe, bounded parser for strongSwan swanctl.conf configuration syntax.

    Bounds enforced:
      - Max content length: 1,000,000 chars
      - Max lines: 10,000
      - Max line length: 4,096 chars
      - Max brace nesting depth: 8
    """

    MAX_CONTENT_LENGTH = 1_000_000
    MAX_LINES = 10_000
    MAX_LINE_LENGTH = 4_096
    MAX_NESTING_DEPTH = 8

    # Fields that contain sensitive authentication credentials
    SECRET_KEY_NAMES = {
        "secret",
        "password",
        "key",
        "rsa_key",
        "ecdsa_key",
        "private_key",
        "pkcs12",
        "file",  # private key file path in secrets block
    }

    @classmethod
    def parse(cls, text: str) -> dict[str, Any]:
        """Parse swanctl.conf text into a normalized, redacted dictionary.

        Returns:
            dict containing:
              - 'normalized_ir': normalized semantic structure
              - 'unsupported_directives': list of unmodeled entries
              - 'canonical_digest': deterministic SHA-256 of public configuration
        """
        # 1. Bounds checks
        if not text:
            raise ConfigurationParseError("Configuration text is empty")
        if len(text) > cls.MAX_CONTENT_LENGTH:
            raise ConfigurationParseError(f"Configuration exceeds maximum size of {cls.MAX_CONTENT_LENGTH} bytes")

        raw_lines = text.splitlines()
        if len(raw_lines) > cls.MAX_LINES:
            raise ConfigurationParseError(f"Configuration exceeds maximum line count of {cls.MAX_LINES}")

        connections: dict[str, Any] = {}
        secrets: dict[str, Any] = {}
        unsupported: list[dict[str, Any]] = []

        # 1. Tokenize text into discrete semantic statements while preserving quoted strings
        tokens: list[tuple[int, str]] = []
        for line_no, raw_line in enumerate(raw_lines, start=1):
            if len(raw_line) > cls.MAX_LINE_LENGTH:
                raise ConfigurationParseError(f"Line {line_no} exceeds maximum length of {cls.MAX_LINE_LENGTH}")

            # Strip comments outside quotes
            in_quote = False
            quote_char = ""
            cleaned: list[str] = []
            for ch in raw_line:
                if ch in ('"', "'"):
                    if not in_quote:
                        in_quote = True
                        quote_char = ch
                    elif ch == quote_char:
                        in_quote = False
                        quote_char = ""
                elif ch == "#" and not in_quote:
                    break
                cleaned.append(ch)

            line_str = "".join(cleaned).strip()
            if not line_str:
                continue

            # Split on { and } outside quotes
            in_quote = False
            curr: list[str] = []
            for ch in line_str:
                if ch in ('"', "'"):
                    if not in_quote:
                        in_quote = True
                        quote_char = ch
                    elif ch == quote_char:
                        in_quote = False
                        quote_char = ""
                    curr.append(ch)
                elif (ch == "{" or ch == "}") and not in_quote:
                    chunk = "".join(curr).strip()
                    if chunk:
                        tokens.append((line_no, chunk))
                    tokens.append((line_no, ch))
                    curr = []
                else:
                    curr.append(ch)
            remainder = "".join(curr).strip()
            if remainder:
                tokens.append((line_no, remainder))

        # 2. Process token stream
        block_stack: list[str] = []
        depth = 0
        current_conn_name: str | None = None
        current_child_name: str | None = None
        current_secret_name: str | None = None

        idx = 0
        while idx < len(tokens):
            line_no, tok = tokens[idx]

            # Block opening check: lookahead for "{"
            if idx + 1 < len(tokens) and tokens[idx + 1][1] == "{":
                block_name = tok.strip()
                if not block_name or "=" in block_name:
                    raise ConfigurationParseError(f"Line {line_no}: Invalid block name '{block_name}'")

                depth += 1
                if depth > cls.MAX_NESTING_DEPTH:
                    raise ConfigurationParseError(
                        f"Line {line_no}: Nesting depth {depth} exceeds limit of {cls.MAX_NESTING_DEPTH}"
                    )
                block_stack.append(block_name)

                # Track context
                if len(block_stack) == 2 and block_stack[0] == "connections":
                    current_conn_name = block_name
                    connections[current_conn_name] = {
                        "name": current_conn_name,
                        "version": 2,
                        "local_addrs": "%any",
                        "remote_addrs": "%any",
                        "proposals": [],
                        "encap": False,
                        "rekey_time": "14400s",
                        "local": {},
                        "remote": {},
                        "children": {},
                    }
                elif len(block_stack) == 4 and block_stack[0] == "connections" and block_stack[2] == "children":
                    current_child_name = block_name
                    if current_conn_name and current_conn_name in connections:
                        connections[current_conn_name]["children"][current_child_name] = {
                            "name": current_child_name,
                            "mode": "tunnel",
                            "local_ts": "0.0.0.0/0",
                            "remote_ts": "0.0.0.0/0",
                            "esp_proposals": [],
                            "start_action": "start",
                            "rekey_time": "3600s",
                            "replay_window": 64,
                        }
                elif len(block_stack) == 2 and block_stack[0] == "secrets":
                    current_secret_name = block_name
                    secrets[current_secret_name] = {
                        "secret_id": current_secret_name,
                        "secret_type": current_secret_name,
                    }

                idx += 2  # Consumed name and "{"
                continue

            # Closing block
            if tok == "}":
                if not block_stack:
                    raise ConfigurationParseError(f"Line {line_no}: Unexpected closing brace without opening block")
                closing = block_stack.pop()
                depth -= 1

                if closing == current_conn_name and len(block_stack) == 1:
                    current_conn_name = None
                elif closing == current_child_name and len(block_stack) == 3:
                    current_child_name = None
                elif closing == current_secret_name and len(block_stack) == 1:
                    current_secret_name = None
                idx += 1
                continue

            # Key-value assignment
            if "=" in tok:
                k, v = [part.strip() for part in tok.split("=", 1)]
                v = v.strip('"').strip("'")
                context_path = ".".join(block_stack)

                # Process based on stack depth and context
                if block_stack and block_stack[0] == "connections":
                    if len(block_stack) == 2 and current_conn_name:
                        # Top-level connection attribute
                        if k == "version":
                            try:
                                connections[current_conn_name]["version"] = int(v)
                            except ValueError:
                                connections[current_conn_name]["version"] = 2
                        elif k == "local_addrs":
                            connections[current_conn_name]["local_addrs"] = v
                        elif k == "remote_addrs":
                            connections[current_conn_name]["remote_addrs"] = v
                        elif k == "proposals":
                            connections[current_conn_name]["proposals"] = parse_proposals_list(v)
                            connections[current_conn_name]["raw_proposals"] = v
                        elif k == "encap":
                            connections[current_conn_name]["encap"] = v.lower() in ("yes", "true", "1")
                        elif k == "rekey_time":
                            connections[current_conn_name]["rekey_time"] = v
                        else:
                            unsupported.append({"path": f"{context_path}.{k}", "value": v})
                    elif len(block_stack) == 3 and current_conn_name and block_stack[2] in ("local", "remote"):
                        role = block_stack[2]
                        if k in ("id", "auth", "certs", "cacerts"):
                            connections[current_conn_name][role][k] = v
                        else:
                            unsupported.append({"path": f"{context_path}.{k}", "value": v})
                    elif len(block_stack) == 4 and current_conn_name and current_child_name and block_stack[2] == "children":
                        child_entry = connections[current_conn_name]["children"][current_child_name]
                        if k == "mode":
                            child_entry["mode"] = v
                        elif k == "local_ts":
                            child_entry["local_ts"] = v
                        elif k == "remote_ts":
                            child_entry["remote_ts"] = v
                        elif k == "esp_proposals":
                            child_entry["esp_proposals"] = parse_proposals_list(v)
                            child_entry["raw_esp_proposals"] = v
                        elif k == "start_action":
                            child_entry["start_action"] = v
                        elif k == "rekey_time":
                            child_entry["rekey_time"] = v
                        elif k == "replay_window":
                            try:
                                child_entry["replay_window"] = int(v)
                            except ValueError:
                                child_entry["replay_window"] = 64
                        else:
                            unsupported.append({"path": f"{context_path}.{k}", "value": v})
                    else:
                        unsupported.append({"path": f"{context_path}.{k}", "value": v})

                elif block_stack and block_stack[0] == "secrets":
                    # Strictly redact secrets
                    if current_secret_name:
                        if k.lower() in cls.SECRET_KEY_NAMES:
                            secrets[current_secret_name][k] = "[REDACTED_SECRET]"
                            secrets[current_secret_name]["is_redacted"] = True
                        else:
                            # Non-secret metadata like id or remote identifier
                            secrets[current_secret_name][k] = v
                    else:
                        unsupported.append({"path": f"{context_path}.{k}", "value": "[REDACTED_SECRET]" if k.lower() in cls.SECRET_KEY_NAMES else v})
                else:
                    # Outside connections or secrets
                    unsupported.append({"path": f"{context_path}.{k}", "value": v})

                idx += 1
                continue

            raise ConfigurationParseError(f"Line {line_no}: Invalid syntax: '{tok}'")

        if block_stack:
            raise ConfigurationParseError(f"Unclosed blocks at end of file: {block_stack}")

        # Assemble normalized IR structure
        normalized_ir = {
            "format": "SWANCTL",
            "version": "6.0.4",
            "connections": connections,
            "secrets": secrets,
        }

        # Compute deterministic canonical digest (over normalized public fields)
        canonical_digest = cls.compute_canonical_digest(normalized_ir)

        return {
            "normalized_ir": normalized_ir,
            "unsupported_directives": unsupported,
            "canonical_digest": canonical_digest,
        }

    @classmethod
    def compute_canonical_digest(cls, normalized_ir: dict[str, Any]) -> str:
        """Compute deterministic SHA-256 digest of normalized public configuration.

        Fields included in digest:
          - connections (sorted): version, local_addrs, remote_addrs, proposals, encap, rekey_time, local (id, auth, certs), remote (id, auth, cacerts)
          - children (sorted): mode, local_ts, remote_ts, esp_proposals, start_action, rekey_time, replay_window
        Fields excluded from digest:
          - secrets block (prevents unkeyed hash of secret references/placeholders)
        """
        public_view = {
            "format": normalized_ir.get("format", "SWANCTL"),
            "connections": normalized_ir.get("connections", {}),
        }
        canonical_json = json.dumps(public_view, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
