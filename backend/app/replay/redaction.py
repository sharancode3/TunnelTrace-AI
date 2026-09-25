"""Secret Redaction and Canonical Configuration Hashing for Replay Provenance.

Strictly ensures:
1. Manifests, logs, and digests never expose raw PSKs, private keys, passwords, or tokens.
2. Canonical serialization is deterministic with sorted keys and normalized encodings.
3. The canonical configuration digest is computed strictly over redacted text and
   clearly documented as NOT representing the original secret-bearing bytes.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

# Regex patterns for credential and secret fields in configurations and logs
SECRET_PATTERNS = [
    # swanctl secrets block: secret = <psk>
    (re.compile(r'(?i)(\bsecret\s*=\s*)(["\']?)([^"\'\r\n\s]+)(["\']?)'), r'\1\2[REDACTED_SECRET]\4'),
    # password = <pass>
    (re.compile(r'(?i)(\bpassword\s*=\s*)(["\']?)([^"\'\r\n\s]+)(["\']?)'), r'\1\2[REDACTED_SECRET]\4'),
    # token / psk / private_key patterns
    (re.compile(r'(?i)(\b(psk|token|api_key|auth_key|private_key)\s*[:=]\s*)(["\']?)([^"\'\r\n\s]+)(["\']?)'), r'\1\3[REDACTED_SECRET]\5'),
    # PEM Private Key blocks
    (re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]+?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----'), '[REDACTED_PRIVATE_KEY_BLOCK]'),
]


def redact_secrets_text(content: str) -> str:
    """Redacts secrets, pre-shared keys, and private key blocks from text content."""
    if not content:
        return ""
    result = content
    for pattern, replacement in SECRET_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def redact_secrets_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively redacts sensitive keys and values from a dictionary."""
    sensitive_keys = {
        "psk", "secret", "password", "token", "private_key", "api_key",
        "auth_key", "client_secret", "master_key", "psk_secret"
    }
    redacted: dict[str, Any] = {}
    for k, v in data.items():
        k_lower = str(k).lower()
        if any(s in k_lower for s in sensitive_keys):
            redacted[k] = "[REDACTED_SECRET]"
        elif isinstance(v, dict):
            redacted[k] = redact_secrets_dict(v)
        elif isinstance(v, list):
            redacted[k] = [
                redact_secrets_dict(item) if isinstance(item, dict)
                else (redact_secrets_text(str(item)) if isinstance(item, str) else item)
                for item in v
            ]
        elif isinstance(v, str):
            redacted[k] = redact_secrets_text(v)
        else:
            redacted[k] = v
    return redacted


def canonicalize_config(config: Any) -> str:
    """Produces a deterministic, canonical UTF-8 string representation of a configuration.

    Guarantees:
    - Sorted dictionary keys
    - Normalized whitespace and line endings (LF only)
    - Stripped leading/trailing line whitespace
    """
    if isinstance(config, dict):
        redacted = redact_secrets_dict(config)
        return json.dumps(redacted, sort_keys=True, indent=2, ensure_ascii=True)
    elif isinstance(config, (list, tuple)):
        redacted_list = [
            redact_secrets_dict(item) if isinstance(item, dict)
            else (redact_secrets_text(str(item)) if isinstance(item, str) else item)
            for item in config
        ]
        return json.dumps(redacted_list, sort_keys=True, indent=2, ensure_ascii=True)
    elif isinstance(config, str):
        redacted_str = redact_secrets_text(config)
        # Normalize line endings to LF and strip trailing line whitespace
        lines = [line.rstrip() for line in redacted_str.replace("\r\n", "\n").split("\n")]
        return "\n".join(lines).strip()
    else:
        return str(config).strip()


def compute_canonical_config_digest(config: Any) -> tuple[str, str]:
    """Computes a SHA-256 digest over the canonical, secret-redacted configuration.

    Returns:
        tuple[str, str]: (canonical_redacted_content, sha256_hexdigest)

    Note:
        The canonical configuration digest is computed strictly over the sanitized,
        non-secret configuration representation. It validates structural and semantic
        configuration integrity without exposing or hashing secret material.
    """
    canonical_text = canonicalize_config(config)
    digest = hashlib.sha256(canonical_text.encode("utf-8")).hexdigest()
    return canonical_text, digest
