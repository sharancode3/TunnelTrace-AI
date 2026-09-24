"""Safe YAML Policy-as-Code Loader.

Strictly enforces:
1. Pure declarative YAML parsing via yaml.safe_load (zero code execution, zero Python constructors).
2. Hard limits on file size (512 KB) and nesting depth to prevent resource exhaustion.
3. Schema validation via PolicyRule Pydantic model.
4. Target field verification against canonical FACT_FIELD_REGISTRY.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from app.security.policy.schema import PolicyBundle, PolicyProfile, PolicyRule


class PolicyLoadError(ValueError):
    """Raised when policy YAML loading or validation fails."""

    pass


MAX_POLICY_FILE_BYTES = 512 * 1024  # 512 KB
MAX_NESTING_DEPTH = 15


def _check_nesting_depth(data: Any, current_depth: int = 1) -> None:
    """Recursively verify dictionary/list nesting depth does not exceed safety bound."""
    if current_depth > MAX_NESTING_DEPTH:
        raise PolicyLoadError(f"Policy YAML exceeds maximum allowed nesting depth of {MAX_NESTING_DEPTH}")
    if isinstance(data, dict):
        for v in data.values():
            _check_nesting_depth(v, current_depth + 1)
    elif isinstance(data, list):
        for item in data:
            _check_nesting_depth(item, current_depth + 1)


class SafePolicyLoader:
    """Loads and validates PolicyRule and PolicyBundle instances from safe declarative YAML."""

    def __init__(self, directory: str | Path | None = None) -> None:
        self.directory = Path(directory) if directory else None

    def load_all_rules(self) -> list[PolicyRule]:
        """Load all valid rules from the instance directory."""
        if not self.directory or not self.directory.is_dir():
            return []
        rules: list[PolicyRule] = []
        rule_ids_seen: set[str] = set()
        for file_path in sorted(self.directory.glob("*.yaml")) + sorted(self.directory.glob("*.yml")):
            rule = self.load_rule_from_file(file_path)
            if rule.rule_id in rule_ids_seen:
                raise PolicyLoadError(f"Duplicate rule_id '{rule.rule_id}' detected in bundle directory '{self.directory}'")
            rule_ids_seen.add(rule.rule_id)
            rules.append(rule)
        return rules

    @classmethod
    def load_rule_from_str(cls, content: str) -> PolicyRule:
        """Parse, validate, and return a PolicyRule from a YAML string."""
        if len(content.encode("utf-8")) > MAX_POLICY_FILE_BYTES:
            raise PolicyLoadError(f"Policy YAML exceeds maximum allowed file size of {MAX_POLICY_FILE_BYTES} bytes")

        raw_dict = yaml.safe_load(content)
        if not isinstance(raw_dict, dict):
            raise ValueError("Policy YAML root element must be a dictionary")

        _check_nesting_depth(raw_dict)

        # Parse through Pydantic model
        rule = PolicyRule.model_validate(raw_dict)
        # Verify canonical field registry references
        rule.validate_field_references()
        return rule

    @classmethod
    def load_rule_from_file(cls, path: str | Path) -> PolicyRule:
        """Read and parse a single rule YAML file."""
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"Policy file not found: {p}")
        with open(p, encoding="utf-8") as f:
            content = f.read()
        return cls.load_rule_from_str(content)

    @classmethod
    def load_bundle_from_directory(
        cls,
        directory: str | Path,
        bundle_id: str,
        bundle_version: str,
        profile: PolicyProfile,
    ) -> PolicyBundle:
        """Load all .yaml / .yml files in a directory and construct a hashed PolicyBundle."""
        d = Path(directory)
        if not d.is_dir():
            raise NotADirectoryError(f"Policy directory not found: {d}")

        rules: list[PolicyRule] = []
        rule_ids_seen: set[str] = set()

        for file_path in sorted(d.glob("*.yaml")) + sorted(d.glob("*.yml")):
            rule = cls.load_rule_from_file(file_path)
            if rule.rule_id in rule_ids_seen:
                raise ValueError(f"Duplicate rule_id '{rule.rule_id}' detected in bundle directory '{d}'")
            rule_ids_seen.add(rule.rule_id)
            rules.append(rule)

        return PolicyBundle.create(
            bundle_id=bundle_id,
            bundle_version=bundle_version,
            profile=profile,
            rules=rules,
        )
