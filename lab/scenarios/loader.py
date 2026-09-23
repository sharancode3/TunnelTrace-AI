"""Safe scenario loader with schema validation, path traversal prevention, and hashing."""

import hashlib
from pathlib import Path
from typing import Union, Tuple

import yaml

from lab.scenarios.schema import ScenarioDefinition


class ScenarioLoadError(Exception):
    """Raised when scenario parsing or schema validation fails."""
    pass


def load_scenario_from_yaml(path_or_content: Union[Path, str]) -> Tuple[ScenarioDefinition, str]:
    """Parse, validate, and compute SHA-256 digest of a scenario YAML specification.

    Returns:
        tuple[ScenarioDefinition, str]: (Parsed scenario object, SHA-256 hex digest)
    """
    raw_text: str
    if isinstance(path_or_content, Path) or (
        isinstance(path_or_content, str) and not path_or_content.strip().startswith("{") and "\n" not in path_or_content and Path(path_or_content).exists()
    ):
        target_path = Path(path_or_content).resolve()
        if not target_path.exists() or not target_path.is_file():
            raise ScenarioLoadError(f"Scenario file not found: {target_path}")
        try:
            raw_text = target_path.read_text(encoding="utf-8")
        except Exception as exc:
            raise ScenarioLoadError(f"Failed to read scenario file '{target_path}': {exc}") from exc
    else:
        raw_text = str(path_or_content)

    # Compute SHA-256 digest of exact raw configuration
    sha256_digest = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()

    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ScenarioLoadError(f"Malformed YAML in scenario: {exc}") from exc

    if not isinstance(data, dict):
        raise ScenarioLoadError("Scenario YAML must represent a top-level dictionary/mapping.")

    try:
        scenario = ScenarioDefinition.model_validate(data)
        scenario.sha256_hash = sha256_digest
        return scenario, sha256_digest
    except Exception as exc:
        raise ScenarioLoadError(f"Scenario validation failed: {exc}") from exc


class ScenarioLoader:
    """Helper class providing convenient methods to load scenarios."""

    @classmethod
    def load_from_yaml(cls, path_or_content: Union[Path, str]) -> ScenarioDefinition:
        scenario, sha = load_scenario_from_yaml(path_or_content)
        return scenario
