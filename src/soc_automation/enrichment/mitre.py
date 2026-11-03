import json
from pathlib import Path
from typing import Any


# Locate the dataset relative to the project structure.
PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DATASET_PATH = PROJECT_ROOT / "data" / "mitre_attack.json"


class MitreDatasetError(Exception):
    """Raised when the MITRE ATT&CK dataset is invalid."""


def load_mitre_dataset(
    dataset_path: str | Path = DEFAULT_DATASET_PATH,
) -> dict[str, Any]:
    """
    Load and validate the local MITRE ATT&CK mapping dataset.
    """

    path = Path(dataset_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"MITRE ATT&CK dataset not found: {path}"
        )

    try:
        with path.open("r", encoding="utf-8") as file:
            dataset = json.load(file)

    except json.JSONDecodeError as exc:
        raise MitreDatasetError(
            f"Invalid JSON in MITRE ATT&CK dataset: {exc}"
        ) from exc

    if not isinstance(dataset, dict):
        raise MitreDatasetError(
            "MITRE ATT&CK dataset must be a JSON object."
        )

    rule_mappings = dataset.get("rule_mappings")

    if not isinstance(rule_mappings, dict):
        raise MitreDatasetError(
            "MITRE dataset must contain a rule_mappings object."
        )

    return dataset


def get_mitre_mapping(
    rule_id: str | int,
    dataset_path: str | Path = DEFAULT_DATASET_PATH,
) -> dict[str, Any]:
    """
    Retrieve verified MITRE ATT&CK mappings for a Wazuh rule ID.

    Returns empty mapping lists when no verified mapping exists.
    """

    if isinstance(rule_id, bool) or not isinstance(rule_id, (str, int)):
        raise TypeError(
            "rule_id must be a string or integer."
        )

    normalized_rule_id = str(rule_id).strip()

    if not normalized_rule_id:
        raise ValueError("rule_id cannot be empty.")

    dataset = load_mitre_dataset(dataset_path)

    mapping = dataset["rule_mappings"].get(normalized_rule_id)

    if mapping is None:
        return {
            "techniques": [],
            "tactics": [],
            "mapping_source": None
        }

    if not isinstance(mapping, dict):
        raise MitreDatasetError(
            f"Mapping for rule {normalized_rule_id} must be an object."
        )

    techniques = mapping.get("techniques", [])
    tactics = mapping.get("tactics", [])
    source = mapping.get("source")

    if not isinstance(techniques, list):
        raise MitreDatasetError(
            f"Techniques for rule {normalized_rule_id} must be a list."
        )

    if not all(
        isinstance(item, str) and item.strip()
        for item in techniques
    ):
        raise MitreDatasetError(
            f"Techniques for rule {normalized_rule_id} "
            "must contain non-empty strings."
        )

    if not isinstance(tactics, list):
        raise MitreDatasetError(
            f"Tactics for rule {normalized_rule_id} must be a list."
        )

    if not all(
        isinstance(item, str) and item.strip()
        for item in tactics
    ):
        raise MitreDatasetError(
            f"Tactics for rule {normalized_rule_id} "
            "must contain non-empty strings."
        )

    if source is not None and (
        not isinstance(source, str) or not source.strip()
    ):
        raise MitreDatasetError(
            f"Mapping source for rule {normalized_rule_id} "
            "must be a non-empty string or null."
        )

    return {
        "techniques": techniques.copy(),
        "tactics": tactics.copy(),
        "mapping_source": source
    }