import json
from pathlib import Path
from typing import Any


# Locate the dataset relative to the project structure.
PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DATASET_PATH = PROJECT_ROOT / "data" / "wazuh_rules.json"


class RuleMetadataError(Exception):
    """Raised when the Wazuh rule metadata dataset is invalid."""


def load_rule_metadata(
    dataset_path: str | Path = DEFAULT_DATASET_PATH,
) -> dict[str, Any]:
    """
    Load the local Wazuh rule metadata dataset.
    """

    path = Path(dataset_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Wazuh rule metadata dataset not found: {path}"
        )

    try:
        with path.open("r", encoding="utf-8") as file:
            dataset = json.load(file)

    except json.JSONDecodeError as exc:
        raise RuleMetadataError(
            f"Invalid JSON in Wazuh metadata dataset: {exc}"
        ) from exc

    if not isinstance(dataset, dict):
        raise RuleMetadataError(
            "Wazuh metadata dataset must be a JSON object."
        )

    rules = dataset.get("rules")

    if not isinstance(rules, dict):
        raise RuleMetadataError(
            "Wazuh metadata dataset must contain a rules object."
        )

    return dataset


def get_rule_metadata(
    rule_id: str | int,
    dataset_path: str | Path = DEFAULT_DATASET_PATH,
) -> dict[str, Any] | None:
    """
    Retrieve metadata for a Wazuh rule ID.

    Returns None when the rule is not present.
    """

    if isinstance(rule_id, bool) or not isinstance(rule_id, (str, int)):
        raise TypeError("rule_id must be a string or integer.")

    normalized_rule_id = str(rule_id).strip()

    if not normalized_rule_id:
        raise ValueError("rule_id cannot be empty.")

    dataset = load_rule_metadata(dataset_path)

    metadata = dataset["rules"].get(normalized_rule_id)

    if metadata is None:
        return None

    if not isinstance(metadata, dict):
        raise RuleMetadataError(
            f"Metadata for rule {normalized_rule_id} must be an object."
        )

    return metadata.copy()