import json

import pytest

from soc_automation.enrichment.rule_metadata import (
    RuleMetadataError,
    get_rule_metadata,
    load_rule_metadata,
)


def test_load_rule_metadata():
    dataset = load_rule_metadata()

    assert "rules" in dataset
    assert isinstance(dataset["rules"], dict)


def test_get_existing_rule_metadata():
    metadata = get_rule_metadata("550")

    assert metadata is not None
    assert metadata["rule_id"] == "550"
    assert metadata["level"] == 7


def test_get_rule_metadata_accepts_integer_id():
    metadata = get_rule_metadata(553)

    assert metadata is not None
    assert metadata["rule_id"] == "553"


def test_unknown_rule_returns_none():
    metadata = get_rule_metadata("999999")

    assert metadata is None


def test_empty_rule_id_is_rejected():
    with pytest.raises(ValueError):
        get_rule_metadata(" ")


def test_missing_dataset_raises_error(tmp_path):
    missing_path = tmp_path / "missing.json"

    with pytest.raises(FileNotFoundError):
        load_rule_metadata(missing_path)


def test_invalid_json_raises_error(tmp_path):
    invalid_path = tmp_path / "invalid.json"
    invalid_path.write_text("{invalid json}", encoding="utf-8")

    with pytest.raises(RuleMetadataError):
        load_rule_metadata(invalid_path)


def test_missing_rules_object_raises_error(tmp_path):
    invalid_path = tmp_path / "missing_rules.json"

    invalid_path.write_text(
        json.dumps({"dataset_version": "1.0.0"}),
        encoding="utf-8",
    )

    with pytest.raises(RuleMetadataError):
        load_rule_metadata(invalid_path)