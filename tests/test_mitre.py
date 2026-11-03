import json

import pytest

from soc_automation.enrichment.mitre import (
    MitreDatasetError,
    load_mitre_dataset,
    get_mitre_mapping,
)


def create_dataset(tmp_path, content):
    dataset_path = tmp_path / "mitre_attack.json"

    dataset_path.write_text(
        json.dumps(content),
        encoding="utf-8"
    )

    return dataset_path


def test_load_mitre_dataset(tmp_path):
    dataset = {
        "dataset_version": "1.0",
        "rule_mappings": {}
    }

    path = create_dataset(tmp_path, dataset)

    result = load_mitre_dataset(path)

    assert result == dataset


def test_get_existing_mitre_mapping(tmp_path):
    dataset = {
        "rule_mappings": {
            "999001": {
                "techniques": ["T1003"],
                "tactics": ["Credential Access"],
                "source": "Verified test mapping"
            }
        }
    }

    path = create_dataset(tmp_path, dataset)

    result = get_mitre_mapping("999001", path)

    assert result["techniques"] == ["T1003"]
    assert result["tactics"] == ["Credential Access"]
    assert result["mapping_source"] == "Verified test mapping"


def test_unknown_rule_returns_empty_mapping(tmp_path):
    path = create_dataset(
        tmp_path,
        {"rule_mappings": {}}
    )

    result = get_mitre_mapping("550", path)

    assert result == {
        "techniques": [],
        "tactics": [],
        "mapping_source": None
    }


def test_rule_id_accepts_integer(tmp_path):
    path = create_dataset(
        tmp_path,
        {"rule_mappings": {}}
    )

    result = get_mitre_mapping(550, path)

    assert result["techniques"] == []
    assert result["tactics"] == []


@pytest.mark.parametrize("rule_id", ["", "   "])
def test_empty_rule_id_rejected(rule_id):
    with pytest.raises(ValueError):
        get_mitre_mapping(rule_id)


@pytest.mark.parametrize("rule_id", [True, 7.5, None])
def test_invalid_rule_id_type_rejected(rule_id):
    with pytest.raises(TypeError):
        get_mitre_mapping(rule_id)


def test_missing_dataset_raises_error(tmp_path):
    missing_path = tmp_path / "missing.json"

    with pytest.raises(FileNotFoundError):
        load_mitre_dataset(missing_path)


def test_invalid_json_raises_error(tmp_path):
    path = tmp_path / "invalid.json"

    path.write_text(
        "{invalid json",
        encoding="utf-8"
    )

    with pytest.raises(MitreDatasetError):
        load_mitre_dataset(path)


def test_missing_rule_mappings_rejected(tmp_path):
    path = create_dataset(
        tmp_path,
        {"dataset_version": "1.0"}
    )

    with pytest.raises(MitreDatasetError):
        load_mitre_dataset(path)


def test_invalid_rule_mapping_rejected(tmp_path):
    path = create_dataset(
        tmp_path,
        {"rule_mappings": {"550": "invalid"}}
    )

    with pytest.raises(MitreDatasetError):
        get_mitre_mapping("550", path)
def test_invalid_techniques_type_rejected(tmp_path):
    path = create_dataset(
        tmp_path,
        {
            "rule_mappings": {
                "550": {
                    "techniques": "T1003",
                    "tactics": [],
                    "source": "Test source"
                }
            }
        }
    )

    with pytest.raises(MitreDatasetError):
        get_mitre_mapping("550", path)


def test_invalid_technique_value_rejected(tmp_path):
    path = create_dataset(
        tmp_path,
        {
            "rule_mappings": {
                "550": {
                    "techniques": ["T1003", ""],
                    "tactics": [],
                    "source": "Test source"
                }
            }
        }
    )

    with pytest.raises(MitreDatasetError):
        get_mitre_mapping("550", path)


def test_invalid_tactics_type_rejected(tmp_path):
    path = create_dataset(
        tmp_path,
        {
            "rule_mappings": {
                "550": {
                    "techniques": [],
                    "tactics": "Credential Access",
                    "source": "Test source"
                }
            }
        }
    )

    with pytest.raises(MitreDatasetError):
        get_mitre_mapping("550", path)


def test_invalid_tactic_value_rejected(tmp_path):
    path = create_dataset(
        tmp_path,
        {
            "rule_mappings": {
                "550": {
                    "techniques": [],
                    "tactics": ["Credential Access", ""],
                    "source": "Test source"
                }
            }
        }
    )

    with pytest.raises(MitreDatasetError):
        get_mitre_mapping("550", path)


def test_invalid_mapping_source_rejected(tmp_path):
    path = create_dataset(
        tmp_path,
        {
            "rule_mappings": {
                "550": {
                    "techniques": [],
                    "tactics": [],
                    "source": 123
                }
            }
        }
    )

    with pytest.raises(MitreDatasetError):
        get_mitre_mapping("550", path)


def test_returned_mapping_lists_are_independent(tmp_path):
    path = create_dataset(
        tmp_path,
        {
            "rule_mappings": {
                "550": {
                    "techniques": ["T1003"],
                    "tactics": ["Credential Access"],
                    "source": "Test source"
                }
            }
        }
    )

    result = get_mitre_mapping("550", path)

    result["techniques"].append("T9999")
    result["tactics"].append("Persistence")

    second_result = get_mitre_mapping("550", path)

    assert second_result["techniques"] == ["T1003"]
    assert second_result["tactics"] == ["Credential Access"]        