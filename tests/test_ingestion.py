import json

import pytest

from soc_automation.ingestion import ingest_wazuh_alert_file
from soc_automation.integrity import calculate_sha256


def create_wazuh_alert():
    return {
        "rule": {
            "id": "550",
            "level": 7,
            "description": "Integrity checksum changed",
        },
        "agent": {
            "name": "SENTINEL-LINUX01",
        },
        "timestamp": "2026-11-03T10:30:00+05:30",
    }


def test_ingest_valid_wazuh_json_file(tmp_path):
    alert = create_wazuh_alert()
    file_path = tmp_path / "alert.json"

    file_path.write_text(json.dumps(alert), encoding="utf-8")

    result = ingest_wazuh_alert_file(file_path)

    assert result["schema_version"] == "1.2"
    assert result["record_type"] == "normalized_alert"
    assert result["alert"]["rule_id"] == "550"
    assert result["raw_alert"] == alert
    assert "investigation" in result
    assert result["investigation"]["status"] == "new"


def test_ingest_file_without_sha256(tmp_path):
    alert = create_wazuh_alert()
    file_path = tmp_path / "alert.json"

    file_path.write_text(json.dumps(alert), encoding="utf-8")

    result = ingest_wazuh_alert_file(file_path)

    assert result["processing"]["integrity"] is None


def test_ingest_file_with_sha256(tmp_path):
    alert = create_wazuh_alert()
    file_path = tmp_path / "alert.json"

    original_bytes = json.dumps(alert).encode("utf-8")
    file_path.write_bytes(original_bytes)

    result = ingest_wazuh_alert_file(
        file_path,
        include_sha256=True,
    )

    expected_hash = calculate_sha256(original_bytes)

    assert result["processing"]["integrity"] == {
        "algorithm": "SHA-256",
        "hash": expected_hash,
    }


def test_ingest_missing_file_raises_error(tmp_path):
    file_path = tmp_path / "missing.json"

    with pytest.raises(FileNotFoundError):
        ingest_wazuh_alert_file(file_path)


def test_ingest_invalid_json_raises_error(tmp_path):
    file_path = tmp_path / "invalid.json"

    file_path.write_text(
        '{"rule": invalid json}',
        encoding="utf-8",
    )

    with pytest.raises(json.JSONDecodeError):
        ingest_wazuh_alert_file(file_path)


def test_ingest_non_object_json_raises_error(tmp_path):
    file_path = tmp_path / "array.json"

    file_path.write_text(
        '[{"rule": {"id": "550"}}]',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="must contain an object"):
        ingest_wazuh_alert_file(file_path)


def test_ingest_empty_json_file_raises_error(tmp_path):
    file_path = tmp_path / "empty.json"
    file_path.write_bytes(b"")

    with pytest.raises(json.JSONDecodeError):
        ingest_wazuh_alert_file(file_path)


def test_ingest_invalid_utf8_raises_error(tmp_path):
    file_path = tmp_path / "invalid_encoding.json"
    file_path.write_bytes(b"\xff\xfe\xfa")

    with pytest.raises(UnicodeDecodeError):
        ingest_wazuh_alert_file(file_path)


def test_ingest_missing_rule_raises_error(tmp_path):
    alert = {
        "agent": {
            "name": "SENTINEL-LINUX01",
        }
    }

    file_path = tmp_path / "missing_rule.json"
    file_path.write_text(json.dumps(alert), encoding="utf-8")

    with pytest.raises(ValueError, match="rule object"):
        ingest_wazuh_alert_file(file_path)


def test_ingest_missing_agent_raises_error(tmp_path):
    alert = {
        "rule": {
            "id": "550",
            "level": 7,
        }
    }

    file_path = tmp_path / "missing_agent.json"
    file_path.write_text(json.dumps(alert), encoding="utf-8")

    with pytest.raises(ValueError, match="agent object"):
        ingest_wazuh_alert_file(file_path)


def test_ingest_sha256_matches_original_file_bytes(tmp_path):
    alert = create_wazuh_alert()
    file_path = tmp_path / "integrity_check.json"

    original_bytes = json.dumps(
        alert,
        indent=4,
    ).encode("utf-8")

    file_path.write_bytes(original_bytes)

    result = ingest_wazuh_alert_file(
        file_path,
        include_sha256=True,
    )

    expected_hash = calculate_sha256(original_bytes)

    assert result["processing"]["integrity"]["hash"] == expected_hash


def test_ingest_file_with_enrichment(tmp_path):
    alert = create_wazuh_alert()
    file_path = tmp_path / "enriched_alert.json"

    file_path.write_text(json.dumps(alert), encoding="utf-8")

    result = ingest_wazuh_alert_file(
        file_path,
        include_enrichment=True,
    )

    assert "enrichment" in result
    assert (
        result["enrichment"]["severity_context"]["severity_label"]
        == "Medium"
    )
    assert "investigation" in result


def test_ingest_file_without_enrichment(tmp_path):
    alert = create_wazuh_alert()
    file_path = tmp_path / "normal_alert.json"

    file_path.write_text(json.dumps(alert), encoding="utf-8")

    result = ingest_wazuh_alert_file(file_path)

    assert "enrichment" not in result
    assert "investigation" in result


def test_ingest_utf8_bom_file(tmp_path):
    alert = create_wazuh_alert()
    file_path = tmp_path / "bom_alert.json"

    original_bytes = (
        b"\xef\xbb\xbf" + json.dumps(alert).encode("utf-8")
    )

    file_path.write_bytes(original_bytes)

    result = ingest_wazuh_alert_file(file_path)

    assert result["alert"]["rule_id"] == "550"
    assert result["raw_alert"] == alert


@pytest.mark.parametrize(
    "option_name, option_value",
    [
        ("include_sha256", "yes"),
        ("include_enrichment", 1),
    ],
)
def test_ingest_invalid_option_types(
    tmp_path,
    option_name,
    option_value,
):
    alert = create_wazuh_alert()
    file_path = tmp_path / "alert.json"

    file_path.write_text(json.dumps(alert), encoding="utf-8")

    with pytest.raises(TypeError):
        ingest_wazuh_alert_file(
            file_path,
            **{option_name: option_value},
        )