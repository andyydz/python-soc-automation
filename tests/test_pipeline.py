import pytest

from soc_automation.pipeline import process_wazuh_alert


def test_process_wazuh_alert():
    alert = {
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

    result = process_wazuh_alert(alert)

    assert result["schema_version"] == "1.0"
    assert result["record_type"] == "normalized_alert"

    assert result["source"]["product"] == "Wazuh"
    assert result["source"]["ingestion_type"] == "file_export"

    assert result["alert"]["rule_id"] == "550"
    assert result["alert"]["severity"] == 7
    assert result["alert"]["agent"] == "SENTINEL-LINUX01"
    assert result["alert"]["timestamp_utc"] == "2026-11-03T05:00:00Z"

    assert result["raw_alert"] == alert


def test_process_wazuh_alert_preserves_timestamp():
    alert = {
        "rule": {
            "id": "550",
            "level": 7,
        },
        "agent": {
            "name": "SENTINEL-LINUX01",
        },
        "timestamp": "2026-11-03T10:30:00+05:30",
    }

    result = process_wazuh_alert(alert)

    assert (
        result["alert"]["timestamp_original"]
        == "2026-11-03T10:30:00+05:30"
    )


def test_process_wazuh_alert_handles_missing_optional_fields():
    alert = {
        "rule": {
            "id": "550",
            "level": 7,
        },
        "agent": {},
    }

    result = process_wazuh_alert(alert)

    assert result["alert"]["description"] is None
    assert result["alert"]["agent"] is None
    assert result["alert"]["timestamp_original"] is None
    assert result["alert"]["timestamp_utc"] is None

    assert len(result["processing"]["warnings"]) >= 3


def test_process_wazuh_alert_returns_standardized_envelope():
    alert = {
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

    result = process_wazuh_alert(alert)

    # Verify the output envelope
    assert result["schema_version"] == "1.0"
    assert result["record_type"] == "normalized_alert"

    # Verify source information
    assert result["source"]["product"] == "Wazuh"
    assert result["source"]["ingestion_type"] == "file_export"

    # Verify processing metadata
    assert "warnings" in result["processing"]
    assert "integrity" in result["processing"]

    # Verify original alert preservation
    assert result["raw_alert"] == alert


def test_process_wazuh_alert_stores_warnings_under_processing():
    alert = {
        "rule": {
            "id": "550",
            "level": 7,
        },
        "agent": {},
    }

    result = process_wazuh_alert(alert)

    assert "warnings" in result["processing"]
    assert len(result["processing"]["warnings"]) >= 3
    assert "warnings" not in result["alert"]


def test_process_wazuh_alert_includes_sha256_integrity():
    alert = {
        "rule": {
            "id": "550",
            "level": 7,
            "description": "Integrity checksum changed",
        },
        "agent": {
            "name": "SENTINEL-LINUX01",
        },
        "timestamp": "2026-11-03T10:30:00Z",
    }

    sha256_hash = "a" * 64

    result = process_wazuh_alert(
        alert,
        sha256_hash=sha256_hash,
    )

    assert result["processing"]["integrity"] == {
        "algorithm": "SHA-256",
        "hash": sha256_hash,
    }


def test_process_wazuh_alert_without_sha256():
    alert = {
        "rule": {
            "id": "550",
            "level": 7,
            "description": "Integrity checksum changed",
        },
        "agent": {
            "name": "SENTINEL-LINUX01",
        },
        "timestamp": "2026-11-03T10:30:00Z",
    }

    result = process_wazuh_alert(alert)

    assert result["processing"]["integrity"] is None