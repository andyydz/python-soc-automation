from typing import Any

from soc_automation.parser import parse_wazuh_alert
from soc_automation.normalizer import normalize_timestamp


def process_wazuh_alert(
    alert: dict[str, Any],
    sha256_hash: str | None = None,
) -> dict[str, Any]:
    """
    Validate, normalize, and structure a Wazuh alert
    into the standardized SOC Automation output format.

    Optionally includes SHA-256 integrity metadata
    calculated from the original file bytes.
    """

    # 1. Validate and extract alert information
    parsed_alert = parse_wazuh_alert(alert)

    # 2. Normalize the original timestamp
    timestamp_result = normalize_timestamp(
        parsed_alert["timestamp_original"]
    )

    # 3. Collect timestamp warnings
    warnings = list(timestamp_result["warnings"])

    # 4. Add warnings for missing optional fields
    if parsed_alert["description"] is None:
        warnings.append("Rule description is missing.")

    if parsed_alert["agent"] is None:
        warnings.append("Agent name is missing.")

    # 5. Build the processed alert
    processed_alert = {
        "rule_id": parsed_alert["rule_id"],
        "severity": parsed_alert["severity"],
        "agent": parsed_alert["agent"],
        "description": parsed_alert["description"],
        "timestamp_original": parsed_alert["timestamp_original"],
        "timestamp_utc": timestamp_result["timestamp_utc"],
    }

    # 6. Build optional integrity metadata
    integrity = None

    if sha256_hash is not None:
        integrity = {
            "algorithm": "SHA-256",
            "hash": sha256_hash,
        }

    # 7. Build the standardized output envelope
    result = {
        "schema_version": "1.0",
        "record_type": "normalized_alert",

        "source": {
            "product": "Wazuh",
            "ingestion_type": "file_export",
        },

        "alert": processed_alert,

        "processing": {
            "warnings": warnings,
            "integrity": integrity,
        },

        "raw_alert": alert,
    }

    # 8. Return the final result
    return result
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