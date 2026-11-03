import copy

import pytest

from soc_automation.enrichment.data_quality import (
    evaluate_alert_quality,
)


@pytest.fixture
def sample_alert():
    return {
        "schema_version": "1.0",
        "record_type": "normalized_alert",
        "alert": {
            "rule_id": "550",
            "severity": 7,
            "description": "Integrity checksum changed",
            "agent_name": "SENTINEL-LINUX01",
            "timestamp_utc": "2026-11-03T10:30:00Z",
        },
    }


def test_complete_alert_passes_quality_check(sample_alert):
    result = evaluate_alert_quality(sample_alert)

    assert result["status"] == "passed"
    assert result["signals"] == []


def test_missing_description_creates_signal(sample_alert):
    sample_alert["alert"]["description"] = None

    result = evaluate_alert_quality(sample_alert)

    assert result["status"] == "issues_found"
    assert any(
        signal["field"] == "description"
        for signal in result["signals"]
    )


def test_missing_agent_name_creates_signal(sample_alert):
    sample_alert["alert"]["agent_name"] = None

    result = evaluate_alert_quality(sample_alert)

    assert result["status"] == "issues_found"
    assert any(
        signal["field"] == "agent_name"
        for signal in result["signals"]
    )


def test_missing_timestamp_creates_signal(sample_alert):
    sample_alert["alert"]["timestamp_utc"] = None

    result = evaluate_alert_quality(sample_alert)

    assert result["status"] == "issues_found"
    assert any(
        signal["field"] == "timestamp_utc"
        for signal in result["signals"]
    )


def test_invalid_severity_creates_signal(sample_alert):
    sample_alert["alert"]["severity"] = 20

    result = evaluate_alert_quality(sample_alert)

    assert result["status"] == "issues_found"
    assert any(
        signal["field"] == "severity"
        for signal in result["signals"]
    )


def test_missing_rule_id_creates_signal(sample_alert):
    sample_alert["alert"]["rule_id"] = ""

    result = evaluate_alert_quality(sample_alert)

    assert result["status"] == "issues_found"
    assert any(
        signal["field"] == "rule_id"
        for signal in result["signals"]
    )


def test_multiple_quality_issues_detected(sample_alert):
    sample_alert["alert"]["description"] = None
    sample_alert["alert"]["agent_name"] = None
    sample_alert["alert"]["timestamp_utc"] = None

    result = evaluate_alert_quality(sample_alert)

    assert result["status"] == "issues_found"
    assert len(result["signals"]) == 3


def test_original_alert_is_not_modified(sample_alert):
    original = copy.deepcopy(sample_alert)

    evaluate_alert_quality(sample_alert)

    assert sample_alert == original


@pytest.mark.parametrize("invalid_alert", [None, [], "alert", 123])
def test_invalid_input_type_rejected(invalid_alert):
    with pytest.raises(TypeError):
        evaluate_alert_quality(invalid_alert)


def test_missing_alert_object_rejected():
    with pytest.raises(ValueError):
        evaluate_alert_quality({"schema_version": "1.0"})