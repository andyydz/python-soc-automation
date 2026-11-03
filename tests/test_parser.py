import json
import pytest
from pathlib import Path

from soc_automation.parser import parse_wazuh_alert


# 1. Test successful parsing of a valid Wazuh alert
def test_parse_wazuh_alert():
    alert_path = (
        Path(__file__).parent.parent
        / "data"
        / "sample_logs"
        / "wazuh_alert.json"
    )

    with alert_path.open("r", encoding="utf-8-sig") as file:
        alert = json.load(file)

    result = parse_wazuh_alert(alert)

    assert result["rule_id"] == "550"
    assert result["severity"] == 7
    assert result["agent"] == "SENTINEL-LINUX01"
    assert result["description"] == "Integrity checksum changed"
    assert result["timestamp_original"] is None


# 2. Reject non-dictionary input
def test_reject_non_dictionary_alert():
    with pytest.raises(TypeError):
        parse_wazuh_alert("invalid alert")


# 3. Reject missing rule
def test_reject_missing_rule():
    alert = {
        "agent": {"name": "SENTINEL-LINUX01"}
    }

    with pytest.raises(ValueError):
        parse_wazuh_alert(alert)


# 4. Reject invalid rule
def test_reject_invalid_rule():
    alert = {
        "rule": "invalid",
        "agent": {"name": "SENTINEL-LINUX01"}
    }

    with pytest.raises(ValueError):
        parse_wazuh_alert(alert)


# 5. Reject missing agent
def test_reject_missing_agent():
    alert = {
        "rule": {"id": "550", "level": 7}
    }

    with pytest.raises(ValueError):
        parse_wazuh_alert(alert)


# 6. Reject invalid agent
def test_reject_invalid_agent():
    alert = {
        "rule": {"id": "550", "level": 7},
        "agent": "invalid"
    }

    with pytest.raises(ValueError):
        parse_wazuh_alert(alert)


# 7. Reject missing rule ID
def test_reject_missing_rule_id():
    alert = {
        "rule": {"level": 7},
        "agent": {"name": "SENTINEL-LINUX01"}
    }

    with pytest.raises(ValueError):
        parse_wazuh_alert(alert)


# 8. Reject empty or whitespace-only rule ID
@pytest.mark.parametrize("rule_id", ["", "   "])
def test_reject_empty_rule_id(rule_id):
    alert = {
        "rule": {"id": rule_id, "level": 7},
        "agent": {"name": "SENTINEL-LINUX01"}
    }

    with pytest.raises(ValueError):
        parse_wazuh_alert(alert)


# 9. Reject missing severity
def test_reject_missing_rule_level():
    alert = {
        "rule": {"id": "550"},
        "agent": {"name": "SENTINEL-LINUX01"}
    }

    with pytest.raises(ValueError):
        parse_wazuh_alert(alert)


# 10. Reject Boolean severity
def test_reject_boolean_rule_level():
    alert = {
        "rule": {"id": "550", "level": True},
        "agent": {"name": "SENTINEL-LINUX01"}
    }

    with pytest.raises(ValueError):
        parse_wazuh_alert(alert)


# 11. Reject invalid severity types
@pytest.mark.parametrize("level", ["7", 7.5, None])
def test_reject_invalid_rule_level(level):
    alert = {
        "rule": {"id": "550", "level": level},
        "agent": {"name": "SENTINEL-LINUX01"}
    }

    with pytest.raises(ValueError):
        parse_wazuh_alert(alert)


# 12. Preserve the original timestamp
def test_preserve_original_timestamp():
    timestamp = "2026-11-03T12:30:00+05:30"

    alert = {
        "rule": {"id": "550", "level": 7},
        "agent": {"name": "SENTINEL-LINUX01"},
        "timestamp": timestamp
    }

    result = parse_wazuh_alert(alert)

    assert result["timestamp_original"] == timestamp


# 13. Handle an explicitly null timestamp
def test_handle_null_timestamp():
    alert = {
        "rule": {"id": "550", "level": 7},
        "agent": {"name": "SENTINEL-LINUX01"},
        "timestamp": None
    }

    result = parse_wazuh_alert(alert)

    assert result["timestamp_original"] is None


# 14. Reject a timestamp with an invalid data type
@pytest.mark.parametrize("timestamp", [12345, True, [], {}])
def test_reject_invalid_timestamp_type(timestamp):
    alert = {
        "rule": {"id": "550", "level": 7},
        "agent": {"name": "SENTINEL-LINUX01"},
        "timestamp": timestamp
    }

    with pytest.raises(ValueError):
        parse_wazuh_alert(alert)