import json
import pytest
from pathlib import Path

from soc_automation.parser import parse_wazuh_alert


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


def test_reject_non_dictionary_alert():
    with pytest.raises(TypeError):
        parse_wazuh_alert("invalid alert")


def test_reject_invalid_rule():
    with pytest.raises(ValueError):
        parse_wazuh_alert({"rule": "invalid"})


def test_reject_invalid_agent():
    with pytest.raises(ValueError):
        parse_wazuh_alert({
            "rule": {},
            "agent": "invalid"
        })


def test_handle_missing_alert_fields():
    result = parse_wazuh_alert({})

    assert result["rule_id"] == "unknown"
    assert result["severity"] is None
    assert result["agent"] == "unknown"
    assert result["description"] == "No description provided"


def test_handle_partially_missing_alert_fields():
    alert = {
        "rule": {
            "id": "550"
        },
        "agent": {
            "name": "SENTINEL-LINUX01"
        }
    }

    result = parse_wazuh_alert(alert)

    assert result["rule_id"] == "550"
    assert result["severity"] is None
    assert result["agent"] == "SENTINEL-LINUX01"
    assert result["description"] == "No description provided"