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
    alert = {"rule": "invalid"}

    with pytest.raises(ValueError):
        parse_wazuh_alert(alert)


def test_reject_invalid_agent():
    alert = {
        "rule": {},
        "agent": "invalid"
    }

    with pytest.raises(ValueError):
        parse_wazuh_alert(alert)