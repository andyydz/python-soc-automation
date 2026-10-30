import json
from pathlib import Path

from soc_automation.parser import parse_wazuh_alert


def test_parse_wazuh_alert():
    alert_path = (
        Path(__file__).resolve().parents[1]
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