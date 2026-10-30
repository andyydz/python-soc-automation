import json
import sys
from pathlib import Path

# Make the src folder available for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from soc_automation.parser import parse_wazuh_alert

# Load the sample Wazuh alert
alert_path = Path("data/sample_logs/wazuh_alert.json")

with alert_path.open("r", encoding="utf-8-sig") as file:
    alert = json.load(file)

# Process the alert
result = parse_wazuh_alert(alert)

# Display the parsed result
print("Parsed Wazuh Alert:")
print(result)

# Verify important fields
assert result["rule_id"] == "550"
assert result["severity"] == 7
assert result["agent"] == "SENTINEL-LINUX01"

print("\nAll parser checks passed!")