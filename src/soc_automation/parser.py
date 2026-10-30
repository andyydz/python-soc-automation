from typing import Any


def parse_wazuh_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """
    Extract important information from a Wazuh security alert.

    Args:
        alert: A Wazuh alert represented as a Python dictionary.

    Returns:
        A normalized dictionary containing important alert fields.
    """

    if not isinstance(alert, dict):
        raise TypeError("Alert must be a dictionary.")

    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}

    if not isinstance(rule, dict):
        raise ValueError("Alert rule must be a dictionary.")

    if not isinstance(agent, dict):
        raise ValueError("Alert agent must be a dictionary.")

    parsed_alert = {
        "rule_id": rule.get("id", "unknown"),
        "severity": rule.get("level"),
        "agent": agent.get("name", "unknown"),
        "description": rule.get(
            "description", "No description provided"
        ),
    }

    return parsed_alert