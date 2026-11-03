from typing import Any


def parse_wazuh_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """
    Validate and extract important information
    from a Wazuh security alert.
    """

    # 1. Validate the top-level alert
    if not isinstance(alert, dict):
        raise TypeError("Alert must be a dictionary.")

    # 2. Validate the required rule object
    if "rule" not in alert or alert["rule"] is None:
        raise ValueError("Alert must contain a rule object.")

    rule = alert["rule"]

    if not isinstance(rule, dict):
        raise ValueError("Alert rule must be a dictionary.")

    # 3. Validate the required agent object
    if "agent" not in alert or alert["agent"] is None:
        raise ValueError("Alert must contain an agent object.")

    agent = alert["agent"]

    if not isinstance(agent, dict):
        raise ValueError("Alert agent must be a dictionary.")

    # 4. Validate required rule ID
    rule_id = rule.get("id")

    if not isinstance(rule_id, str) or not rule_id.strip():
        raise ValueError("Rule ID must be a non-empty string.")

    # 5. Validate required severity
    severity = rule.get("level")

    if not isinstance(severity, int) or isinstance(severity, bool):
        raise ValueError("Rule level must be an integer.")

    # 6. Validate optional description
    description = rule.get("description")

    if description is not None and not isinstance(description, str):
        raise ValueError("Rule description must be a string or null.")

    # 7. Validate optional agent name
    agent_name = agent.get("name")

    if agent_name is not None and not isinstance(agent_name, str):
        raise ValueError("Agent name must be a string or null.")

    # 8. Extract and validate original timestamp
    timestamp = alert.get("timestamp")

    if timestamp is not None and not isinstance(timestamp, str):
        raise ValueError("Timestamp must be a string or null.")

    # 9. Return extracted information
    parsed_alert = {
        "rule_id": rule_id,
        "severity": severity,
        "agent": agent_name,
        "description": description,
        "timestamp_original": timestamp,
    }

    return parsed_alert