from typing import Any


def evaluate_alert_quality(alert: dict[str, Any]) -> dict[str, Any]:
    """
    Evaluate the quality and completeness of a standardized alert.

    This function identifies missing or invalid fields.
    It does not modify or reject the original alert.
    """

    if not isinstance(alert, dict):
        raise TypeError("alert must be a dictionary.")

    normalized_alert = alert.get("alert")

    if not isinstance(normalized_alert, dict):
        raise ValueError(
            "Standardized alert must contain an alert object."
        )

    signals = []

    # Check rule ID.
    rule_id = normalized_alert.get("rule_id")

    if not isinstance(rule_id, (str, int)) or isinstance(rule_id, bool):
        signals.append({
            "field": "rule_id",
            "issue": "missing_or_invalid",
            "severity": "warning",
        })
    elif not str(rule_id).strip():
        signals.append({
            "field": "rule_id",
            "issue": "missing_or_invalid",
            "severity": "warning",
        })

    # Check severity.
    severity = normalized_alert.get("severity")

    if (
        isinstance(severity, bool)
        or not isinstance(severity, int)
        or not 0 <= severity <= 15
    ):
        signals.append({
            "field": "severity",
            "issue": "missing_or_invalid",
            "severity": "warning",
        })

    # Check rule description.
    description = normalized_alert.get("description")

    if not isinstance(description, str) or not description.strip():
        signals.append({
            "field": "description",
            "issue": "missing",
            "severity": "info",
        })

    # Check agent name.
    agent_name = normalized_alert.get("agent_name")

    if not isinstance(agent_name, str) or not agent_name.strip():
        signals.append({
            "field": "agent_name",
            "issue": "missing",
            "severity": "warning",
        })

    # Check normalized timestamp.
    timestamp_utc = normalized_alert.get("timestamp_utc")

    if not isinstance(timestamp_utc, str) or not timestamp_utc.strip():
        signals.append({
            "field": "timestamp_utc",
            "issue": "missing_or_unavailable",
            "severity": "info",
        })

    return {
        "status": "issues_found" if signals else "passed",
        "signals": signals,
    }