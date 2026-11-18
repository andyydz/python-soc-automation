"""Alert triage and summary reporting module.

Filters incoming Wazuh security alerts by severity thresholds and aggregates
triage telemetry into structured analyst summaries (dictionary or Markdown).
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any, Dict, List, Optional, Union


def _extract_alert_data(alert: Any) -> Dict[str, Any]:
    """Helper to defensively extract target fields regardless of wrapper envelope.
    
    Supports both raw exported Wazuh records and engine-normalized envelopes.
    """
    default_record = {
        "rule_id": "UNKNOWN",
        "rule_level": -1,
        "rule_description": "No description available",
        "file_path": "N/A",
        "timestamp": "UNKNOWN",
    }

    if not isinstance(alert, dict):
        return default_record

    # If the record is wrapped in an envelope (e.g., Schema v1.2), unwrap it
    target = alert.get("alert") if isinstance(alert.get("alert"), dict) else alert
    if not isinstance(target, dict):
        return default_record

    rule = target.get("rule") if isinstance(target.get("rule"), dict) else {}
    syscheck = target.get("syscheck") if isinstance(target.get("syscheck"), dict) else {}

    # Safe level parsing
    raw_level = rule.get("level")
    try:
        level = int(raw_level) if raw_level is not None else -1
    except (ValueError, TypeError):
        level = -1

    return {
        "rule_id": str(rule.get("id", "UNKNOWN")),
        "rule_level": level,
        "rule_description": str(rule.get("description", "No description available")),
        "file_path": str(syscheck.get("path", "N/A")),
        "timestamp": str(target.get("timestamp", "UNKNOWN")),
    }


def filter_by_severity(
    alerts: List[Dict[str, Any]], 
    min_level: int = 8
) -> List[Dict[str, Any]]:
    """Filters alerts based on a minimum rule level threshold.

    Args:
        alerts: List of raw or normalized Wazuh alert dictionaries.
        min_level: Inclusive integer threshold for filtering (default: 8 for High/Critical).

    Returns:
        List of alert dictionaries matching or exceeding the threshold.
    """
    if not isinstance(alerts, list):
        return []

    triaged_alerts = []
    for alert in alerts:
        extracted = _extract_alert_data(alert)
        if extracted.get("rule_level", -1) >= min_level:
            triaged_alerts.append(alert)

    return triaged_alerts


def generate_summary_report(
    alerts: List[Dict[str, Any]], 
    output_format: str = "dict"
) -> Union[Dict[str, Any], str]:
    """Aggregates alerts by rule ID, frequency, and affected target paths.

    Args:
        alerts: List of alerts (typically already filtered by triage threshold).
        output_format: Format of the report ('dict', 'json', or 'markdown').

    Returns:
        Structured dictionary, JSON string, or formatted Markdown report.
    """
    if not isinstance(alerts, list) or len(alerts) == 0:
        empty_summary: Dict[str, Any] = {
            "total_alerts": 0,
            "unique_rules": 0,
            "rules": {},
        }
        if output_format == "markdown":
            return "# Wazuh FIM Triage Summary Report\n\nNo matching alerts found."
        if output_format == "json":
            return json.dumps(empty_summary, indent=2)
        return empty_summary

    aggregation: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
            "level": -1,
            "description": "",
            "frequency": 0,
            "target_files": set(),
            "timestamps": [],
        }
    )

    for alert in alerts:
        data = _extract_alert_data(alert)
        r_id = data["rule_id"]

        rule_entry = aggregation[r_id]
        rule_entry["frequency"] += 1
        rule_entry["level"] = data["rule_level"]
        rule_entry["description"] = data["rule_description"]
        if data["file_path"] != "N/A":
            rule_entry["target_files"].add(data["file_path"])
        if data["timestamp"] != "UNKNOWN":
            rule_entry["timestamps"].append(data["timestamp"])

    # Prepare standard dictionary output
    formatted_rules: Dict[str, Any] = {}
    for r_id, stats in aggregation.items():
        formatted_rules[r_id] = {
            "level": stats["level"],
            "description": stats["description"],
            "count": stats["frequency"],
            "affected_paths": sorted(list(stats["target_files"])),
            "first_seen": min(stats["timestamps"]) if stats["timestamps"] else "UNKNOWN",
            "last_seen": max(stats["timestamps"]) if stats["timestamps"] else "UNKNOWN",
        }

    summary: Dict[str, Any] = {
        "total_alerts": len(alerts),
        "unique_rules": len(formatted_rules),
        "rules": formatted_rules,
    }

    if output_format == "json":
        return json.dumps(summary, indent=2)

    if output_format == "markdown":
        lines = [
            "# Wazuh FIM Triage Summary Report",
            f"**Total Filtered Alerts:** {summary['total_alerts']} | **Unique Rules:** {summary['unique_rules']}",
            "",
            "| Rule ID | Level | Frequency | Description | Monitored Target Path(s) |",
            "|:---:|:---:|:---:|:---|:---|",
        ]
        for r_id, meta in formatted_rules.items():
            paths = ", ".join(meta["affected_paths"]) if meta["affected_paths"] else "None"
            lines.append(
                f"| `{r_id}` | {meta['level']} | {meta['count']} | {meta['description']} | `{paths}` |"
            )
        return "\n".join(lines)

    return summary