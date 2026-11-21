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

    def _first_non_empty(mapping: Dict[str, Any], keys: tuple[str, ...]) -> Optional[str]:
        for key in keys:
            val = mapping.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
        return None

    raw_fim_path = syscheck.get("path")
    fim_path = raw_fim_path.strip() if isinstance(raw_fim_path, str) and raw_fim_path.strip() else None

    data_obj = target.get("data") if isinstance(target.get("data"), dict) else {}
    win_obj = data_obj.get("win") if isinstance(data_obj.get("win"), dict) else {}
    system_obj = win_obj.get("system") if isinstance(win_obj.get("system"), dict) else {}
    eventdata = win_obj.get("eventdata") if isinstance(win_obj.get("eventdata"), dict) else {}

    target_file = _first_non_empty(eventdata, ("targetFilename", "TargetFilename"))
    process_image = _first_non_empty(
        eventdata, ("image", "Image", "sourceImage", "SourceImage")
    )
    target_process_image = _first_non_empty(eventdata, ("targetImage", "TargetImage"))

    # affected_paths / file_path only reflect file targets, never process/target images
    file_path = fim_path or target_file or "N/A"

    alert_timestamp = str(target.get("timestamp", "UNKNOWN"))
    event_timestamp = _first_non_empty(system_obj, ("systemTime", "SystemTime")) or _first_non_empty(
        eventdata, ("UtcTime", "utcTime")
    )

    return {
        "rule_id": str(rule.get("id", "UNKNOWN")),
        "rule_level": level,
        "rule_description": str(rule.get("description", "No description available")),
        "file_path": file_path,
        "fim_path": fim_path,
        "target_file": target_file,
        "process_image": process_image,
        "target_process_image": target_process_image,
        "timestamp": alert_timestamp,
        "alert_timestamp": alert_timestamp,
        "event_timestamp": event_timestamp,
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
        if data["alert_timestamp"] != "UNKNOWN":
            rule_entry["timestamps"].append(data["alert_timestamp"])

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

def _stringify_alert_blob(alert: Any) -> str:
    """Safely serializes an alert structure for substring heuristic checks."""
    if alert is None:
        return ""
    if isinstance(alert, str):
        return alert
    try:
        return json.dumps(alert, default=str)
    except (TypeError, ValueError):
        return str(alert)


def _extract_srcip(alert: Any) -> Optional[str]:
    """Extracts source IP from raw or normalized Wazuh alert dictionaries."""
    if not isinstance(alert, dict):
        return None
    target = alert.get("alert") if isinstance(alert.get("alert"), dict) else alert
    if not isinstance(target, dict):
        return None
    data = target.get("data")
    if isinstance(data, dict) and data.get("srcip"):
        return str(data["srcip"])
    return None


def build_v07_triage_context(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Derives v0.7-informed noise, sub-threshold SSH, and evasion context.

    Evaluates across the provided alert list so low-severity or filtered events
    (such as Level 5 SSH 100200 attempts or evasion-adjacent strings) remain
    visible to analysts without altering severity-filtered alert lists.
    """
    context: Dict[str, Any] = {
        "fim_noise_paths": [],
        "fim_suspicious_paths": [],
        "subthreshold_ssh_100200": {},
        "evasion_indicators": [],
    }
    if not isinstance(alerts, list):
        return context

    noise_markers = ("/.cache/", "/tracker3", "/nautilus", "/gvfs")
    ssh_counts_by_ip: Dict[str, int] = defaultdict(int)
    seen_noise: set[str] = set()
    seen_suspicious: set[str] = set()

    for idx, alert in enumerate(alerts):
        data = _extract_alert_data(alert)
        rule_id = data["rule_id"]
        path = data["file_path"]
        blob_lower = _stringify_alert_blob(alert).lower()

        # 1. FIM noise vs. suspicious path classification
        if path != "N/A":
            path_lower = path.lower()
            if any(marker in path_lower for marker in noise_markers):
                if path not in seen_noise:
                    seen_noise.add(path)
                    context["fim_noise_paths"].append(path)
            elif "/." in path or path.startswith("/var/tmp/"):
                if path not in seen_suspicious:
                    seen_suspicious.add(path)
                    context["fim_suspicious_paths"].append(path)

        # 2. Sub-threshold SSH rule 100200 grouping by source IP
        if rule_id == "100200":
            srcip = _extract_srcip(alert) or "unknown_srcip"
            ssh_counts_by_ip[srcip] += 1

        # 3. Evasion-adjacent indicator (rundll32 / comsvcs without literal minidump)
        has_lolbin = ("rundll32.exe" in blob_lower) or ("comsvcs.dll" in blob_lower)
        if has_lolbin and "minidump" not in blob_lower:
            context["evasion_indicators"].append(
                {
                    "index": idx,
                    "rule_id": rule_id,
                    "level": data["rule_level"],
                    "reason": "LOLBin/DLL reference without literal minidump string (v0.7 evasion pattern)",
                }
            )

    context["subthreshold_ssh_100200"] = dict(sorted(ssh_counts_by_ip.items()))
    return context


def format_v07_context_markdown(context: Dict[str, Any]) -> str:
    """Renders v0.7 triage context as a readable Markdown section."""
    noise_paths = context.get("fim_noise_paths", [])
    suspicious_paths = context.get("fim_suspicious_paths", [])
    ssh_ips = context.get("subthreshold_ssh_100200", {})
    evasion = context.get("evasion_indicators", [])

    lines = [
        "## v0.7 Triage Context (Noise, Sub-Threshold SSH & Evasion)",
        f"- **Likely FIM Noise Paths:** {', '.join(f'`{p}`' for p in noise_paths) if noise_paths else 'None detected'}",
        f"- **Suspicious / Hidden FIM Paths:** {', '.join(f'`{p}`' for p in suspicious_paths) if suspicious_paths else 'None detected'}",
    ]

    if ssh_ips:
        formatted_ips = ", ".join(f"`{ip}` ({cnt})" for ip, cnt in ssh_ips.items())
        lines.append(f"- **SSH Rule 100200 Counts by Source IP:** {formatted_ips}")
    else:
        lines.append("- **SSH Rule 100200 Counts by Source IP:** None detected")

    if evasion:
        reasons = "; ".join(
            f"rule `{item['rule_id']}` (level {item['level']}): {item['reason']}"
            for item in evasion
        )
        lines.append(f"- **Evasion-Adjacent Indicators:** {reasons}")
    else:
        lines.append("- **Evasion-Adjacent Indicators:** None detected")

    return "\n".join(lines)
