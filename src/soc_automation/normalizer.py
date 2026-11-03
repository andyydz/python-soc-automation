from datetime import datetime, timezone
from typing import Any


def normalize_timestamp(timestamp_original: str | None) -> dict[str, Any]:
    """
    Convert a timezone-aware ISO 8601 timestamp to UTC.

    The original timestamp is not modified.
    Missing, malformed, or timezone-free timestamps
    produce a warning and a null UTC timestamp.
    """

    warnings = []

    if timestamp_original is None:
        return {
            "timestamp_utc": None,
            "warnings": [
                "Timestamp is missing; UTC normalization skipped."
            ],
        }

    if not isinstance(timestamp_original, str):
        raise TypeError("Timestamp must be a string or null.")

    # Treat empty or whitespace-only timestamps as malformed.
    if not timestamp_original.strip():
        return {
            "timestamp_utc": None,
            "warnings": [
                "Timestamp is empty; UTC normalization skipped."
            ],
        }

    try:
        parsed_timestamp = datetime.fromisoformat(timestamp_original)
    except ValueError:
        return {
            "timestamp_utc": None,
            "warnings": [
                "Timestamp has an invalid ISO 8601 format."
            ],
        }

    if (
        parsed_timestamp.tzinfo is None
        or parsed_timestamp.utcoffset() is None
    ):
        return {
            "timestamp_utc": None,
            "warnings": [
                "Timestamp has no timezone information; "
                "UTC normalization skipped."
            ],
        }

    utc_timestamp = parsed_timestamp.astimezone(timezone.utc)

    timestamp_utc = (
        utc_timestamp.isoformat().replace("+00:00", "Z")
    )

    return {
        "timestamp_utc": timestamp_utc,
        "warnings": warnings,
    }


def normalize_alert(parsed_alert: dict[str, Any]) -> dict[str, Any]:
    """
    Create a normalized alert from the parser output.
    """

    if not isinstance(parsed_alert, dict):
        raise TypeError("Parsed alert must be a dictionary.")

    # Normalize the original timestamp.
    timestamp_result = normalize_timestamp(
        parsed_alert.get("timestamp_original")
    )

    # Collect processing warnings.
    warnings = timestamp_result["warnings"].copy()

    if parsed_alert.get("description") is None:
        warnings.append("Rule description is missing.")

    if parsed_alert.get("agent") is None:
        warnings.append("Agent name is missing.")

    # Build the normalized alert.
    normalized_alert = {
        "rule_id": parsed_alert["rule_id"],
        "severity": parsed_alert["severity"],
        "agent": parsed_alert.get("agent"),
        "description": parsed_alert.get("description"),
        "timestamp_original": parsed_alert.get("timestamp_original"),
        "timestamp_utc": timestamp_result["timestamp_utc"],
        "warnings": warnings,
    }

    return normalized_alert