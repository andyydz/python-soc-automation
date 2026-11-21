from typing import Any


VALID_STATUSES = {
    "new",
    "in_progress",
    "escalated",
    "closed",
    "false_positive",
}


def _validate_string_list(
    value: Any,
    field_name: str,
) -> list[str]:
    """
    Validate and return a copy of a list of non-empty strings.
    """

    if not isinstance(value, list):
        raise TypeError(f"{field_name} must be a list.")

    if not all(
        isinstance(item, str) and item.strip()
        for item in value
    ):
        raise ValueError(
            f"{field_name} must contain non-empty strings."
        )

    return list(value)


from soc_automation.enrichment.artifacts import extract_artifacts


def _extract_investigation_artifacts(
    alert: dict[str, Any],
    enrichment: dict[str, Any],
) -> dict[str, list[str]]:
    """Returns normalized artifact lists from enrichment or alert fallback."""
    keys = (
        "file_paths",
        "process_images",
        "target_process_images",
        "ip_addresses",
    )
    raw_artifacts = enrichment.get("artifacts")
    source = raw_artifacts if isinstance(raw_artifacts, dict) else extract_artifacts(alert)
    return {
        key: _validate_string_list(source.get(key, []), key)
        for key in keys
    }


def build_investigation(
    alert: dict[str, Any],
    enrichment: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Build an investigation-ready structure from a
    standardized alert and optional enrichment data.

    Original alert and enrichment inputs are never modified.
    """

    # 1. Validate top-level input
    if not isinstance(alert, dict):
        raise TypeError("alert must be a dictionary.")

    if enrichment is not None and not isinstance(enrichment, dict):
        raise TypeError("enrichment must be a dictionary or None.")

    # 2. Use an empty dictionary only when enrichment is omitted
    if enrichment is None:
        enrichment = {}

    # 3. Extract enrichment components
    rule_metadata = {} if enrichment.get("rule_metadata") is None else enrichment.get("rule_metadata")
    severity_context = {} if enrichment.get("severity_context") is None else enrichment.get("severity_context")
    mitre_attack = {} if enrichment.get("mitre_attack") is None else enrichment.get("mitre_attack")

    # 4. Validate enrichment component types
    components = {
        "rule_metadata": rule_metadata,
        "severity_context": severity_context,
        "mitre_attack": mitre_attack,
    }

    for name, component in components.items():
        if not isinstance(component, dict):
            raise TypeError(f"{name} must be a dictionary.")

    # 5. Extract original alert information
    rule_id = alert.get("rule_id")
    severity = alert.get("severity")
    description = alert.get("description")
    agent_name = alert.get("agent_name") or alert.get("agent")

    # 6. Validate enrichment lists
    groups = _validate_string_list(
        rule_metadata.get("groups", []),
        "groups",
    )

    techniques = _validate_string_list(
        mitre_attack.get("techniques", []),
        "techniques",
    )

    tactics = _validate_string_list(
        mitre_attack.get("tactics", []),
        "tactics",
    )

    artifacts = _extract_investigation_artifacts(alert, enrichment)

    # 7. Build investigation-ready output
    investigation = {
        "status": "new",
        "summary": description,

        "affected_asset": {
            "agent_name": agent_name,
            "asset_identifier": None,
            "ip_address": (
                artifacts["ip_addresses"][0]
                if artifacts["ip_addresses"]
                else None
            ),
        },

        "detection_details": {
            "rule_id": rule_id,
            "description": description,
            "severity": severity,
            "groups": groups,
            "mitre_techniques": techniques,
            "mitre_tactics": tactics,
        },

        "priority": {
            "label": severity_context.get("severity_label"),
            "reason": None,
            "source": severity_context.get(
                "classification_source"
            ),
        },

        "case_reference": None,
        "evidence": [
            {"type": kind, "value": val}
            for kind, vals in artifacts.items()
            for val in vals
        ],
        "analyst_notes": [],
    }

    return investigation