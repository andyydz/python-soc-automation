from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from soc_automation.enrichment.rule_metadata import (
    get_rule_metadata,
    RuleMetadataError,
)
from soc_automation.enrichment.severity import (
    get_severity_context,
)
from soc_automation.enrichment.mitre import (
    get_mitre_mapping,
    MitreDatasetError,
)
from soc_automation.enrichment.data_quality import (
    evaluate_alert_quality,
)


def enrich_alert(
    alert: dict[str, Any],
    rule_dataset_path: str | Path | None = None,
    mitre_dataset_path: str | Path | None = None,
) -> dict[str, Any]:
    """
    Enrich a standardized alert using local Wazuh metadata,
    severity context, MITRE ATT&CK mappings, and data-quality checks.

    The original alert is not modified.
    """

    if not isinstance(alert, dict):
        raise TypeError("alert must be a dictionary.")

    normalized_alert = alert.get("alert")

    if not isinstance(normalized_alert, dict):
        raise ValueError(
            "Standardized alert must contain an alert object."
        )

    rule_id = normalized_alert.get("rule_id")
    severity_level = normalized_alert.get("severity")

    enrichment = {
        "status": "complete",
        "rule_metadata": None,
        "severity_context": None,
        "mitre_attack": {
            "techniques": [],
            "tactics": [],
            "mapping_source": None,
        },
        "data_quality": {
            "status": "not_evaluated",
            "signals": [],
        },
        "provenance": {
            "enrichment_engine_version": "0.1.0",
            "methods": [],
            "sources": [],
            "processed_at": datetime.now(
                timezone.utc
            ).isoformat().replace("+00:00", "Z"),
        },
    }

    errors = []

    # 1. Wazuh rule metadata enrichment.
    try:
        if rule_dataset_path is None:
            metadata = get_rule_metadata(rule_id)
        else:
            metadata = get_rule_metadata(
                rule_id,
                rule_dataset_path,
            )

        enrichment["rule_metadata"] = metadata

        enrichment["provenance"]["methods"].append(
            "local_wazuh_rule_id_lookup"
        )

        if metadata is not None:
            enrichment["provenance"]["sources"].append(
                "wazuh_rules.json"
            )

    except (
        OSError,
        ValueError,
        TypeError,
        RuleMetadataError,
    ) as exc:
        errors.append(f"rule_metadata: {exc}")

    # 2. Severity context enrichment.
    try:
        severity_context = get_severity_context(
            severity_level
        )

        enrichment["severity_context"] = severity_context

        enrichment["provenance"]["methods"].append(
            "engine_defined_severity_classification"
        )

    except (ValueError, TypeError) as exc:
        errors.append(f"severity_context: {exc}")

    # 3. MITRE ATT&CK enrichment.
    try:
        if mitre_dataset_path is None:
            mitre_mapping = get_mitre_mapping(rule_id)
        else:
            mitre_mapping = get_mitre_mapping(
                rule_id,
                mitre_dataset_path,
            )

        enrichment["mitre_attack"] = {
            "techniques": mitre_mapping["techniques"],
            "tactics": mitre_mapping["tactics"],
            "mapping_source": mitre_mapping["mapping_source"],
        }

        enrichment["provenance"]["methods"].append(
            "local_wazuh_rule_id_mitre_lookup"
        )

        if mitre_mapping["mapping_source"] is not None:
            enrichment["provenance"]["sources"].append(
                mitre_mapping["mapping_source"]
            )

    except (
        OSError,
        ValueError,
        TypeError,
        MitreDatasetError,
    ) as exc:
        errors.append(f"mitre_attack: {exc}")

    # 4. Data-quality evaluation.
    try:
        quality_result = evaluate_alert_quality(alert)

        enrichment["data_quality"] = quality_result

        enrichment["provenance"]["methods"].append(
            "standardized_alert_quality_validation"
        )

    except (ValueError, TypeError) as exc:
        errors.append(f"data_quality: {exc}")

    # 5. Determine enrichment status.
    # Data-quality evaluation is independent of enrichment success.
    successful_components = sum([
        "local_wazuh_rule_id_lookup"
        in enrichment["provenance"]["methods"],

        "engine_defined_severity_classification"
        in enrichment["provenance"]["methods"],

        "local_wazuh_rule_id_mitre_lookup"
        in enrichment["provenance"]["methods"],
    ])

    if errors:
        if successful_components > 0:
            enrichment["status"] = "partial"
        else:
            enrichment["status"] = "unavailable"

    enrichment["provenance"]["errors"] = errors

    # Return a new envelope without modifying the input.
    result = alert.copy()
    result["schema_version"] = "1.1"
    result["enrichment"] = enrichment

    return result