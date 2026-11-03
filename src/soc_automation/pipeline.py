from typing import Any

from soc_automation.parser import parse_wazuh_alert
from soc_automation.normalizer import normalize_timestamp
from soc_automation.enrichment.engine import enrich_alert


def process_wazuh_alert(
    alert: dict[str, Any],
    sha256_hash: str | None = None,
    include_enrichment: bool = False,
) -> dict[str, Any]:
    """
    Validate, normalize, and structure a Wazuh alert.

    Optionally includes SHA-256 integrity metadata
    and alert enrichment.
    """

    # 1. Validate enrichment option
    if not isinstance(include_enrichment, bool):
        raise TypeError("include_enrichment must be a boolean.")

    # 2. Validate and extract alert information
    parsed_alert = parse_wazuh_alert(alert)

    # 3. Normalize the original timestamp
    timestamp_result = normalize_timestamp(
        parsed_alert["timestamp_original"]
    )

    # 4. Collect timestamp warnings
    warnings = list(timestamp_result["warnings"])

    # 5. Add warnings for missing optional fields
    if parsed_alert["description"] is None:
        warnings.append("Rule description is missing.")

    if parsed_alert["agent"] is None:
        warnings.append("Agent name is missing.")

    # 6. Build the processed alert
    processed_alert = {
        "rule_id": parsed_alert["rule_id"],
        "severity": parsed_alert["severity"],
        "agent": parsed_alert["agent"],
        "description": parsed_alert["description"],
        "timestamp_original": parsed_alert["timestamp_original"],
        "timestamp_utc": timestamp_result["timestamp_utc"],
    }

    # 7. Build optional integrity metadata
    integrity = None

    if sha256_hash is not None:
        integrity = {
            "algorithm": "SHA-256",
            "hash": sha256_hash,
        }

    # 8. Build the standardized output envelope
    result = {
        "schema_version": "1.0",
        "record_type": "normalized_alert",
        "source": {
            "product": "Wazuh",
            "ingestion_type": "file_export",
        },
        "alert": processed_alert,
        "processing": {
            "warnings": warnings,
            "integrity": integrity,
        },
        "raw_alert": alert,
    }

    # 9. Optionally enrich the standardized alert
    if include_enrichment:

        # The enrichment engine expects agent_name.
        # Adapt a copy without changing the public alert schema.
        enrichment_input = {
            **result,
            "alert": {
                **result["alert"],
                "agent_name": result["alert"]["agent"],
            },
        }

        enriched_result = enrich_alert(enrichment_input)

        # Restore the original standardized alert structure.
        enriched_result["alert"] = result["alert"]

        result = enriched_result

    # 10. Return the final result
    return result