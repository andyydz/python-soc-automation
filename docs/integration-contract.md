# Python SOC Automation Engine: Integration Contract

## 1. Purpose and implementation status

This document defines the file-based interface of Python SOC Automation Engine: what the engine accepts, what it produces, and what consumers can rely on. It describes the implemented engine at **schema version 1.2**.

| Milestone | Capability | Status |
|---|---|---|
| 1. Standardized Alert Output | File ingestion, parsing and validation, `raw_alert` preservation, standardized envelope, UTC timestamps, optional SHA-256, warnings, UTF-8 BOM support | Implemented |
| 2. Alert Enrichment | Optional local enrichment (`--enrich`) | Implemented |
| 3. Investigation-Ready Output | `investigation` object, generated for every processed alert | Implemented |
| 4. CLI and Integration Interface | `soc-automation` CLI, JSON output to stdout or file | Implemented |

Field names and nesting in this document follow the implementation (`pipeline.py`, `investigation/builder.py`, `enrichment/engine.py`, `parser.py`, and `ingestion.py`). Where the implementation does not fix a type, value, or format, this document says so rather than guessing.

The contract is independent of any consuming tool. The engine does not depend on SENTINEL or any other system.

## 2. Supported input and input limitations

| Item | Value |
|---|---|
| Format | JSON |
| Unit | One exported Wazuh alert per file |
| Source | A local file |
| Encoding | UTF-8; a byte order mark is accepted (`utf-8-sig`) |
| Top-level value | Must be a JSON object |

Not supported: live Wazuh manager or API ingestion, multiple alerts per file, JSON Lines, and other SIEM formats. The engine processes exported files only.

## 3. Input structure and validation

### Fields used

Other fields in the alert are preserved in `raw_alert` and are not otherwise interpreted by the parser.

| Field | Requirement | Valid values |
|---|---|---|
| `rule` | Required | Dictionary |
| `rule.id` | Required | Non-empty string |
| `rule.level` | Required | Integer. A Python boolean is not accepted as an integer. |
| `agent` | Required | Dictionary |
| `rule.description` | Optional | String or null |
| `agent.name` | Optional | String or null |
| `timestamp` | Optional | String or null |

A missing or null `rule` or `agent`, and an invalid `rule.id` or `rule.level`, raise validation errors. A missing optional field is handled by the pipeline and recorded as a processing warning. Values of other types are not valid for the optional fields.

### Failure categories

Exact error messages are not part of this contract.

| Condition | Behavior |
|---|---|
| File cannot be read or decoded | Reported as an error. The CLI exits with a failure status. |
| Content is not valid JSON | Reported as an error. The CLI exits with a failure status. |
| Top-level JSON value is not an object | Reported as an error. The CLI exits with a failure status. |
| Parser validation failure (required structure or field missing or invalid) | Reported as a validation error. The CLI exits with a failure status. |
| Missing optional field or timestamp problem | Recorded in `processing.warnings`. Processing continues. |
| Data-quality issue (enrichment enabled) | Recorded as signals in `enrichment.data_quality.signals`, not in `processing.warnings`. Processing continues. |
| Enrichment error or unavailable dataset | Recorded in the enrichment status and `enrichment.provenance.errors` (section 8). |
| Output file cannot be written | Reported as an error. The CLI exits with a failure status. |

## 4. Processing workflow

1. The CLI receives a local JSON file path and the optional flags.
2. Ingestion reads the original file bytes.
3. If `--sha256` is set, the digest is calculated over those original bytes.
4. The bytes are decoded as UTF-8 JSON (BOM supported), and the top-level value is checked to be an object.
5. The pipeline parses and validates the alert.
6. The pipeline normalizes it into the standardized envelope, including UTC timestamp normalization.
7. If `--enrich` is set, the `enrichment` section is added.
8. The pipeline always generates the `investigation` object.
9. The CLI writes the JSON result to stdout or to the file given with `-o` / `--output`, creating missing output directories.

## 5. Standardized output envelope (schema 1.2)

| Key | Presence | Value |
|---|---|---|
| `schema_version` | Always | `"1.2"` |
| `record_type` | Always | `"normalized_alert"` |
| `source` | Always | Object with `product` (`"Wazuh"`) and `ingestion_type` (`"file_export"`). |
| `alert` | Always | Normalized alert fields (section 6). |
| `processing` | Always | Object with `warnings` and `integrity`. |
| `raw_alert` | Always | The original parsed alert, preserved without modification. |
| `enrichment` | Only when `--enrich` is set | Derived enrichment data (section 8). |
| `investigation` | Always | Investigation-ready object, generated whether or not enrichment is enabled (section 9). |

## 6. Field definitions and nullability

| Path | Type | Nullable | Notes |
|---|---|---|---|
| `schema_version` | string | No | `"1.2"` |
| `record_type` | string | No | `"normalized_alert"` |
| `source.product` | string | No | `"Wazuh"` |
| `source.ingestion_type` | string | No | `"file_export"` |
| `alert.rule_id` | string | No | From `rule.id`. Non-empty. |
| `alert.severity` | integer | No | From `rule.level`, unchanged. |
| `alert.agent` | string | Yes | From `agent.name`. `null` when absent. |
| `alert.description` | string | Yes | From `rule.description`. `null` when absent. |
| `alert.timestamp_original` | string | Yes | The input `timestamp` value. `null` when absent. |
| `alert.timestamp_utc` | string | Yes | The timestamp normalized to UTC. `null` when it cannot be normalized. |
| `processing.warnings` | array | No | Processing warnings. May be empty. |
| `processing.integrity` | object | Yes | `null` when SHA-256 is disabled (section 11). |
| `raw_alert` | object | No | The original parsed alert. |

The textual form of `alert.timestamp_utc` (for example, a `Z` suffix or a `+00:00` offset) and the structure of individual warning entries are not specified by this contract. Verify them against actual output. Warning codes are not defined.

## 7. Original versus normalized data

| Category | Location | Rule |
|---|---|---|
| Original data | `raw_alert` | The preserved original parsed alert, without modification. Authoritative. |
| Normalized fields | `alert` | Reformatting of source values, such as the UTC timestamp. Convenience copies that do not replace `raw_alert`. |
| Derived data | `enrichment`, `investigation` | Produced by the engine. Not source data. |
| Engine metadata | `source`, `processing` | Describes the origin and the processing, not the alert. |

If `alert` and `raw_alert` ever differ in meaning, `raw_alert` is the source of truth. `raw_alert` is the parsed alert and is not a byte-for-byte copy of the input file. For byte-level comparison, use the SHA-256 digest.

## 8. Optional enrichment structure and limitations

Enrichment is added only when `--enrich` is set, and it uses only local datasets.

| Key | Content |
|---|---|
| `status` | Overall enrichment status: `"complete"`, `"partial"`, or `"unavailable"`. The precise conditions for each value are not specified here. |
| `rule_metadata` | Local Wazuh rule metadata lookup result: an object or `null`. Internal structure not specified here. |
| `severity_context` | Engine-defined severity context with `original_level`, `severity_label`, and `classification_source`. |
| `mitre_attack.techniques` | Technique results from the local MITRE ATT&CK dataset. |
| `mitre_attack.tactics` | Tactic results from the local MITRE ATT&CK dataset. |
| `mitre_attack.mapping_source` | Where the mapping came from. |
| `data_quality.status` | Status of the data-quality checks: `"passed"` or `"issues_found"`. |
| `data_quality.signals` | Data-quality signals raised for the alert. These are stored here, not in `processing.warnings`. |
| `provenance.enrichment_engine_version` | Version of the enrichment engine. |
| `provenance.methods` | Methods used. |
| `provenance.sources` | Sources used. |
| `provenance.processed_at` | When enrichment was processed. |
| `provenance.errors` | Errors encountered during enrichment. |

### Severity context

These ranges are defined by this engine. They are not official Wazuh severity categories. The original rule level is preserved in `alert.severity` and `raw_alert`.

| Rule level | Severity context |
|---|---|
| 0 | Ignored |
| 1 to 4 | Low |
| 5 to 7 | Medium |
| 8 to 11 | High |
| 12 to 15 | Critical |

The severity context accepts integer levels from 0 through 15. A value outside this range causes the severity enrichment component to fail and may affect the overall enrichment status. Such a failure is an enrichment error (see `enrichment.provenance.errors`), not a change to the preserved original level.

### Limitations

- The MITRE ATT&CK dataset currently has no verified rule mappings. The lookup mechanism exists, but no technique mappings are populated, so consumers should expect empty technique results.
- Mappings are never inferred or fabricated. A mapping appears only if it exists in the local dataset.
- Local datasets cover only what has been added to them and are not a complete copy of Wazuh's ruleset.
- Enrichment is a decision aid, not an authoritative assessment.

## 9. Investigation object structure

The pipeline always generates `investigation`, with or without enrichment. It is a structured record, not case management.

| Path | Initial value or content |
|---|---|
| `status` | `"new"` |
| `summary` | Assigned directly from the alert description (`alert.description`). |
| `affected_asset.agent_name` | Agent name, when available from the alert. |
| `affected_asset.asset_identifier` | `null` unless supported by available data. |
| `affected_asset.ip_address` | `null` unless supported by available data. |
| `detection_details.rule_id` | Rule identifier. |
| `detection_details.description` | Rule description. |
| `detection_details.severity` | Original rule level. |
| `detection_details.groups` | Rule groups. |
| `detection_details.mitre_techniques` | MITRE techniques. Enrichment-derived. |
| `detection_details.mitre_tactics` | MITRE tactics. Enrichment-derived. |
| `priority.label` | Taken from `enrichment.severity_context.severity_label`. Enrichment-derived. |
| `priority.reason` | Currently `null`. |
| `priority.source` | Taken from `enrichment.severity_context.classification_source`. Enrichment-derived. |
| `case_reference` | `null` |
| `evidence` | Empty list |
| `analyst_notes` | Empty list |

When enrichment is disabled, enrichment-derived values may be empty or null. The engine does not invent asset information or analyst observations, and it does not create, look up, or manage cases. `evidence` and `analyst_notes` are placeholders for later analyst input.

## 10. Processing warnings and errors

**Warnings.** Non-fatal findings such as missing optional fields and timestamp problems are recorded in `processing.warnings` and do not stop processing. This contract does not define warning codes or a warning entry structure.

**Data-quality signals.** Data-quality issues are not stored in `processing.warnings`. When enrichment is enabled, they are recorded separately in `enrichment.data_quality.signals`, and `enrichment.data_quality.status` reports the result (section 8). When enrichment is disabled, no data-quality checks are reported.

**Errors.** Fatal conditions (section 3) are reported by the CLI with a failure status. This contract does not define error codes, exact messages, or an error payload format.

**Enrichment errors.** Enrichment problems are recorded in `enrichment.provenance.errors` and reflected in `enrichment.status`.

## 11. Optional SHA-256 integrity metadata

`processing.integrity` is always present in the output.

| Condition | Value |
|---|---|
| `--sha256` not set | `null` |
| `--sha256` set | Object with `algorithm` (`"SHA-256"`) and `hash` (the calculated digest). |

- The digest is calculated over the exact original input file bytes, before JSON decoding, and not over re-serialized JSON.
- The digest supports integrity comparison: anyone holding the same file can recompute it and compare.
- The digest does **not** prove authenticity. It does not show who created the file, that the alert is genuine, or that the source is trustworthy.

## 12. CLI usage and interface

The package is configured in `pyproject.toml` and supports editable installation (`python -m pip install -e .`). It provides the `soc-automation` entry point. Run `soc-automation --help` for the full usage text.

| Argument | Behavior |
|---|---|
| Input file (positional) | A local Wazuh JSON alert file. |
| `-o`, `--output` | Write the JSON result to the specified file instead of stdout. Missing output directories are created automatically. |
| `--sha256` | Calculate SHA-256 over the original input bytes and populate `processing.integrity`. |
| `--enrich` | Add the `enrichment` section. |

Without `-o` / `--output`, the JSON result is written to stdout. Errors are reported with a failure exit status. Specific exit codes are not defined by this contract.

## 13. Schema compatibility

- The current schema version is **1.2**.
- Consumers should check `schema_version` before reading other fields.
- Consumers should reject major versions they do not support.
- Consumers should ignore unknown optional fields.
- Versioning policy: a minor version adds optional fields; a major version contains breaking changes, such as type changes, removals, or changed semantics.
- Consumers should treat `processing.integrity` as nullable rather than testing for the key's absence.

## 14. Sanitized example input and output

All data is synthetic. Values in angle brackets are illustrative placeholders for content or formats that this contract does not specify, and they are not literal output.

### Example input

```json
{
  "timestamp": "2025-01-15T10:15:30+00:00",
  "rule": {
    "id": "5710",
    "level": 5,
    "description": "sshd: attempt to login using a non-existent user"
  },
  "agent": {
    "name": "web-server-01"
  }
}
```

### Output with no flags

Enrichment and SHA-256 are disabled. `enrichment` is absent, `processing.integrity` is `null`, and `investigation` is still present with enrichment-derived values empty or null. The `summary` is taken directly from the alert description. The `groups` list and the exact `timestamp_utc` form are illustrative.

```json
{
  "schema_version": "1.2",
  "record_type": "normalized_alert",
  "source": {
    "product": "Wazuh",
    "ingestion_type": "file_export"
  },
  "alert": {
    "rule_id": "5710",
    "severity": 5,
    "agent": "web-server-01",
    "description": "sshd: attempt to login using a non-existent user",
    "timestamp_original": "2025-01-15T10:15:30+00:00",
    "timestamp_utc": "2025-01-15T10:15:30Z"
  },
  "processing": {
    "warnings": [],
    "integrity": null
  },
  "raw_alert": {
    "timestamp": "2025-01-15T10:15:30+00:00",
    "rule": {
      "id": "5710",
      "level": 5,
      "description": "sshd: attempt to login using a non-existent user"
    },
    "agent": {
      "name": "web-server-01"
    }
  },
  "investigation": {
    "status": "new",
    "summary": "sshd: attempt to login using a non-existent user",
    "affected_asset": {
      "agent_name": "web-server-01",
      "asset_identifier": null,
      "ip_address": null
    },
    "detection_details": {
      "rule_id": "5710",
      "description": "sshd: attempt to login using a non-existent user",
      "severity": 5,
      "groups": [],
      "mitre_techniques": [],
      "mitre_tactics": []
    },
    "priority": {
      "label": null,
      "reason": null,
      "source": null
    },
    "case_reference": null,
    "evidence": [],
    "analyst_notes": []
  }
}
```

### Output with `--sha256` and `--enrich`

Only the sections that differ from the previous example are shown. For rule level 5, the severity context label is `"Medium"`, and `investigation.priority` is derived from it. The `severity_context` object shows its three keys. `rule_metadata` is shown as `null` for illustration, since its internal structure is not specified here, and the `enrichment` object includes placeholders where this contract does not specify the values. The empty `techniques` and `tactics` lists and the `null` `mapping_source` reflect the current dataset, which has no verified rule mappings.

```json
{
  "processing": {
    "warnings": [],
    "integrity": {
      "algorithm": "SHA-256",
      "hash": "<SHA-256 digest of the original input file bytes>"
    }
  },
  "enrichment": {
    "status": "<complete | partial | unavailable>",
    "rule_metadata": null,
    "severity_context": {
      "original_level": 5,
      "severity_label": "Medium",
      "classification_source": "python_soc_automation"
    },
    "mitre_attack": {
      "techniques": [],
      "tactics": [],
      "mapping_source": null
    },
    "data_quality": {
      "status": "<passed | issues_found>",
      "signals": []
    },
    "provenance": {
      "enrichment_engine_version": "<version>",
      "methods": ["<method>"],
      "sources": ["<source>"],
      "processed_at": "<timestamp>",
      "errors": []
    }
  },
  "investigation": {
    "priority": {
      "label": "Medium",
      "reason": null,
      "source": "python_soc_automation"
    }
  }
}
```

## 15. Security considerations and integration boundaries

### Security

- Treat input files as untrusted. The engine validates them, and consumers should not execute any content from them.
- `raw_alert` preserves the full original alert and may contain sensitive security information, such as hostnames, usernames, IP addresses, and log content.
- Protect output files, and sanitize them before sharing or committing them to a repository.
- SHA-256 supports integrity comparison only. It is not a signature and does not prove authenticity.
- Do not place credentials, tokens, or secrets in input or output files.

### Integration boundaries

- The engine processes exported Wazuh JSON files. It does not connect to a live Wazuh manager or Wazuh API.
- It performs no autonomous incident response. Any disruptive response action requires human approval.
- It is not a case-management platform. The `investigation` object is a structured record only.
- SENTINEL SOC Lab is a separate project. A file-based exchange with SENTINEL is a future possibility and is not implemented.
- Other SIEM platforms, such as Splunk, Elastic, and Microsoft Sentinel, are not current capabilities.
