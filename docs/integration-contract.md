# Python SOC Automation Engine: Integration Contract

## 1. Purpose and implementation status

This document defines the file-based interface of Python SOC Automation Engine: what the engine accepts, what it produces, and what consumers can rely on.

The engine has two CLI workflows:

- **Normal processing** produces the standardized output envelope at **schema version 1.2**. Sections 3 to 14 describe this envelope in detail.
- **Batch triage** (`--triage`) produces an aggregated Markdown or JSON report. It does not produce the normal single-alert envelope. See sections 2, 4.2, and 5.1.

| Milestone | Capability | Status |
|---|---|---|
| 1. Standardized Alert Output | File ingestion, parsing and validation, `raw_alert` preservation, standardized envelope, UTC timestamps, optional SHA-256, warnings, UTF-8 BOM support | Implemented |
| 2. Alert Enrichment | Optional local enrichment (`--enrich`), including offline artifact extraction | Implemented |
| 3. Investigation-Ready Output | `investigation` object, generated for every processed alert | Implemented |
| 4. CLI and Integration Interface | `soc-automation` CLI, JSON output to stdout or file, batch triage with Markdown and JSON reports | Implemented |

Field names and nesting for the normal-processing envelope follow the implementation (`pipeline.py`, `investigation/builder.py`, `enrichment/engine.py`, `enrichment/artifacts.py`, `parser.py`, and `ingestion.py`). Where the implementation does not fix a type, value, or format, this document says so rather than guessing.

The contract is independent of any consuming tool. The engine does not connect to or depend on SENTINEL or any other system at runtime. Its local datasets include rule metadata and MITRE mappings for custom SENTINEL Sysmon rules (section 8).

## 2. Supported input and input limitations

The two workflows accept different input.

### Normal processing (default)

| Item | Value |
|---|---|
| Format | JSON |
| Unit | One exported Wazuh alert object per file |
| Source | A local file |
| Encoding | UTF-8; a byte order mark is accepted (`utf-8-sig`) |
| Top-level value | Must be a JSON object |
| Output | The standardized schema `1.2` JSON envelope (section 5) |

Normal ingestion does **not** accept multiple alerts per file, JSON arrays, or NDJSON (JSON Lines). Those restrictions apply to normal processing only. They are not restrictions on the whole project.

### Batch triage (`--triage`)

| Item | Value |
|---|---|
| Format | JSON or NDJSON |
| Accepted input | A JSON array, a single JSON object, or NDJSON (parsed line by line when whole-input JSON parsing fails) |
| Source | A local file |
| Encoding | UTF-8; a byte order mark is accepted |
| Options | `--min-level` (default `8`), `--report-format` (`markdown` or `json`, default `markdown`), optional `--sha256` and `--enrich`, `-o` / `--output` |
| Output | An aggregated Markdown or JSON triage report. It is not the schema `1.2` envelope (section 5.1). |

### Not supported by either workflow

Live Wazuh manager or API ingestion, real-time monitoring, and other SIEM formats. The engine processes exported files only.

## 3. Input structure and validation (normal processing)

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

A missing or null `rule` or `agent`, and an invalid `rule.id` or `rule.level`, raise validation errors.

### Optional fields: validation versus warnings

Optional fields are handled in two stages. The parser rejects values of the wrong type. The pipeline records warnings for values that are absent or cannot be normalized.

| Input | Parser | Result |
|---|---|---|
| `rule.description`, `agent.name`, or `timestamp` missing or `null` | Accepted | A processing warning is recorded in `processing.warnings`. |
| `timestamp` is an empty, malformed, or timezone-free string | Accepted | A normalization warning is recorded, and `alert.timestamp_utc` is `null`. |
| An optional field has an invalid type, for example a numeric `timestamp`, a numeric `rule.description`, or a non-string `agent.name` | Rejected | A validation error. The CLI exits with a failure status. It is not a processing warning. |

### Failure categories

These categories describe normal processing. Triage mode applies its own input handling (section 2), and this contract does not define its per-alert error messages. Exact error messages are not part of this contract.

| Condition | Behavior |
|---|---|
| File cannot be read or decoded | Reported as an error. The CLI exits with a failure status. |
| Content is not valid JSON | Reported as an error. The CLI exits with a failure status. |
| Top-level JSON value is not an object | Reported as an error. The CLI exits with a failure status. |
| Parser validation failure (required structure or field missing or invalid, or an optional field with an invalid type) | Reported as a validation error. The CLI exits with a failure status. |
| Missing optional field or timestamp problem | Recorded in `processing.warnings`. Processing continues. |
| Data-quality issue (enrichment enabled) | Recorded as signals in `enrichment.data_quality.signals`, not in `processing.warnings`. Processing continues. |
| Enrichment error or unavailable dataset | Recorded in the enrichment status and `enrichment.provenance.errors` (section 8). |
| Output file cannot be written | Reported as an error. The CLI exits with a failure status. |

## 4. Processing workflows

### 4.1 Normal processing

1. The CLI receives a local JSON file path and the optional flags.
2. Ingestion reads the original file bytes.
3. If `--sha256` is set, the digest is calculated over those original bytes.
4. The bytes are decoded as UTF-8 JSON (BOM supported), and the top-level value is checked to be an object.
5. `pipeline.py` orchestrates processing. `parser.py` validates the alert and extracts its fields.
6. `normalizer.py` normalizes the timestamp to UTC.
7. `pipeline.py` builds the standardized output envelope.
8. If `--enrich` is set, the `enrichment` section is added.
9. The pipeline always generates the `investigation` object.
10. The CLI writes the JSON result to stdout or to the file given with `-o` / `--output`, creating missing output directories.

### 4.2 Batch triage (`--triage`)

1. The CLI receives a local input file path and the optional flags.
2. The original file bytes are read. If `--sha256` is set, the digest is calculated over those original bytes.
3. The bytes are decoded as UTF-8 (BOM supported) and parsed as a JSON array, a single JSON object, or NDJSON.
4. Alerts are filtered by severity using `--min-level` (default `8`).
5. The v0.7 triage context is built from the input alerts.
6. The aggregated summary report is generated from the filtered alerts.
7. If `--enrich` is set, the triaged alerts are enriched using local datasets.
8. The requested report (Markdown or JSON, from `--report-format`) is assembled, including the applicable context, digest, and enrichment information.
9. The result is written to stdout or to the file given with `-o` / `--output`.

## 5. Standardized output envelope (schema 1.2, normal processing)

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

### 5.1 Triage report output (not the envelope)

Triage mode produces an aggregated report, not the single-alert envelope above. Triage reports do not use `processing.integrity`.

| Aspect | Behavior |
|---|---|
| Formats | Markdown or JSON, selected with `--report-format`. |
| Source digest | With `--sha256`, the JSON report stores the digest as `source_sha256`. The digest is calculated over the original input bytes. |
| Enrichment | With `--enrich`, the JSON report includes the enriched records under `enrichments`. The Markdown report includes an enrichment summary. |
| Content | Aggregated alert summaries with additional triage context, and extracted FIM and Sysmon artifacts. |

This contract does not define the full structure of triage reports, the structure of individual records under `enrichments`, or a schema version for triage output. Verify those against actual output. Triage reports summarize and contextualize exported alerts. They do not confirm incidents or recommend response actions.

## 6. Field definitions and nullability (normal processing)

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
| `alert.timestamp_utc` | string | Yes | The timestamp normalized to UTC, as an ISO 8601 timestamp with a trailing `Z`. `null` when normalization cannot be performed. |
| `processing.warnings` | array | No | Processing warnings. May be empty. |
| `processing.integrity` | object | Yes | `null` when SHA-256 is disabled (section 11). |
| `raw_alert` | object | No | The original parsed alert. |

### Timestamp output format

`alert.timestamp_utc` is an ISO 8601 UTC timestamp with a trailing `Z` (for example, `2025-01-15T10:15:30Z`). Timezone-aware ISO 8601 input timestamps are converted to UTC, and the `+00:00` suffix is replaced with `Z`. The field is `null` when normalization cannot be performed, which happens when `timestamp` is absent, or when it is an empty, malformed, or timezone-free string. In those cases a warning is recorded in `processing.warnings` (section 3).

The structure of individual warning entries is not specified by this contract. Verify it against actual output. Warning codes are not defined.

## 7. Original versus normalized data

| Category | Location | Rule |
|---|---|---|
| Original data | `raw_alert` | The preserved original parsed alert, without modification. Authoritative. |
| Normalized fields | `alert` | Reformatting of source values, such as the UTC timestamp. Convenience copies that do not replace `raw_alert`. |
| Derived data | `enrichment`, `investigation` | Produced by the engine. Not source data. |
| Engine metadata | `source`, `processing` | Describes the origin and the processing, not the alert. |

If `alert` and `raw_alert` ever differ in meaning, `raw_alert` is the source of truth. `raw_alert` is the parsed alert and is not a byte-for-byte copy of the input file. For byte-level comparison, use the SHA-256 digest.

## 8. Optional enrichment structure and limitations

Enrichment is added only when `--enrich` is set, and it uses only local datasets. In normal processing it appears as the `enrichment` section. In triage mode, enriched records appear under `enrichments` (section 5.1).

| Key | Content |
|---|---|
| `status` | Overall enrichment status: `"complete"`, `"partial"`, or `"unavailable"`. The precise conditions for each value are not specified here. |
| `rule_metadata` | Local Wazuh rule metadata lookup result: an object or `null`. Internal structure not specified here. |
| `severity_context` | Engine-defined severity context with `original_level`, `severity_label`, and `classification_source`. |
| `mitre_attack.techniques` | Technique results from the local MITRE ATT&CK dataset. Empty for rule IDs with no mapping. |
| `mitre_attack.tactics` | Tactic results from the local MITRE ATT&CK dataset. Empty for rule IDs with no mapping. |
| `mitre_attack.mapping_source` | Where the mapping came from. `null` for rule IDs with no mapping. |
| `artifacts` | Extracted artifacts, as an object with four list fields (below). Present only as part of the `enrichment` section, so only when `--enrich` is set. |
| `data_quality.status` | Status of the data-quality checks: `"passed"` or `"issues_found"` when evaluation completes, or `"not_evaluated"`. |
| `data_quality.signals` | Data-quality signals raised for the alert. These are stored here, not in `processing.warnings`. |
| `provenance.enrichment_engine_version` | Version of the enrichment engine. |
| `provenance.methods` | Methods used. |
| `provenance.sources` | Sources used. |
| `provenance.processed_at` | When enrichment was processed. |
| `provenance.errors` | Errors encountered during enrichment. |

### Artifacts

`enrichment.artifacts` is extracted offline from supported alert structures, and each field is a list:

| Field | Content |
|---|---|
| `file_paths` | Extracted file paths. |
| `process_images` | Extracted process images. |
| `target_process_images` | Extracted target process images. |
| `ip_addresses` | Extracted IP addresses. |

A list is empty when no supported artifact of that category is found. These are values found in the alert itself, not conclusions about it. `enrichment.artifacts` is part of the optional enrichment section. It is distinct from `investigation.evidence`, which can contain extracted artifacts with or without enrichment (section 9).

### Data-quality status

The data-quality evaluator returns `"passed"` or `"issues_found"` when it completes. The enrichment engine initializes the status as `"not_evaluated"`, and that value can remain if evaluation fails. Consumers should handle all three values.

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

### MITRE ATT&CK dataset

`data/mitre_attack.json` currently contains **seven** custom SENTINEL Sysmon rule mappings, for rule IDs `100110`, `100111`, `100112`, `100120`, `100130`, `100131`, and `100140`. Each mapping contains technique IDs, tactic names, and the source `"SENTINEL Sysmon Replay Rules"`.

- Lookups use only this local dataset.
- A rule ID that is not in the dataset returns empty technique and tactic lists and a `null` mapping source. This is the expected result for most Wazuh rules.
- Mappings are never inferred or fabricated. A mapping appears only if it exists in the dataset.
- The dataset is limited. It does not represent complete MITRE ATT&CK coverage.
- The presence of a mapping does not establish that it has been independently validated against every possible detection scenario.

### Other limitations

- Local datasets cover only what has been added to them and are not a complete copy of Wazuh's ruleset.
- Enrichment is a decision aid, not an authoritative assessment.

## 9. Investigation object structure (normal processing)

The pipeline always generates `investigation`, with or without enrichment. It is a structured record, not case management.

| Path | Initial value or content |
|---|---|
| `status` | `"new"` |
| `summary` | Assigned directly from the alert description (`alert.description`). |
| `affected_asset.agent_name` | Agent name, when available from the alert. |
| `affected_asset.asset_identifier` | Currently `null`. The investigation builder sets it to `null` explicitly and does not populate it from alert data. |
| `affected_asset.ip_address` | `null` unless supported by available data. Can be populated from extracted IP information when available. |
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
| `evidence` | List of extracted artifacts; empty when no supported artifacts are found (below). |
| `analyst_notes` | Empty list |

### Evidence

`investigation.evidence` is a list of entries. Each entry has a `type` and a `value`. The builder uses the artifact dictionary keys directly as the entry `type`, so the possible `type` values are exactly:

- `file_paths`
- `process_images`
- `target_process_images`
- `ip_addresses`

Behavior:

- `evidence` is empty when no supported artifacts are found. It is not always empty.
- When enrichment artifacts are unavailable, the investigation builder calls artifact extraction directly. Therefore `investigation.evidence` can contain extracted artifacts **even when `--enrich` is disabled**.
- `enrichment.artifacts` (section 8), by contrast, is present only when `--enrich` is set.

When enrichment is disabled, enrichment-derived values (MITRE context and priority) may be empty or null. The engine does not invent asset information or analyst observations, and it does not create, look up, or manage cases. `analyst_notes` is a placeholder for later analyst input, and it starts as an empty list.

## 10. Processing warnings and errors

**Warnings.** Non-fatal findings such as missing optional fields and timestamp problems are recorded in `processing.warnings` and do not stop processing. This contract does not define warning codes or a warning entry structure. Optional fields with an invalid type are not warnings; they fail validation (section 3).

**Data-quality signals.** Data-quality issues are not stored in `processing.warnings`. When enrichment is enabled, they are recorded separately in `enrichment.data_quality.signals`, and `enrichment.data_quality.status` reports the result (section 8). When enrichment is disabled, no data-quality checks are reported.

**Errors.** Fatal conditions (section 3) are reported by the CLI with a failure status. This contract does not define error codes, exact messages, or an error payload format.

**Enrichment errors.** Enrichment problems are recorded in `enrichment.provenance.errors` and reflected in `enrichment.status`.

## 11. Optional SHA-256 integrity metadata

### Normal processing

`processing.integrity` is always present in the output.

| Condition | Value |
|---|---|
| `--sha256` not set | `null` |
| `--sha256` set | Object with `algorithm` (`"SHA-256"`) and `hash` (the calculated digest). |

### Triage mode

Triage reports do not use `processing.integrity`. When `--sha256` is set, the JSON report stores the digest as `source_sha256` (section 5.1).

### Both workflows

- The digest is calculated over the exact original input file bytes, before JSON decoding, and not over re-serialized JSON.
- The digest supports integrity comparison: anyone holding the same file can recompute it and compare.
- The digest does **not** prove authenticity. It does not show who created the file, that the alert is genuine, or that the source is trustworthy.

## 12. CLI usage and interface

The package is configured in `pyproject.toml` and supports editable installation (`python -m pip install -e .`). It provides the `soc-automation` entry point. Run `soc-automation --help` for the full usage text.

| Argument | Behavior |
|---|---|
| Input file (positional) | A local input file. Normal processing expects one Wazuh JSON alert object. With `--triage`, a JSON array, a single JSON object, or NDJSON is accepted. |
| `-o`, `--output` | Write the result to the specified file instead of stdout. Missing output directories are created automatically. |
| `--sha256` | Calculate SHA-256 over the original input bytes. Normal processing populates `processing.integrity`. Triage JSON output stores `source_sha256`. |
| `--enrich` | Enable local enrichment. Normal processing adds the `enrichment` section. Triage mode adds `enrichments` (JSON) or an enrichment summary (Markdown). |
| `--triage` | Enable the batch triage workflow. |
| `--min-level` | Minimum Wazuh rule level for triage. Default `8`. |
| `--report-format` | Triage report format: `markdown` or `json`. Default `markdown`. |

Examples:

```powershell
# Normal processing: one alert object, schema 1.2 envelope
soc-automation data/sample_logs/wazuh_alert.json --enrich --sha256

# Batch triage: aggregated JSON report with a custom threshold
soc-automation data/sample_logs/fim_lifecycle_evidence.json --triage --min-level 5 --report-format json
```

Without `-o` / `--output`, the result is written to stdout. Errors are reported with a failure exit status. Specific exit codes are not defined by this contract.

## 13. Schema compatibility

- The current schema version is **1.2**. It applies to the normal-processing envelope (section 5).
- Consumers should check `schema_version` before reading other fields.
- Consumers should reject major versions they do not support.
- Consumers should ignore unknown optional fields.
- Versioning policy: a minor version adds optional fields; a major version contains breaking changes, such as type changes, removals, or changed semantics.
- Consumers should treat `processing.integrity` as nullable rather than testing for the key's absence.
- Triage reports are not covered by the schema `1.2` envelope guarantees in this document.

## 14. Sanitized example input and output

All data is synthetic. Values in angle brackets are illustrative placeholders for content or formats that this contract does not specify, and they are not literal output. These examples show normal processing.

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

Enrichment and SHA-256 are disabled. `enrichment` is absent, `processing.integrity` is `null`, and `investigation` is still present with enrichment-derived values empty or null. The `summary` is taken directly from the alert description. The `evidence` list is empty because this synthetic input contains no fields from which supported artifacts can be extracted. The `groups` list is illustrative.

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

Only the sections that differ from the previous example are shown. For rule level 5, the severity context label is `"Medium"`, and `investigation.priority` is derived from it. The `severity_context` object shows its three keys. `rule_metadata` is shown as `null` for illustration, since its internal structure is not specified here, and the `enrichment` object includes placeholders where this contract does not specify the values.

Rule `5710` is not one of the seven mapped rule IDs (section 8). The empty `techniques` and `tactics` lists and the `null` `mapping_source` are therefore the expected result for this particular example. They do not mean the MITRE dataset is empty. The `artifacts` lists are empty because the synthetic input contains no extractable artifact fields.

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
    "artifacts": {
      "file_paths": [],
      "process_images": [],
      "target_process_images": [],
      "ip_addresses": []
    },
    "data_quality": {
      "status": "<passed | issues_found | not_evaluated>",
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
- `raw_alert` preserves the full original alert and may contain sensitive security information, such as hostnames, usernames, IP addresses, and log content. Extracted artifacts, evidence entries, and triage reports can contain file paths and IP addresses taken from the alert.
- Protect output files, and sanitize them before sharing or committing them to a repository.
- SHA-256 supports integrity comparison only. It is not a signature and does not prove authenticity.
- Do not place credentials, tokens, or secrets in input or output files.

### Integration boundaries

- The engine processes exported Wazuh JSON files. It does not connect to a live Wazuh manager or Wazuh API, and it does not monitor in real time.
- It performs no autonomous incident response. Any disruptive response action requires human approval.
- It is not a case-management platform. The `investigation` object is a structured record only.
- SENTINEL SOC Lab is a separate project. Exported SENTINEL alert data can be processed as files, and the engine's local datasets include metadata and MITRE mappings for custom SENTINEL Sysmon rules. There is no direct connection to the SENTINEL Wazuh manager and no automated cross-repository integration. File-based compatibility is not a live integration.
- Other SIEM platforms, such as Splunk, Elastic, and Microsoft Sentinel, are not current capabilities.
