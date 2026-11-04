# Sample Input and Output

Developer: Andrew Vinston D'Souza

Related: [README](../README.md) | [Architecture](architecture.md) | [Integration contract](integration-contract.md) | [Testing](testing.md) | [Development log](development-log.md)

## 1. Purpose

This guide walks through the Python SOC Automation Engine end to end, using one synthetic Wazuh alert: the command-line options, the Python entry point, the schema 1.2 output, and the validation rules.

The engine processes exported Wazuh alert JSON files. It does not connect to a live Wazuh manager or API.

All commands and outputs below are **examples**. They were not captured from a run, and values marked with angle brackets are illustrative placeholders. The field names and structure follow schema 1.2. For the formal definition, see the [integration contract](integration-contract.md).

## 2. Setup

Python 3.10 or newer is required. From the repository root, in PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e .
soc-automation --help
```

On Linux or macOS, activate the environment with `source .venv/bin/activate` instead.

## 3. Sample Input

All examples use this synthetic alert:

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

The command examples assume this alert is saved as `examples/sample_wazuh_alert.json`. **You must create that file before running the commands.** It is not part of the repository unless you add it. The repository's existing sample file, `data/sample_logs/wazuh_alert.json`, contains a different alert (rule `550`, level `7`, no timestamp) and should be left unchanged.

In PowerShell, from the repository root:

```powershell
New-Item -ItemType Directory -Force examples | Out-Null
@'
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
'@ | Set-Content -Path examples/sample_wazuh_alert.json -Encoding utf8
```

A file saved with a UTF-8 byte order mark is accepted.

## 4. Command-Line Examples

| Argument | Behavior |
|---|---|
| Input file (positional) | Local Wazuh JSON alert file. |
| `-o`, `--output` | Write the JSON result to a file instead of stdout. Missing output directories are created automatically. |
| `--sha256` | Calculate SHA-256 over the original input bytes. |
| `--enrich` | Add local enrichment. |

**A. Standard processing.** Writes the JSON result to stdout.

```powershell
soc-automation examples/sample_wazuh_alert.json
```

**B. Saving output.** Creates the `output` directory if it does not exist.

```powershell
soc-automation examples/sample_wazuh_alert.json --output output/processed_alert.json
Get-Content output/processed_alert.json
```

**C. SHA-256.**

```powershell
soc-automation examples/sample_wazuh_alert.json --sha256
```

**D. Enrichment.**

```powershell
soc-automation examples/sample_wazuh_alert.json --enrich
```

**E. Combined processing.**

```powershell
soc-automation examples/sample_wazuh_alert.json --sha256 --enrich --output output/enriched_alert.json
```

If an error occurs, the CLI reports it and exits with a failure status. Check the exit status with `$LASTEXITCODE` in PowerShell.

## 5. Python Usage

**F. Python API.** `ingest_wazuh_alert_file()` in `soc_automation.ingestion` reads the file, optionally calculates SHA-256, decodes the JSON, validates the top-level object, and runs the processing pipeline.

The signature is:

```python
ingest_wazuh_alert_file(file_path, include_sha256=False, include_enrichment=False)
```

Both options are off by default, matching the CLI. `include_sha256=True` corresponds to `--sha256`, and `include_enrichment=True` corresponds to `--enrich`.

```python
import json

from soc_automation.ingestion import ingest_wazuh_alert_file

# Standard processing (no optional flags)
result = ingest_wazuh_alert_file("examples/sample_wazuh_alert.json")

# SHA-256 and enrichment enabled
result = ingest_wazuh_alert_file(
    "examples/sample_wazuh_alert.json",
    include_sha256=True,
    include_enrichment=True,
)

print(json.dumps(result, indent=2))
```

The function returns the processed result in the structure shown in section 6. Outside an editable install, add `src` to the import path first (in PowerShell, `$env:PYTHONPATH = "src"`).

## 6. Output Examples

### 6.1 Standard output (no optional flags)

For command A. `enrichment` is absent, `processing.integrity` is `null`, and `investigation` is still present.

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

Notes:

- `raw_alert` is the original parsed alert, preserved without modification. The `alert` section holds normalized fields and does not replace it.
- The exact textual form of `timestamp_utc` (for example, a `Z` suffix versus `+00:00`) and the `groups` list are illustrative.
- Without enrichment, enrichment-derived investigation values may be empty or null.

### 6.2 With `--sha256`

For command C. Only `processing` differs from the standard output.

```json
{
  "processing": {
    "warnings": [],
    "integrity": {
      "algorithm": "SHA-256",
      "hash": "<SHA-256 digest of the original input file bytes>"
    }
  }
}
```

The digest is calculated over the exact original file bytes, before decoding. It supports integrity comparison only. It does not prove authenticity or that the source is trustworthy.

### 6.3 With `--enrich`

For command D. `enrichment` is added, and the priority in `investigation` is derived from the severity context. Only the sections that differ from the standard output are shown.

```json
{
  "enrichment": {
    "status": "complete",
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
      "status": "passed",
      "signals": []
    },
    "provenance": {
      "enrichment_engine_version": "<version>",
      "methods": [
        "local_wazuh_rule_id_lookup",
        "engine_defined_severity_classification",
        "local_wazuh_rule_id_mitre_lookup",
        "standardized_alert_quality_validation"
      ],
      "sources": [],
      "processed_at": "<ISO 8601 timestamp of the run>",
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

Notes:

- `status` can be `"complete"`, `"partial"`, or `"unavailable"`. This example assumes all enrichment components succeeded.
- `data_quality.status` is `"passed"` or `"issues_found"`. This example assumes the sample satisfies the data-quality checks. Any issues would appear in `enrichment.data_quality.signals`, not in `processing.warnings`.
- `rule_metadata` is `null` because there is no matching local rule metadata entry for rule `5710`.
- **The MITRE ATT&CK dataset currently has no verified rule mappings.** Technique and tactic lists are empty and `mapping_source` is `null`. No mappings are invented.
- Severity context uses engine-defined ranges (0 Ignored, 1 to 4 Low, 5 to 7 Medium, 8 to 11 High, 12 to 15 Critical). These are not official Wazuh severity categories.
- `provenance.methods` lists the implemented enrichment methods. `provenance.sources` is empty here because no local dataset source was recorded for this example, since rule `5710` has no matching metadata or MITRE entry.
- `enrichment_engine_version` and `processed_at` are illustrative placeholders. In real output, `processed_at` is the time of the run.

Command E combines both: `processing.integrity` is populated and `enrichment` is present.

### 6.4 The investigation object

`investigation` is always generated, with or without enrichment:

| Field | Content |
|---|---|
| `status` | `"new"` |
| `summary` | Taken directly from the alert description. |
| `affected_asset` | `agent_name`, `asset_identifier`, `ip_address`. Asset fields are `null` unless supported by available data. |
| `detection_details` | `rule_id`, `description`, `severity`, `groups`, `mitre_techniques`, `mitre_tactics`. |
| `priority` | `label` and `source` come from the severity context when enrichment is enabled. `reason` is currently `null`. |
| `case_reference` | `null` |
| `evidence` | Empty list |
| `analyst_notes` | Empty list |

The engine does not invent asset information or analyst observations. `evidence` and `analyst_notes` are placeholders for later analyst input. This is a structured record, not a case-management platform.

### 6.5 Example output versus guaranteed output

The structure and field names above follow schema 1.2. The values are examples. Warning entries, provenance details, exact timestamp formatting, and the contents of `rule_metadata` depend on the input and the local datasets, so do not treat the examples as exact output.

## 7. Validation

The parser validates required structure before processing.

| Field | Requirement |
|---|---|
| `rule` | Required. Must be an object. |
| `agent` | Required. Must be an object. |
| `rule.id` | Required. Must be a non-empty string. |
| `rule.level` | Required. Must be an integer. A boolean is not accepted. |
| `rule.description` | Optional. String or null. |
| `agent.name` | Optional. String or null. |
| `timestamp` | Optional. String or null. |

- A missing or null required structure, or an invalid required value, is an error. The CLI reports it and exits with a failure status.
- A missing optional value does not fail processing. It produces a warning in `processing.warnings` and a `null` in the matching `alert` field.
- A partial alert no longer succeeds through parser defaults. Required fields must be valid.

Examples of invalid input (each is an error):

```json
{ "rule": null, "agent": { "name": "web-server-01" } }
```

```json
{ "rule": { "id": "", "level": 5 }, "agent": { "name": "web-server-01" } }
```

```json
{ "rule": { "id": "5710", "level": true }, "agent": { "name": "web-server-01" } }
```

The first has a null `rule`, the second an empty `rule.id`, and the third a boolean `rule.level`.

Example of a valid alert with missing optional values:

```json
{ "rule": { "id": "5710", "level": 5 }, "agent": {} }
```

This alert is processed. `alert.description`, `alert.agent`, `alert.timestamp_original`, and `alert.timestamp_utc` are `null`, and `processing.warnings` contains warning entries for the missing values. The structure of warning entries and exact error messages are not defined in this guide.

Other failures reported as errors include an unreadable or undecodable file, invalid JSON, a top-level JSON value that is not an object, and an output file that cannot be written.

## 8. Project Boundaries

- This is file-based Wazuh alert processing. There is no live Wazuh manager or API connection.
- There is no autonomous incident response.
- It is not a full case-management platform.
- SENTINEL SOC Lab is a separate project. Integration remains future work and is not implemented.
- The MITRE ATT&CK dataset currently has no verified rule mappings.
- Other SIEM input formats are not supported.
- Alerts may contain sensitive data. Treat input and output files accordingly, and use sanitized samples when sharing.
