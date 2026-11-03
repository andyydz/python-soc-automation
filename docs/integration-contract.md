# Python SOC Automation Engine — Integration Contract

> **Status: draft for human review.** This contract is **Proposed** and follows Architecture Specification v1.0. It describes the intended interface of the *future* engine. Today, only the Python function `parse_wazuh_alert(alert: dict[str, Any])` is **Implemented**. There is no JSON file loading, CLI, live Wazuh API connection, normalization, SHA-256 hashing or SENTINEL integration yet. The input requirements (section 2) and validation behavior (section 3) are finalized decisions, but they describe **Planned** behavior and are not claimed to be implemented.

| Label | Meaning |
|---|---|
| **Implemented** | Exists and is tested. |
| **Planned** | Approved milestone, not yet built. |
| **Proposed** | Contract detail not yet built or finally confirmed. |

The contract is independent of any consuming system. SENTINEL, or any other tool, may consume the output; the engine does not depend on it.

---

## 1. Supported input

| Item | Value |
|---|---|
| Format | JSON |
| Unit | **One Wazuh alert per file** |
| Origin | Alert exported to a file (`source.ingestion_type = "file_export"`) |
| Encoding | UTF-8 (**Proposed**) |
| Not supported | Live Wazuh API ingestion, multiple alerts per file, JSON Lines, other SIEM formats |

Current state: the **Implemented** parser accepts a Python dictionary. File loading will be implemented separately (Milestone 4).

---

## 2. Expected Wazuh input structure

Only the fields below are used by this contract. Other fields present in a Wazuh alert are preserved in `raw_alert` and otherwise ignored.

| Field | Type | Used for | Requirement |
|---|---|---|---|
| `rule` | object | Rule data | **Required** object |
| `rule.id` | string | Rule ID | **Required**, non-empty string |
| `rule.level` | integer | Original severity | **Required** integer |
| `rule.description` | string | Rule description | Optional string |
| `agent` | object | Agent data | **Required** object |
| `agent.name` | string | Agent name | Optional string |
| `timestamp` | string | Original and normalized timestamp | Optional string |

Handling of optional fields:

- **Missing:** the corresponding output value is `null` and a warning is recorded.
- **Present with an invalid type:** a validation error is reported (section 3).

These requirements describe the **Planned** engine. How the currently **Implemented** parser handles each case should be confirmed against its code and tests.

---

## 3. Input validation rules

| # | Condition | Class | Result |
|---|---|---|---|
| 1 | File missing or unreadable | Fatal error | Stop; report. No output record. |
| 2 | Content is not valid JSON | Fatal error | Stop; report. No output record. |
| 3 | Top-level value is not an object | Fatal error | Stop; report. No output record. |
| 4 | `rule` or `agent` missing, `null` or not an object | Validation error | Report field and reason. No output record. |
| 5 | `rule.id` missing, not a string, or empty | Validation error | Report field and reason. No output record. |
| 6 | `rule.level` missing or not an integer | Validation error | Report field and reason. No output record. |
| 7 | Optional field present with an invalid type (`rule.description`, `agent.name` or `timestamp` not a string) | Validation error | Report field and reason. No output record. |
| 8 | Optional field missing | Warning | Value `null`; warning recorded; output record still produced. |
| 9 | `timestamp` is a string but malformed or ambiguous | Warning | Normalized timestamp `null`; warning recorded; output record still produced. |
| 10 | Enrichment unavailable | Informational | Skipped with explanation. |
| 11 | Output cannot be written | Reported error | State the path and reason. |

Outcomes:

- **Fatal errors (1–3) and validation errors (4–7) produce no normalized output record.** A clear error report is returned separately (section 8).
- **Missing optional fields (8) and unparseable timestamp strings (9) still produce a valid output record** with `null` values and warnings.
- A missing, `null` or malformed `rule` or `agent` object is handled by rule 4. It must **not** be silently converted to an empty dictionary, because that would turn a structural problem into an apparent missing-field warning.
- **Proposed:** an optional field present with an explicit `null` is treated as missing (rule 8).

---

## 4. Standardized output envelope (Proposed)

| Section | Purpose |
|---|---|
| `schema_version` | Contract version, `"1.0"`. |
| `record_type` | Identifies the record. Proposed value: `"normalized_alert"`. |
| `source` | Origin metadata: system, `ingestion_type` and input file reference. |
| `alert` | Normalized alert fields. |
| `processing` | Engine name and version, outcome, warnings and optional `integrity` block. |
| `raw_alert` | The authoritative preserved original parsed Wazuh alert, unmodified. |
| `enrichment` | Optional. Derived data (Milestone 2). |
| `investigation` | Optional. Investigation-ready data (Milestone 3). |

The envelope is produced only when processing succeeds, with or without warnings. Fatal and validation errors do not produce an envelope.

---

## 5. Required and optional fields (Milestone 1)

| Path | Required | Type | Nullable | Notes |
|---|---|---|---|---|
| `schema_version` | Yes | string | No | `"1.0"` |
| `record_type` | Yes | string | No | |
| `source.system` | Yes | string | No | `"wazuh"` |
| `source.ingestion_type` | Yes | string | No | `"file_export"` |
| `source.input_file.name` | Yes | string | No | File name only. |
| `alert.rule_id` | Yes | string | No | From required `rule.id`; non-empty. |
| `alert.severity` | Yes | integer | No | From required `rule.level`, unchanged. |
| `alert.rule_description` | Yes | string | **Yes** | `null` + warning if missing. |
| `alert.agent_name` | Yes | string | **Yes** | `null` + warning if missing. |
| `alert.timestamp_original` | Yes | string | **Yes** | Exact input value; `null` + warning if missing. |
| `alert.timestamp_utc` | Yes | string | **Yes** | UTC with `Z`; `null` + warning if missing, malformed or ambiguous. |
| `processing.engine` | Yes | object | No | Name and version. |
| `processing.status` | Yes | string | No | `"success"` or `"success_with_warnings"` (section 8). |
| `processing.warnings` | Yes | array | No | May be empty. |
| `processing.integrity` | Optional | object | — | Present only when SHA-256 is enabled. |
| `raw_alert` | Yes | object | No | Authoritative preserved original. |
| `enrichment` | Optional | object | — | Absent in Milestone 1. |
| `investigation` | Optional | object | — | Absent in Milestone 1. |

"Required" means the key is always present. Nullable required keys hold `null` when the source value is unavailable.

---

## 6. Original alert preservation

- `raw_alert` is the **authoritative** preserved source object. It holds the original parsed Wazuh alert, with no fields added, removed or modified.
- Fields in `alert` may retain values that correspond to the original (for example, `alert.severity` and `alert.timestamp_original`). They are convenience copies and are **not a substitute** for the original alert. If they differ in meaning from `raw_alert`, `raw_alert` is the source of truth.
- Normalization never overwrites source data.
- `alert.severity` keeps the original Wazuh severity. **No new priority or classification is derived in Milestone 1.**
- `alert.timestamp_original` keeps the exact input string.

`raw_alert` is the **parsed** alert. It is not a byte-for-byte copy of the input file. For byte-level comparison, use the optional SHA-256 in `processing.integrity` (section 9).

---

## 7. Normalized versus derived data

| Category | Location | Rule |
|---|---|---|
| Original source data | `raw_alert` | Verbatim and authoritative. |
| Normalized fields | `alert` | Reformatting only. No new meaning added. |
| Derived enrichment | `enrichment`, `investigation` | Optional, evidence-based, explainable. States its basis. |
| Engine metadata | `source`, `processing` (including `processing.integrity`) | Describes the processing, not the alert. |

Derived data must not invent MITRE ATT&CK mappings or incident classifications. Missing values are never silently filled in.

---

## 8. Warnings and fatal errors

### Warning object (Proposed)

```json
{
  "code": "TIMESTAMP_MALFORMED",
  "field": "timestamp",
  "message": "Timestamp could not be parsed as ISO 8601 / RFC 3339; normalized timestamp set to null."
}
```

| Code (Proposed) | Meaning |
|---|---|
| `MISSING_OPTIONAL_FIELD` | An optional field is absent; value is `null`. |
| `TIMESTAMP_MISSING` | No timestamp in the input. |
| `TIMESTAMP_MALFORMED` | Timestamp cannot be parsed. |
| `TIMESTAMP_AMBIGUOUS` | No timezone information; no timezone assumed. |
| `ENRICHMENT_SKIPPED` | Enrichment unavailable; explanation provided. |

### Processing status

| `processing.status` | Meaning |
|---|---|
| `"success"` | Record produced; `processing.warnings` is empty. |
| `"success_with_warnings"` | Record produced; `processing.warnings` has at least one entry. |

There is no failure status inside the envelope. Fatal and validation errors produce no record.

### Fatal and validation errors

Fatal errors (unreadable file, invalid JSON, non-object top level) and validation errors (section 3, rules 4–7) stop processing and are reported with a clear message, **separately from the output envelope**. No normalized output record is produced. Output write failures are also reported clearly. See the example error report in section 14.

Exit codes and the exact error report format are **Planned** for Milestone 4.

---

## 9. Optional SHA-256 metadata (Planned)

SHA-256 is off by default. When enabled, the metadata is placed in **`processing.integrity`**:

```json
"processing": {
  "integrity": {
    "algorithm": "sha256",
    "scope": "original_input_file_bytes",
    "digest": "<64 hex characters>"
  }
}
```

| Field | Meaning |
|---|---|
| `algorithm` | `"sha256"`. |
| `scope` | `"original_input_file_bytes"`: the exact bytes of the input file, taken from the same buffer that is decoded as JSON. |
| `digest` | Lowercase hexadecimal SHA-256 digest (**Proposed** encoding). |

- The input file is read **once** into a byte buffer. The digest is calculated from that same buffer, and the same buffer is then decoded as JSON. The file is not read a second time for hashing, so the digest always describes the exact bytes that were parsed.
- Re-serialized JSON is never hashed and described as the original-file hash.
- The `integrity` block is omitted when hashing is disabled.
- The digest supports **integrity comparison** of the exact bytes processed: a holder of the same file can recompute it and compare.
- It does **not** establish authenticity, and it does not prove that the source is trustworthy. It does not show who created the file or that the alert is genuine.

---

## 10. Optional external case references (Planned, Milestone 3)

Case correlation is optional. The engine can store a reference to a case held in an external system, without depending on that system.

```json
"investigation": {
  "case_reference": {
    "system": "external-case-system",
    "id": "CASE-0001"
  }
}
```

- The engine records the reference as supplied. It does not create, look up or validate cases.
- Omitted when not supplied.
- Field names are **Proposed**.

---

## 11. Schema version compatibility

- `"1.0"` is the **initial** contract version.
- Consumers **must** check `schema_version` before reading other fields.
- Consumers should reject major versions they do not support.
- Consumers **should ignore unknown optional fields**.
- **Minor** version: additive optional fields.
- **Major** version: breaking changes (field type changes, removals, changed semantics).

---

## 12. Expected future file-based SENTINEL integration (Planned)

- SENTINEL may read the engine's output files, and may supply sanitized exported Wazuh alerts for Milestone 4 validation.
- Exchange is **file-based**: input is one alert JSON file; output is one JSON envelope.
- The engine has no dependency on SENTINEL and works with any file that meets section 1.
- Any SENTINEL-specific logic lives on the consumer side, not in the engine.

**Not implemented:** no SENTINEL integration exists today.

---

## 13. Example valid input

One Wazuh alert in one JSON file (illustrative, sanitized). The required fields are listed in section 2.

```json
{
  "timestamp": "2025-01-15T10:15:30.123+00:00",
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

---

## 14. Example proposed normalized output (Milestone 1)

This example assumes **SHA-256 is enabled**, so `processing.integrity` is present. When SHA-256 is disabled, `processing.integrity` is omitted.

```json
{
  "schema_version": "1.0",
  "record_type": "normalized_alert",
  "source": {
    "system": "wazuh",
    "ingestion_type": "file_export",
    "input_file": {
      "name": "alert-0001.json"
    }
  },
  "alert": {
    "rule_id": "5710",
    "severity": 5,
    "rule_description": "sshd: attempt to login using a non-existent user",
    "agent_name": "web-server-01",
    "timestamp_original": "2025-01-15T10:15:30.123+00:00",
    "timestamp_utc": "2025-01-15T10:15:30.123Z"
  },
  "processing": {
    "engine": {
      "name": "python-soc-automation",
      "version": "<engine version>"
    },
    "status": "success",
    "warnings": [],
    "integrity": {
      "algorithm": "sha256",
      "scope": "original_input_file_bytes",
      "digest": "<64 hex characters>"
    }
  },
  "raw_alert": {
    "timestamp": "2025-01-15T10:15:30.123+00:00",
    "rule": {
      "id": "5710",
      "level": 5,
      "description": "sshd: attempt to login using a non-existent user"
    },
    "agent": {
      "name": "web-server-01"
    }
  }
}
```

`enrichment` and `investigation` are absent in Milestone 1. With SHA-256 disabled, the same record has no `processing.integrity` key.

### Partial example: warnings (not a complete envelope)

Input with no `timestamp` and no `rule.description`. All required fields are valid, so a record is produced.

```json
{
  "rule": { "id": "5710", "level": 5 },
  "agent": { "name": "web-server-01" }
}
```

Relevant parts of the resulting record. This is a **partial** example: `schema_version`, `record_type`, `source`, `raw_alert` and other `processing` fields (such as `engine`) are omitted, and SHA-256 is assumed disabled, so there is no `processing.integrity`.

```json
{
  "alert": {
    "rule_id": "5710",
    "severity": 5,
    "rule_description": null,
    "agent_name": "web-server-01",
    "timestamp_original": null,
    "timestamp_utc": null
  },
  "processing": {
    "status": "success_with_warnings",
    "warnings": [
      {
        "code": "MISSING_OPTIONAL_FIELD",
        "field": "rule.description",
        "message": "Field is missing; value set to null."
      },
      {
        "code": "TIMESTAMP_MISSING",
        "field": "timestamp",
        "message": "No timestamp in input; normalized timestamp set to null."
      }
    ]
  }
}
```

### Example validation error (Proposed report format)

Input where `rule` is `null`, a structural error:

```json
{
  "timestamp": "2025-01-15T10:15:30.123+00:00",
  "rule": null,
  "agent": { "name": "web-server-01" }
}
```

No normalized output record is produced, and the engine does not substitute an empty dictionary. A separate error report is returned instead. The exact report format is **Planned** for Milestone 4.

```json
{
  "status": "validation_error",
  "errors": [
    {
      "field": "rule",
      "message": "Expected an object for 'rule' but found null."
    }
  ]
}
```

Input where an optional field has an invalid type (`agent.name` is a number) is also a validation error:

```json
{
  "status": "validation_error",
  "errors": [
    {
      "field": "agent.name",
      "message": "Expected a string for 'agent.name' but found a number."
    }
  ]
}
```

---

## 15. Integration limitations and security considerations

### Limitations

- One alert per file. No batching.
- No live Wazuh API ingestion.
- Wazuh only. Microsoft Sentinel, Splunk and Elastic Security are future expansion and out of the current scope.
- Milestone 1 does not derive priority, classification or MITRE mappings.
- Validation errors produce an error report and no output record.
- Only parsing is **Implemented** today; the rest of this contract is **Planned** or **Proposed**.
- Timestamps without timezone information are not normalized.

### Security considerations

- Treat input files as untrusted. Validate before use; do not execute any content.
- Alerts may contain sensitive data (hostnames, usernames, IP addresses, log content). `raw_alert` preserves all of it. Protect output files accordingly and sanitize before sharing or committing to a repository.
- SHA-256 supports integrity comparison of the exact bytes processed. It does not authenticate the source, provide a signature, or show that the source is trustworthy.
- Do not place credentials, tokens or secrets in input or output files.
- The engine does not execute response actions. Any disruptive action requires human approval.
- Report file paths and errors without leaking more of the alert content than necessary.

### Future expansion

Support for Microsoft Sentinel, Splunk and Elastic Security may be considered later. This is not a current requirement and is not covered by this contract.
