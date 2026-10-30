# Sample Input and Output

Developer: Andrew Vinston D'Souza

Related: [README](../README.md) | [Architecture](architecture.md) | [Testing](testing.md) | [Development log](development-log.md)

## 1. Purpose

This document demonstrates the current parser on a local sample. It is not a live Wazuh integration. The parser works on a Python dictionary and does not connect to a Wazuh manager, read files or retrieve alerts.

The example below uses a file integrity monitoring style alert, consistent with the Wazuh-based monitoring in the SENTINEL SOC Lab. Hostnames and values are sample data.

## 2. Sample Wazuh Alert

```json
{
  "rule": {
    "id": "550",
    "level": 7,
    "description": "Integrity checksum changed"
  },
  "agent": {
    "name": "SENTINEL-LINUX01"
  }
}
```

The repository's sample file, `data/sample_logs/wazuh_alert.json`, is the input the test code loads. A real Wazuh alert contains more fields than shown here. The parser reads only the ones listed in the next section.

## 3. Input Structure

| Path | Meaning |
|---|---|
| `rule.id` | Identifier of the Wazuh rule that fired |
| `rule.level` | Severity level assigned by the rule |
| `rule.description` | Human-readable description of the rule |
| `agent.name` | Name of the monitored host that generated the alert |

## 4. Python Dictionary Representation

After JSON is loaded, the alert is a Python dictionary:

```python
alert = {
    "rule": {
        "id": "550",
        "level": 7,
        "description": "Integrity checksum changed",
    },
    "agent": {
        "name": "SENTINEL-LINUX01",
    },
}
```

Loading a file is done by the caller. In the tests, the file is opened with `encoding="utf-8-sig"` and parsed with the `json` module.

## 5. Parser Invocation

```python
from soc_automation.parser import parse_wazuh_alert

result = parse_wazuh_alert(alert)
print(result)
```

The import works under pytest because `pytest.ini` sets `pythonpath = src`. Outside pytest, add `src` to the import path first. In PowerShell:

```powershell
$env:PYTHONPATH = "src"
python
```

## 6. Returned Output

```json
{
  "rule_id": "550",
  "severity": 7,
  "agent": "SENTINEL-LINUX01",
  "description": "Integrity checksum changed"
}
```

## 7. Field-by-Field Explanation

| Output key | Taken from | Value in this example |
|---|---|---|
| `rule_id` | `rule.id` | `"550"` |
| `severity` | `rule.level` | `7` |
| `agent` | `agent.name` | `"SENTINEL-LINUX01"` |
| `description` | `rule.description` | `"Integrity checksum changed"` |

## 8. Missing Fields

If fields are absent, the parser uses default values defined in `parser.py` instead of failing. The output always has the same four keys.

```python
partial = {"rule": {"id": "550"}}

result = parse_wazuh_alert(partial)

print(result["rule_id"])   # 550
print(sorted(result))      # ['agent', 'description', 'rule_id', 'severity']
```

Here `rule_id` keeps the supplied value. `severity`, `agent` and `description` hold the parser's defaults. The default values are not repeated in this document; see `src/soc_automation/parser.py` for them.

## 9. Invalid Input

```python
for bad_alert in (["not", "a", "dictionary"], {"rule": "not a dictionary"}, {"agent": "not a dictionary"}):
    try:
        parse_wazuh_alert(bad_alert)
    except (TypeError, ValueError) as error:
        print(type(error).__name__)
```

Expected output:

```text
TypeError
ValueError
ValueError
```

## 10. TypeError and ValueError

| Exception | Raised when | Example |
|---|---|---|
| `TypeError` | The alert is not a dictionary | A list or string passed as the alert |
| `ValueError` | `rule` or `agent` is present but not a valid dictionary structure | `{"rule": "not a dictionary"}` |

The split separates two failure types: the wrong kind of object was supplied, or the right kind of object had an invalid structure. Callers can handle each case differently, for example by logging and skipping a malformed alert.

## 11. Limitations

- Local sample demonstration only. There is no live Wazuh integration.
- The parser handles one dictionary per call and extracts four fields.
- Validation is structural and does not check an alert against the full Wazuh schema.
- No classification, scoring, IOC extraction, correlation or reporting exists yet. See the [planned architecture](architecture.md).
