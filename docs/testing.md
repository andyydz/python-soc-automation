# Testing Strategy

Developer: Andrew Vinston D'Souza
Status: Six automated tests pass in the latest verified run. Coverage has not been measured.

Related: [README](../README.md) | [Architecture](architecture.md) | [Development log](development-log.md) | [Sample output](sample-output.md)

## 1. Testing Objectives

- Confirm that `parse_wazuh_alert()` returns the expected fields for a valid alert.
- Confirm that invalid input fails with the intended exception type rather than producing misleading output.
- Confirm that missing and partially missing fields are handled with defaults.
- Provide a regression check so later changes do not silently break the parser.

## 2. Testing Environment

| Item | Value |
|---|---|
| Operating system | Windows 11 |
| Editor | Visual Studio Code |
| Shell | PowerShell |
| Python | 3.14.4 |
| pytest | 9.2.0 |
| Isolation | Python virtual environment (`.venv`), excluded from Git |

## 3. pytest Configuration

`pytest.ini` in the repository root:

```ini
[pytest]
pythonpath = src
testpaths = tests
```

- `pythonpath = src` adds `src` to the import path, so tests can import `soc_automation` without manual path changes.
- `testpaths = tests` makes pytest look for tests in the `tests` directory.

## 4. Test Directory Structure

```text
python-soc-automation/
├── data/
│   └── sample_logs/
│       └── wazuh_alert.json     # sample input
├── src/
│   └── soc_automation/
│       ├── __init__.py
│       └── parser.py            # code under test
├── tests/
│   └── test_parser.py           # six tests
└── pytest.ini
```

Tests are kept separate from the implementation so each can change independently. The test code reads the sample JSON with `encoding="utf-8-sig"` to handle a UTF-8 BOM (see the [development log](development-log.md)).

## 5. The Six Tests

| # | Scenario | Expected behavior |
|---|---|---|
| 1 | Successful Wazuh alert parsing | A valid alert returns a dictionary with `rule_id`, `severity`, `agent` and `description` matching the input values |
| 2 | Non-dictionary input | `TypeError` is raised |
| 3 | Invalid rule structure | `ValueError` is raised |
| 4 | Invalid agent structure | `ValueError` is raised |
| 5 | Completely missing alert fields | The parser returns a result using default values instead of failing |
| 6 | Partially missing alert fields | Fields that are present are returned as given, and absent fields use defaults |

## 6. Running the Tests

From the repository root, with the virtual environment active:

```powershell
python -m pytest -v
```

## 7. Example Successful Result

A condensed illustration of a passing run. Exact output, including test names and timing, will differ:

```text
collected 6 items

tests/test_parser.py ......                                      [100%]

6 passed
```

A passing run means the six scenarios above behave as the tests expect. It does not mean the parser is correct for every possible Wazuh alert, and it says nothing about components that do not exist yet. Passing tests verify the behavior that is tested, not the reliability of future components.

## 8. Input Validation Testing

Tests 2, 3 and 4 check that invalid structures are rejected:

| Invalid input | Exception |
|---|---|
| Alert that is not a dictionary | `TypeError` |
| `rule` that is not a valid dictionary structure | `ValueError` |
| `agent` that is not a valid dictionary structure | `ValueError` |

These tests matter because the parser is the entry point for alert data. If a malformed alert were accepted, the error would surface later, in code that is harder to debug and where the result might look valid.

## 9. Missing-Field Testing

Tests 5 and 6 cover incomplete alerts, which are realistic because not every Wazuh alert carries every field. They check that the parser applies defaults and keeps the output structure consistent, with all four keys present, rather than raising errors or returning partial results.

## 10. Testing Limitations

- **Coverage is unmeasured.** No coverage tool has been run, so the proportion of code exercised is unknown. No coverage percentage is claimed.
- **Small input set.** Tests use a sample alert and constructed dictionaries, not a wide range of real Wazuh alerts.
- **Structural validation only.** There are no tests for field value types or ranges beyond the behavior described above.
- **No integration testing.** There is no live Wazuh connection to test against.
- **No planned components.** Nothing is tested for normalization, scoring, IOC extraction, correlation or reporting, because none exist.

## 11. Future Testing Improvements (Planned)

None of these are implemented.

- Measure coverage and review the gaps.
- Add more sample alerts covering different rule types and agents.
- Add edge cases for unexpected field value types.
- Add tests alongside each new module as it is built.
- Add tests for any file or batch ingestion layer.
