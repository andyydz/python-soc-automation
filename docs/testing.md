# Testing Strategy

Developer: Andrew Vinston D'Souza
Status: The suite has 12 test modules covering the processing workflow from file ingestion to CLI output. This document does not state a pass count. Run the suite for the current result. Coverage has not been measured.

Related: [README](../README.md) | [Architecture](architecture.md) | [Integration contract](integration-contract.md) | [Development log](development-log.md) | [Sample output](sample-output.md)

## 1. Testing Objectives

- Confirm that each pipeline component behaves as intended: ingestion, parsing, normalization, integrity, enrichment, investigation output, and the CLI.
- Confirm that invalid or malformed input fails clearly rather than producing misleading output.
- Confirm that original alert data and original input bytes are preserved.
- Confirm that enrichment is dataset-driven, that its failure states are handled, and that no mappings are fabricated.
- Provide a regression check so later changes do not silently break existing behavior.

## 2. Testing Environment

| Item | Value |
|---|---|
| Operating system | Windows 11 |
| Editor | Visual Studio Code |
| Shell | PowerShell |
| Python | 3.14.4 |
| pytest | 9.2.0 |
| Isolation | Python virtual environment (`.venv`), excluded from Git |

These are the versions recorded in the project documentation for the development environment. The project itself requires Python 3.10 or newer.

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
tests/
├── test_cli.py
├── test_data_quality.py
├── test_engine.py
├── test_ingestion.py
├── test_integrity.py
├── test_investigation.py
├── test_mitre.py
├── test_normalizer.py
├── test_parser.py
├── test_pipeline.py
├── test_rule_metadata.py
└── test_severity.py
```

Tests are kept separate from the implementation under `src/soc_automation/`, so each can change independently. Tests use local JSON files and local datasets. The suite does not need a Wazuh manager or any other live infrastructure.

## 5. Test Coverage by Module

The table maps each test module to the area it covers, based on the module names and the verified scope of the suite. It does not list individual test names.

| Test module | Area covered |
|---|---|
| `test_parser.py` | Required and optional Wazuh alert fields; invalid types and structures. |
| `test_normalizer.py` | Timestamp normalization, including missing and invalid timestamps. |
| `test_integrity.py` | SHA-256 consistency, and that the digest changes when input bytes change. |
| `test_ingestion.py` | File ingestion, UTF-8 BOM support, malformed JSON, invalid UTF-8, and preservation of original input bytes for hashing. |
| `test_pipeline.py` | Standardized schema output and processing warnings. |
| `test_engine.py` | The enrichment engine: optional enrichment and enrichment failure states. |
| `test_rule_metadata.py` | Local Wazuh rule metadata lookups. |
| `test_severity.py` | Engine-defined severity classification. |
| `test_mitre.py` | Local MITRE ATT&CK lookups. |
| `test_data_quality.py` | Data-quality signals. |
| `test_investigation.py` | Investigation object generation and validation. |
| `test_cli.py` | Command-line behavior (section 9). |

Some scenarios span more than one file. For example, the pipeline tests exercise several components together.

## 6. Running the Test Suite

From the repository root, with the virtual environment active:

```powershell
python -m pip install -e .
python -m pip install pytest
python -m pytest -v
```

To run a single module:

```powershell
python -m pytest tests/test_cli.py -v
```

## 7. Example pytest Output

This is **illustrative output**, not a recorded result. Test names, counts, and timing will differ. Placeholders in angle brackets stand for values from your own run.

```text
python -m pytest -v

============================= test session starts =============================
collected <N> items

tests/test_cli.py::<test_name> PASSED                                    [  x%]
tests/test_data_quality.py::<test_name> PASSED                           [  x%]
...
tests/test_severity.py::<test_name> PASSED                              [100%]

============================== <N> passed in <time> ===============================
```

A passing run means the tested scenarios behave as the tests expect. It does not mean the engine is correct for every possible Wazuh alert, and it does not verify behavior that the tests do not cover.

## 8. Validation and Error-Handling Tests

The suite checks that invalid input is rejected or reported rather than silently accepted:

| Area | What is verified |
|---|---|
| Alert fields | Required and optional Wazuh alert fields, including invalid types and structures. |
| Timestamps | Normalization, and handling of missing and invalid timestamps. |
| File decoding | Malformed JSON and invalid UTF-8. |
| Investigation | Investigation object validation. |
| Enrichment | Enrichment failure states and data-quality signals. |
| CLI | Error reporting (section 9). |

These tests matter because the parser and ingestion layer are the entry point for untrusted data. A malformed alert that was accepted would surface later, in code where it is harder to debug and where the result might look valid. See the test files for the exact exceptions and messages asserted.

## 9. CLI and Ingestion Tests

**Ingestion** (`test_ingestion.py`, `test_integrity.py`):

- Reading local JSON files, including UTF-8 files with a byte order mark.
- Rejection of malformed JSON and invalid UTF-8.
- Preservation of the original input bytes for hashing.
- SHA-256 consistency, and a changed digest when the input bytes change.

**CLI** (`test_cli.py`):

- Help output.
- JSON output to stdout.
- `--sha256` and `--enrich`, individually and combined.
- Output file creation, including nested directories that do not yet exist.
- Error handling.

CLI tests run against local sample input and require no live Wazuh infrastructure.

## 10. Enrichment and Investigation Tests

**Enrichment** (`test_engine.py`, `test_rule_metadata.py`, `test_severity.py`, `test_mitre.py`, `test_data_quality.py`):

- Optional enrichment, including enrichment failure states.
- Local Wazuh rule metadata lookups.
- Engine-defined severity classification. These ranges are defined by this engine and are not official Wazuh categories.
- Local MITRE ATT&CK lookups.
- Data-quality signals.

**Investigation** (`test_investigation.py`, `test_pipeline.py`):

- Investigation object generation and validation.
- Integration of the investigation object in the processing pipeline.

The shipped MITRE dataset currently has no verified rule mappings. Passing MITRE tests show that the lookup mechanism behaves as tested. They do not show that technique mappings are populated or correct.

## 11. Testing Limitations

- **Coverage is unmeasured.** No coverage tool has been run, so the proportion of code exercised is unknown. No coverage percentage is claimed.
- **Local, synthetic input.** Tests use local JSON files, local datasets, and constructed input, not a wide range of real Wazuh alerts.
- **No live integration testing.** The engine processes exported files. There is no live Wazuh manager or API to test against.
- **Dataset-dependent enrichment.** Enrichment is limited by the local datasets. See the MITRE note in section 10.
- **Scope of this document.** Performance, load, and fuzz testing are not described here, and none is claimed. This document does not describe a continuous integration workflow.
- **Not-implemented capabilities.** Nothing is tested for autonomous response, alert correlation, full case management, or SENTINEL SOC Lab integration. None of these is implemented.

## 12. Future Testing Improvements

None of these are implemented.

- Measure coverage and review the gaps.
- Add more sample alerts covering different rule types, agents, and malformed shapes.
- Add further edge cases for unexpected field value types and timestamp formats.
- Add tests alongside any new enrichment dataset entries, including verified MITRE mappings if they are added.
- Add tests for any future integration, such as a file-based exchange with SENTINEL SOC Lab, if one is built.
