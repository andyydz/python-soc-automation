# Testing Strategy

Developer: Andrew Vinston D'Souza
Status: The suite has 16 test modules covering the processing workflow from file ingestion to CLI output, including batch triage. This document does not state a pass count. Run the suite for the current result. Coverage has not been measured.

Related: [README](../README.md) | [Architecture](architecture.md) | [Integration contract](integration-contract.md) | [Development log](development-log.md) | [Sample output](sample-output.md)

## 1. Testing Objectives

- Confirm that each pipeline component behaves as intended: ingestion, parsing, normalization, integrity, enrichment, investigation output, artifact extraction, triage, and the CLI.
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
├── test_artifacts.py
├── test_cli.py
├── test_data_quality.py
├── test_engine.py
├── test_ingestion.py
├── test_integrity.py
├── test_investigation.py
├── test_investigation_builder.py
├── test_json_triage_report.py
├── test_mitre.py
├── test_normalizer.py
├── test_parser.py
├── test_pipeline.py
├── test_rule_metadata.py
├── test_severity.py
└── test_triage.py
```

Tests are kept separate from the implementation under `src/soc_automation/`, so each can change independently. Tests use local JSON files and local datasets. The suite does not need a Wazuh manager or any other live infrastructure.

## 5. Test Coverage by Module

The table maps each test module to the area it covers, based on the module names and the verified scope of the suite. It does not list individual test names, and a module is described only by what it is known to assert.

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
| `test_investigation_builder.py` | Investigation object construction; affected asset and detection details; integration of enrichment and artifacts; handling of missing or incomplete enrichment; input immutability; validation errors for invalid alert and enrichment structures. |
| `test_artifacts.py` | Artifact extraction from FIM and Sysmon alerts (file paths, process images, target process images, and IP addresses); handling of empty and malformed input; artifact aggregation in triage summary reports. |
| `test_triage.py` | Severity threshold filtering; malformed and missing alert fields; Markdown and dictionary report generation; empty reports; triage context for FIM noise paths, suspicious hidden paths, subthreshold SSH event counts, and evasion indicators (including `test_v07_triage_context_noise_ssh_and_evasion()`); Sysmon event and timestamp context. |
| `test_json_triage_report.py` | JSON triage report generation through the CLI; FIM alert reporting; unknown timestamps; schema `1.2` normalized-alert envelopes; `--sha256` and `--enrich` in triage mode; report structure and artifact context. |
| `test_cli.py` | Command-line behavior in normal processing mode and triage mode (section 9). |

Some scenarios span more than one file. For example, the pipeline tests exercise several components together, and triage report tests exercise the triage and artifact modules together.

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

tests/test_artifacts.py::<test_name> PASSED                              [  x%]
tests/test_cli.py::<test_name> PASSED                                    [  x%]
...
tests/test_triage.py::<test_name> PASSED                                [100%]

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
| Investigation | Investigation object validation, including validation errors for invalid alert and enrichment structures. |
| Artifacts | Handling of empty and malformed input during artifact extraction. |
| Triage | Handling of malformed and missing alert fields. |
| Enrichment | Enrichment failure states and data-quality signals. |
| CLI | Error reporting (section 9). |

These tests matter because the parser and ingestion layer are the entry point for untrusted data. A malformed alert that was accepted would surface later, in code where it is harder to debug and where the result might look valid. See the test files for the exact exceptions and messages asserted.

## 9. Ingestion and CLI Tests

The CLI has two distinct modes. Normal processing handles a single alert file. Triage mode handles multiple alerts and is activated explicitly with `--triage`. Normal processing does not accept the multi-alert input formats that triage mode accepts.

**Ingestion** (`test_ingestion.py`, `test_integrity.py`):

- Reading local JSON files, including UTF-8 files with a byte order mark.
- Rejection of malformed JSON and invalid UTF-8.
- Preservation of the original input bytes for hashing.
- SHA-256 consistency, and a changed digest when the input bytes change.

### 9.1 CLI: normal processing mode

Covered in `test_cli.py`. This mode processes a single Wazuh JSON alert file and produces normalized JSON output.

- Help output.
- JSON output to stdout.
- `--sha256` and `--enrich`, individually and combined.
- `--output`, including creation of nested output directories that do not yet exist.
- Error handling for missing files, malformed JSON, and invalid JSON root structures.

### 9.2 CLI: triage mode

Covered in `test_cli.py` and `test_json_triage_report.py`. Triage mode is activated with `--triage`.

**Implemented input support (triage mode only):**

- JSON arrays.
- A single JSON object.
- NDJSON (newline-delimited JSON): when JSON parsing of the whole input fails, the content is parsed line by line.

**Explicitly tested input behavior:**

- The inspected CLI tests explicitly demonstrate JSON-array input.
- NDJSON and single-object input are implemented, but this document does not claim a dedicated test for either.

**Options and output covered:**

- `--min-level` severity threshold, defaulting to `8`.
- `--report-format` with `markdown` and `json` choices.
- `--output` for saving the report to a file.
- `--sha256` and `--enrich` in triage mode.
- Aggregated alert summaries with additional triage context, and extraction of relevant FIM and Sysmon artifacts.

CLI tests run against local sample input and require no live Wazuh infrastructure.

## 10. Enrichment, Investigation, and Artifact Tests

**Enrichment** (`test_engine.py`, `test_rule_metadata.py`, `test_severity.py`, `test_mitre.py`, `test_data_quality.py`):

- Optional enrichment, including enrichment failure states.
- Local Wazuh rule metadata lookups.
- Engine-defined severity classification. These ranges are defined by this engine and are not official Wazuh categories.
- Local MITRE ATT&CK lookups.
- Data-quality signals.

**Investigation** (`test_investigation.py`, `test_investigation_builder.py`, `test_pipeline.py`):

- Investigation object generation and validation.
- Construction of the affected asset and detection details.
- Integration of enrichment and artifacts into the investigation object.
- Handling of missing or incomplete enrichment.
- Input immutability: building the investigation object does not modify its inputs.
- Integration of the investigation object in the processing pipeline.

**Artifacts and triage** (`test_artifacts.py`, `test_triage.py`, `test_json_triage_report.py`):

- Extraction of file paths, process images, target process images, and IP addresses from FIM and Sysmon alerts.
- Severity threshold filtering and aggregated Markdown, dictionary, and JSON report generation.
- Triage context for FIM noise paths, suspicious hidden paths, subthreshold SSH event counts, and evasion indicators, and for Sysmon events and timestamps.
- Schema `1.2` normalized-alert envelopes in JSON triage reports.

The local MITRE dataset contains mappings only for the custom SENTINEL Sysmon replay rules. Passing MITRE tests show that the lookup mechanism behaves as tested. They do not show that mappings are complete or correct beyond that limited set.

## 11. Testing Limitations

- **Coverage is unmeasured.** No coverage tool has been run, so the proportion of code exercised is unknown. No coverage percentage is claimed.
- **Local, synthetic input.** Tests use local JSON files, local datasets, and constructed input, not a wide range of real Wazuh alerts. The tests do not validate real-world detection effectiveness.
- **No live integration testing.** The engine processes exported files. There is no live Wazuh manager or API to test against.
- **Dataset-dependent enrichment.** Enrichment is limited by the local datasets. See the MITRE note in section 10.
- **Scope of this document.** Performance, load, and fuzz testing are not described here, and none is claimed. This document does not describe a continuous integration workflow.
- **Not-implemented capabilities.** A dedicated cross-event correlation engine, autonomous response, real-time monitoring, full case management, and live Wazuh API polling are not implemented or tested. File-based triage of exported alerts is covered.

## 12. Future Testing Improvements

None of these are implemented.

- Measure coverage and review the gaps.
- Add more sample alerts covering different rule types, agents, and malformed shapes.
- Add further edge cases for unexpected field value types and timestamp formats.
- Add tests alongside any new enrichment dataset entries, including additional verified MITRE mappings if they are added.
- Add tests for any future automated integration with SENTINEL SOC Lab, if one is built.
