# Development Log

Developer: Andrew Vinston D'Souza
Environment: Windows 11, Visual Studio Code, PowerShell, Git and GitHub, local Python virtual environment (`.venv`). The project requires Python 3.10 or newer.

Related: [README](../README.md) | [Architecture](architecture.md) | [Testing](testing.md) | [Sample output](sample-output.md)

This log records how the project developed, from the initial repository to the four completed milestones. It is organized chronologically by phase. No dates are recorded.

## Summary

| Phase | Focus | Status |
|---|---|---|
| 1 | Project foundation | Complete |
| Milestone 1 | Standardized Alert Output | Complete |
| Milestone 2 | Alert Enrichment | Complete |
| Milestone 3 | Investigation-Ready Output | Complete |
| Milestone 4 | CLI and Integration Interface | Complete |

The current standardized output schema version is 1.2.

## Phase 1: Project Foundation

- Created the GitHub repository `andyydz/python-soc-automation` and set it up locally.
- Established separate directories for application code (`src/`), tests (`tests/`), and sample data (`data/`).
- Configured Git, GitHub, `.gitignore`, and `pytest.ini`.
- Created a local virtual environment (`.venv`), excluded from Git because it is local and reproducible.
- Added a synthetic Wazuh alert sample, intended to contain no production data.

The initial layout:

```text
python-soc-automation/
├── data/
│   └── sample_logs/
│       └── wazuh_alert.json
├── src/
│   └── soc_automation/
│       ├── __init__.py
│       └── parser.py
├── tests/
│   └── test_parser.py
├── .gitignore
├── pytest.ini
└── README.md
```

The layout has grown since this first structure. See [Architecture](architecture.md) for the current modules.

## Milestone 1: Standardized Alert Output

The parser came first because every later stage depends on reliable alert data. Starting with a small, well-tested foundation reduces the risk of building enrichment logic on unvalidated input.

**Initial parser.** `parse_wazuh_alert` in `src/soc_automation/parser.py` accepted a Python dictionary and extracted the rule ID, severity level, agent name, and description. Reading files was deliberately left out so that parsing logic could be tested without external dependencies. At that stage the parser validated its input before reading any fields: a non-dictionary alert raised `TypeError`, and a `rule` or `agent` with an invalid structure raised `ValueError`. The reasoning was that a security automation tool should not turn malformed input into plausible-looking output. The first test suite had six tests covering successful parsing, invalid input types and structures, and fully or partially missing fields.

**Extension to a standardized output.** Milestone 1 then added:

- JSON file ingestion, kept separate from parsing logic.
- Preservation of the original alert in `raw_alert`.
- A standardized output envelope.
- Timestamp normalization to UTC.
- Optional SHA-256 integrity calculation over the original file bytes.
- Processing warnings and error handling.
- UTF-8 BOM support through `utf-8-sig`.

## Milestone 2: Alert Enrichment

Implemented:

- Local Wazuh rule metadata lookup.
- Engine-defined severity context classification.
- Local MITRE ATT&CK dataset lookup.
- Data-quality checks.
- Enrichment status, provenance, and error handling.

Enrichment is explainable and dataset-driven: derived values come from defined logic or local datasets rather than guesses.

Severity context ranges are defined by this engine. They are not official Wazuh severity categories.

| Rule level | Severity context |
|---|---|
| 0 | Ignored |
| 1 to 4 | Low |
| 5 to 7 | Medium |
| 8 to 11 | High |
| 12 to 15 | Critical |

**Limitation.** The MITRE ATT&CK dataset currently has no verified rule mappings. The lookup functionality exists, but no technique mappings are populated, and none are fabricated.

## Milestone 3: Investigation-Ready Output

Implemented a structured `investigation` object containing:

- Investigation status.
- Affected asset fields.
- Detection details.
- Priority context, when enrichment is available.
- Case reference.
- Evidence and analyst notes.

The engine does not invent asset information or analyst observations. The object is a structured record, not full case management.

## Milestone 4: CLI and Integration Interface

Implemented:

- Python package configuration through `pyproject.toml`.
- Editable installation with `python -m pip install -e .`.
- The `soc-automation` CLI entry point.
- Local JSON file input.
- Optional `--sha256` and `--enrich` flags.
- JSON output to stdout or a specified file.
- Automatic creation of missing output directories.
- Error handling with an appropriate exit status.

The engine still processes exported JSON files only. It has no live Wazuh connection.

## Development Practice

The project follows **Build, Test, Verify, Commit, Push**:

| Step | Purpose |
|---|---|
| Build | Make one small, focused change |
| Test | Run pytest to check the change against defined expectations |
| Verify | Read the results and the diff to confirm the change does what was intended and nothing else |
| Commit | Record the verified change with a clear message, keeping history readable |
| Push | Publish to GitHub so the remote repository reflects the verified state |

Working in small increments means a failing test points to a small, recent change, which keeps debugging fast and the history easy to review. Tests run with `python -m pytest -v`; see [Testing](testing.md) for details.

## Development Challenges and Resolutions

### Challenge 1: Import and pytest configuration

**What happened.** The code lives in `src/soc_automation/`, which is not on Python's import path by default, so tests could not import `soc_automation`.

**Why it mattered.** Without a fix, tests cannot import the code they verify, and the layout would have to be abandoned or worked around with fragile path changes inside test files.

**Resolution.** A `pytest.ini` file was added:

```ini
[pytest]
pythonpath = src
testpaths = tests
```

`pythonpath = src` adds the source directory to the import path during test runs, and `testpaths = tests` tells pytest where to discover tests.

**Learned.** Import paths are configuration, not an afterthought. Keeping them in one project file is cleaner than path manipulation inside tests.

### Challenge 2: UTF-8 BOM in the sample JSON

**What happened.** The sample JSON file was created through PowerShell with a UTF-8 byte order mark (BOM) at the start of the file.

**Why it mattered.** A BOM is not part of the JSON content. Reading such a file with plain UTF-8 leaves the marker in the text, which can interfere with JSON parsing.

**Resolution.** The file is read with `utf-8-sig`, which removes a BOM if present and reads files without one as ordinary UTF-8. Ingestion keeps this tolerance, so files saved with or without a BOM are accepted.

**Learned.** Tool defaults affect file contents. Readers should tolerate common encoding variations in data created on different systems.

### Challenge 3: Separating implementation and tests

**What happened.** A decision was needed on whether to keep the parser and its tests together or apart.

**Why it mattered.** Mixing the two makes it harder to see what is production code and what is verification.

**Resolution.** Application code stays under `src/soc_automation/` and tests stay under `tests/`.

**Learned.** Separation makes each file easier to read and change. Tests can be extended without touching the implementation, and the source tree stays limited to application code.

### Challenge 4: Git authentication

**What happened.** Access to the GitHub repository from the local machine initially required authentication to be configured.

**Why it mattered.** Without working authentication, commits cannot be pushed, and credentials must be handled without being stored in the project.

**Resolution.** Git Credential Manager browser-based authentication was configured and access to the remote was verified. No credentials are stored in the repository.

**Learned.** Use a credential manager rather than embedding secrets in commands or files.

### Challenge 5: Git push rejection

**What happened.** During README documentation updates, a push to `main` was rejected because the remote branch contained changes that were not present locally.

**Why it mattered.** Pushing over unseen remote work would discard it. The rejection is a safeguard, and the correct response is to integrate the remote changes first.

**Resolution.**

```powershell
git pull --rebase origin main
git push origin main
```

`git pull --rebase` fetches the remote changes and replays the local commits on top of them, producing a linear history without an extra merge commit. The push then succeeded. Force-pushing was avoided because it overwrites remote history and could destroy work that exists only on the remote.

**Learned.** Synchronize with the remote before pushing, and treat a rejected push as information rather than an obstacle to override.

## Technical Decisions

| Decision | Reasoning |
|---|---|
| Separate `src/` and `tests/` | Clear boundary between application code and verification |
| Configure paths in `pytest.ini` | One place for import and discovery settings |
| Read JSON with `utf-8-sig` | Tolerates files saved with or without a BOM |
| Keep file ingestion separate from parsing | Parsing logic stays independent of I/O and easy to test |
| Preserve the original alert in `raw_alert` | Source data is never lost or silently altered |
| Keep enrichment explainable and dataset-driven | Derived values are traceable, and no mappings are invented |
| Calculate SHA-256 on original bytes, not re-serialized JSON | The digest reflects the exact input processed |
| Keep modular responsibilities across pipeline components | Each component is easier to test and change |
| Rebase before pushing, no force push | Preserves remote history and keeps the log linear |
| Follow Build, Test, Verify, Commit, Push | Small, verified increments keep debugging and review simple |

## Current Status

- Phase 1 and Milestones 1 to 4 are complete.
- The engine processes exported Wazuh alert JSON files through the `soc-automation` CLI or the Python package.
- The current output schema version is 1.2.
- The MITRE ATT&CK dataset has no verified rule mappings yet.
- There is no live Wazuh manager or API connection, no autonomous incident response, and no full case-management functionality.

## Future Possibilities (Not Implemented)

These are possibilities only, not current capabilities:

- Integration with SENTINEL SOC Lab, which is a separate project.
- Support for other SIEM platforms, such as Splunk, Elastic, and Microsoft Sentinel.
- Verified MITRE ATT&CK rule mappings in the local dataset.
