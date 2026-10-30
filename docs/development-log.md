# Development Log

Developer: Andrew Vinston D'Souza
Environment: Windows 11, Visual Studio Code, PowerShell, Python 3.14.4, pytest 9.2.0, Git and GitHub, virtual environment (`.venv`)

Related: [README](../README.md) | [Architecture](architecture.md) | [Testing](testing.md) | [Sample output](sample-output.md)

This log is organized by development phase. No dates are recorded.

## Phase 1: Project Initialization

**Repository and structure.** The GitHub repository `andyydz/python-soc-automation` was created and set up locally. The project was organized with separate directories for application code, tests and sample data:

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

**Development environment.** Work is done on Windows 11 in Visual Studio Code, with PowerShell as the shell.

**Virtual environment.** A Python virtual environment (`.venv`) isolates project dependencies from the system Python installation. It is excluded from Git through `.gitignore`, since it is local and reproducible.

## Phase 2: Parser Implementation (Milestone 1)

**Purpose.** The parser is the first component because every later stage depends on reliable alert data. Starting with a small, well-tested foundation reduces the risk of building scoring or correlation logic on unvalidated input.

**Function.** `parse_wazuh_alert(alert: dict[str, Any]) -> dict[str, Any]` in `src/soc_automation/parser.py`. It extracts the rule ID, severity level, agent name and description, and returns them under the keys `rule_id`, `severity`, `agent` and `description`.

**Scope decision.** The parser accepts a Python dictionary. Reading files and connecting to Wazuh were deliberately left out, so that parsing logic can be tested without any external dependency.

## Phase 3: Validation and Exception Handling

The parser validates its input before reading any fields:

- A non-dictionary alert raises `TypeError`.
- A `rule` or `agent` that is not a valid dictionary structure raises `ValueError`.
- Absent fields use default values defined in the parser.

The reasoning is that a security automation tool should not turn malformed input into plausible-looking output. Distinct exception types separate "wrong kind of input" from "right kind of input with a bad structure".

## Phase 4: Sample Data

A sample Wazuh alert was added as `data/sample_logs/wazuh_alert.json` to provide realistic input for tests. It is intended to contain no production data. See challenge 2 below for an encoding issue encountered when creating it.

## Phase 5: Test Implementation

pytest was introduced to verify behavior as the parser was written. The suite in `tests/test_parser.py` currently contains six tests:

1. Successful Wazuh alert parsing.
2. Rejection of non-dictionary input.
3. Rejection of an invalid rule structure.
4. Rejection of an invalid agent structure.
5. Handling completely missing alert fields.
6. Handling partially missing alert fields.

The latest verified run passed all six tests (`python -m pytest -v`). Details are in [Testing](testing.md).

## Phase 6: Git and GitHub Workflow

The project follows **Build, Test, Verify, Commit, Push**:

| Step | Purpose |
|---|---|
| Build | Make one small, focused change |
| Test | Run pytest to check the change against defined expectations |
| Verify | Read the results and the diff to confirm the change does what was intended and nothing else |
| Commit | Record the verified change with a clear message, keeping history readable |
| Push | Publish to GitHub so the remote repository reflects the verified state |

Working in small increments means a failing test points to a small, recent change, which keeps debugging fast and the history easy to review.

## Phase 7: Development Challenges and Resolutions

### Challenge 1: Import and pytest configuration

**What happened.** The parser lives in `src/soc_automation/`, a directory that is not on Python's import path by default. The test file needed to import `soc_automation` and the source directory therefore had to be discoverable by pytest.

**Why it mattered.** Without it, tests cannot import the code they are meant to verify, and the layout would have to be abandoned or worked around with fragile path changes inside test files.

**Resolution.** A `pytest.ini` file was added:

```ini
[pytest]
pythonpath = src
testpaths = tests
```

`pythonpath = src` adds the `src` directory to the import path during test runs, so `soc_automation` can be imported. `testpaths = tests` tells pytest to look for tests in the `tests` directory.

**Learned.** Import paths are configuration, not an afterthought, and keeping that configuration in one project file is cleaner than path manipulation inside tests.

### Challenge 2: UTF-8 BOM in the sample JSON

**What happened.** The sample JSON file was created through PowerShell using UTF-8 encoding with a byte order mark (BOM), a marker character at the start of the file.

**Why it mattered.** A BOM is not part of the JSON content. Reading such a file with plain UTF-8 leaves the marker in the text, which can interfere with JSON parsing.

**Resolution.** The test reads the file with `encoding="utf-8-sig"`. This encoding removes a BOM if one is present and reads files without a BOM as ordinary UTF-8, so it is safe for either kind of file.

**Learned.** Tool defaults affect file contents, and readers should be tolerant of common encoding variations when handling data created on different systems.

### Challenge 3: Separating implementation and tests

**What happened.** A decision was made to keep the parser and its tests in separate files rather than combine them.

**Why it mattered.** Mixing the two makes it harder to see what is production code and what is verification.

**Resolution.** Implementation stays in `src/soc_automation/parser.py` and tests stay in `tests/test_parser.py`.

**Learned.** Separation of concerns makes each file easier to read and change. Tests can be updated or extended without touching the implementation, and the source tree stays limited to application code.

### Challenge 4: Git authentication

**What happened.** Access to the GitHub repository from the local machine initially required authentication to be configured.

**Why it mattered.** Without working authentication, commits cannot be pushed, and credentials must be handled without being stored in the project.

**Resolution.** Git Credential Manager browser-based authentication was configured, and access to the remote repository was verified. No credentials are stored in the repository.

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

## Phase 8: Technical Decisions

| Decision | Reasoning |
|---|---|
| Accept a dictionary rather than read files in the parser | Keeps parsing independent of I/O and easy to test |
| Separate `src/` and `tests/` | Clear boundary between application code and verification |
| Raise `TypeError` and `ValueError` | Distinguishes wrong input type from invalid structure |
| Use defaults for absent fields | Alerts may be incomplete, and the behavior is explicit and tested |
| Configure paths in `pytest.ini` | One place for import and discovery settings |
| Read sample JSON with `utf-8-sig` | Tolerates files saved with or without a BOM |
| Rebase before pushing, no force push | Preserves remote history and keeps the log linear |

## Phase 9: Current Status

- Milestone 1, the Wazuh alert parser, is complete with six passing tests in the latest verified run.
- There is no live Wazuh integration, scoring, correlation or reporting.
- The project is in development and is not production-ready.

## Phase 10: Future Milestones (Planned)

None of these are implemented.

1. Alert normalization
2. Severity classification and risk scoring
3. IOC extraction
4. Alert correlation
5. Automated reporting in CSV and JSON
6. Testing and quality improvements
7. SENTINEL SOC Lab integration
8. Final documentation and project review
