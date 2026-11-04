# Contributing to Python SOC Automation Engine

Thank you for your interest in contributing to Python SOC Automation Engine.

This project is a modular Python engine that ingests, validates, normalizes, enriches, and structures Wazuh security alerts into investigation-ready records. It works on alert data supplied as JSON files and does not connect to a live Wazuh manager. Contributions, suggestions, bug reports, and improvements are welcome.

Please also read our [Code of Conduct](CODE_OF_CONDUCT.md) before participating.

## Getting Started

### 1. Fork and Clone the Repository

Fork the repository, then clone your fork:

```bash
git clone https://github.com/YOUR_USERNAME/python-soc-automation.git
cd python-soc-automation
```

### 2. Create and Activate a Virtual Environment

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
source .venv/bin/activate
```

The project requires Python 3.10 or newer.

### 3. Install the Project and Pytest

Install the project in editable mode. Packaging and dependencies are defined in `pyproject.toml`:

```bash
python -m pip install -e .
python -m pip install pytest
```

The project does not use a `requirements.txt` file.

### 4. Run the Tests

```bash
python -m pytest -v
```

All existing tests should pass before you begin and before you submit changes.

## Project Layout

- `src/soc_automation/` contains the source code.
- `tests/` contains the automated tests.
- `soc-automation` is the command-line entry point installed with the package.

## Development Workflow

1. Create a separate feature branch from an up-to-date copy of the main branch.
2. Make focused changes. Keep each pull request limited to one logical change.
3. Add or update tests for new features, behavior changes, and bug fixes.
4. Run the complete test suite with `python -m pytest -v`.
5. Update relevant documentation when behavior, options, or output formats change.
6. Review your diff before committing.
7. Submit a pull request.

## Contribution Principles

- **Preserve original data.** Original Wazuh alert data must not be altered or discarded. Normalized and enriched fields are added alongside it.
- **Keep processing deterministic and explainable.** The same input should produce the same output, and every derived value should be traceable to its source.
- **Do not invent security classifications.** MITRE ATT&CK mappings must come from the project's local dataset, and severity context must follow defined, documented logic. Do not fabricate or guess mappings or classifications. If no mapping exists, the output should reflect that rather than fill the gap.
- **Validate untrusted input.** Alert files may be malformed, incomplete, or hostile. Handle such input safely and fail with clear errors rather than unhandled exceptions.
- **Keep the architecture modular.** Each component should have a clear, single responsibility.
- **Avoid unnecessary dependencies.** Prefer the Python standard library. Discuss any new dependency in an issue before adding it.
- **Maintain backward compatibility where practical.** If a change affects output structure, CLI options, or public interfaces, call it out in your pull request.
- **Do not commit sensitive data.** Never commit credentials, API keys, production alert exports, or sensitive infrastructure details such as internal hostnames, IP addresses, or usernames. Use synthetic or sanitized data in tests and examples.

## Code Quality

- Follow standard Python conventions.
- Use meaningful function and variable names.
- Add docstrings to important functions.
- Keep functions focused on a single responsibility.
- Handle expected errors explicitly.
- Avoid hardcoding environment-specific paths.

## Testing Requirements

Before submitting a pull request:

1. Run the complete suite with `python -m pytest -v`.
2. Confirm that existing tests still pass.
3. Add tests for new features and bug fixes, including malformed or edge-case input where relevant.
4. Confirm that no credentials or sensitive data are included in code, test fixtures, or commit history.

### Testing the CLI

If your change affects the command-line interface or the pipeline it calls, add or update tests in `tests/` alongside the existing CLI tests. CLI behavior that is covered by tests includes the optional `--sha256` and `--enrich` flags, JSON output to stdout or a specified file, and automatic creation of missing output directories.

Tests run against local sample files and do not require a Wazuh manager, agents, or any other live infrastructure.

## Pull Request Process

1. Push your feature branch to your fork.
2. Open a pull request against the main repository.
3. Provide a clear description covering:
   - What changed.
   - Why the change is necessary.
   - How the change was tested.
   - Any compatibility considerations.

## Reporting Bugs and Requesting Features

Please use the repository's GitHub issue templates when reporting bugs or proposing new functionality. For bug reports, include the steps to reproduce, expected and actual behavior, your Python version and operating system, and a minimal, sanitized sample alert if one is needed. Do not attach production alert data or sensitive information.

## Security

Do not report security vulnerabilities through public issues or pull requests. Follow the instructions in [SECURITY.md](SECURITY.md).

Thank you for contributing to Python SOC Automation Engine.
