Contributing Guidelines

Thank you for your interest in contributing to Python SOC Automation Engine!

This project aims to provide a modular Python-based engine for processing Wazuh security alerts, standardizing alert data, enriching security context, and supporting SOC investigation workflows.

Contributions, suggestions, bug reports, and improvements are welcome.

Getting Started

1. Fork the Repository

Fork the repository and clone your fork:

git clone https://github.com/YOUR_USERNAME/python-soc-automation.git
cd python-soc-automation

2. Set Up the Environment

Create a virtual environment:

python -m venv .venv

Activate it:

Windows PowerShell:

.venv\Scripts\Activate.ps1

Linux/macOS:

source .venv/bin/activate

3. Install Dependencies

Install the project's dependencies:

pip install -r requirements.txt

4. Run Tests

Execute the test suite:

pytest -v

All existing tests should pass before submitting changes.

Contribution Guidelines

Please follow these principles:

- Keep the architecture modular.
- Maintain backward compatibility wherever possible.
- Preserve original Wazuh alert data.
- Do not invent MITRE ATT&CK mappings or security classifications.
- Keep enrichment logic explainable and traceable.
- Handle malformed input safely.
- Avoid introducing unnecessary dependencies.
- Include tests for new functionality.
- Update documentation when behavior or interfaces change.

Code Quality

- Follow standard Python conventions.
- Use meaningful function and variable names.
- Add docstrings to important functions.
- Keep functions focused on a single responsibility.
- Handle expected errors explicitly.
- Avoid hardcoding environment-specific paths.

Testing Requirements

Before submitting a pull request:

1. Run the complete pytest suite.
2. Confirm that existing tests still pass.
3. Add tests for new features and bug fixes.
4. Check that no sensitive information or credentials are included.
5. Review your changes before committing.

Pull Request Process

1. Create a separate branch for your contribution.
2. Make your changes.
3. Run the test suite.
4. Update relevant documentation.
5. Submit a pull request with a clear description.

Please explain:

- What changed.
- Why the change is necessary.
- How the change was tested.
- Any compatibility considerations.

Reporting Bugs and Requesting Features

Please use the repository's GitHub issue templates when reporting bugs or proposing new functionality.

Security

Please follow the instructions in "SECURITY.md" (SECURITY.md) when reporting security vulnerabilities.

Thank you for contributing to Python SOC Automation Engine!
