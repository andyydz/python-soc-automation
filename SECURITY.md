# Security Policy

Python SOC Automation Engine is a local, file-based tool that ingests Wazuh alert JSON files, validates and normalizes them, optionally enriches them using local datasets, and produces investigation-ready records. It does not connect to a live Wazuh manager and is not a production incident-response service.

This project is independently maintained. Security reports are handled on a best-effort basis.

## Supported Versions

Security updates are focused on the latest code on the `main` branch.

| Version          | Supported |
| ---------------- | --------- |
| Latest (`main`)  | Yes       |
| Older versions   | No        |

## Reporting a Vulnerability

Please report security vulnerabilities responsibly and privately.

**Do not report vulnerabilities through public GitHub issues or pull requests.**

1. If GitHub Private Vulnerability Reporting is enabled for this repository, use the **Report a vulnerability** option on the repository's **Security** tab to submit a private report.
2. If private reporting is unavailable, contact the repository maintainer through an appropriate private GitHub channel, and do not include sensitive technical details in any public post or comment.

For non-security bugs and feature requests, use the repository's regular issue templates instead.

## What to Include

A useful report contains:

- A clear description of the vulnerability.
- Steps to reproduce the issue.
- The potential security impact.
- Affected files, components, or CLI options.
- The version or commit you tested, your Python version, and your operating system.
- Relevant logs or proof-of-concept information, sanitized as described below.
- A suggested mitigation, if known.

## Handling Sensitive Data in Reports

Please sanitize everything you submit. Do not share:

- Credentials, API keys, or tokens.
- Production alert exports or real security data.
- Internal hostnames, IP addresses, usernames, or other sensitive infrastructure details.

Use synthetic or redacted alert samples and the smallest proof of concept that demonstrates the issue.

## Scope

Reports may include issues involving:

- Unsafe JSON alert processing.
- Input validation weaknesses.
- Improper handling of sensitive information.
- File integrity verification (SHA-256) issues.
- Unsafe file operations, including CLI file input and output.
- Dependency vulnerabilities.
- Incorrect or unsafe handling of local enrichment datasets (Wazuh rule metadata and MITRE ATT&CK data).

## Responsible Disclosure

Please allow the maintainer reasonable time to investigate and address a reported vulnerability before publicly disclosing technical details. No specific response or resolution timeframe is guaranteed.

Thank you for helping improve the security and reliability of this project.
