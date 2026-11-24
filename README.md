# Python SOC Automation Engine

A standalone Python tool for **file-based processing, enrichment, triage, and reporting** of exported Wazuh alert files.

> Student project. It works on exported alert files only. There is no live Wazuh connection.

## Overview

`python-soc-automation` takes Wazuh alerts that have been exported to files and turns them into standardized, analyst-friendly output. It can process a single alert, add local enrichment, and triage batches of alerts into Markdown or JSON reports.

It complements [SENTINEL](https://github.com/andyydz/Sentinel-SOC-Lab) through exported alert files. There is no live Wazuh API integration and no real-time connection between the two projects.

- **Package:** `src/soc_automation/`
- **CLI command:** `soc-automation`
- **Entry point:** `soc_automation.cli:main`

## Implemented Capabilities

### Single-alert processing

- Reads a single alert from a JSON file
- Produces a standardized output schema, **v1.2**
- Preserves the original alert as `raw_alert`
- Normalizes timestamps to UTC
- Optional SHA-256 hashing of the original input bytes (`--sha256`)

### Optional local enrichment (`--enrich`)

- Wazuh rule metadata
- Engine-defined severity context
- Local MITRE ATT&CK lookup (currently 7 custom Sysmon rule mappings)
- Data-quality checks
- Provenance information
- Artifact extraction: file paths, process images, target process images, and IP addresses

### Structured investigation output

- Produces structured investigation data from processed alerts

### Batch triage (`--triage`)

- Accepts a JSON array, a single JSON object, or NDJSON
- Filters by severity with `--min-level`
- Generates Markdown or JSON reports with `--report-format markdown|json`

## CLI Flags

| Flag | Purpose |
|------|---------|
| `--sha256` | Hash the original input bytes with SHA-256 |
| `--enrich` | Add local enrichment to the output |
| `--triage` | Run batch triage on JSON array, JSON object, or NDJSON input |
| `--min-level` | Filter triage results by minimum severity level |
| `--report-format markdown\|json` | Choose the triage report format |

## Repository Structure

```text
src/soc_automation/
├── cli.py              # CLI entry point (soc_automation.cli:main)
├── ingestion.py
├── integrity.py
├── parser.py
├── normalizer.py
├── pipeline.py
├── triage.py
├── enrichment/
│   ├── artifacts.py
│   ├── data_quality.py
│   ├── engine.py
│   ├── mitre.py
│   ├── rule_metadata.py
│   └── severity.py
└── investigation/
    └── builder.py

tests/                  # 16 test_*.py modules
docs/Readme.md
```

## Tests

The `tests/` directory contains **16 `test_*.py` modules** with **154 top-level `def test_` functions**.

> This is a source-level count of test functions, not a claim about a live test run or pass/fail results.

## Documentation

Additional documentation is in [`docs/Readme.md`](docs/Readme.md).

## Scope and Limitations

This project is intentionally limited. It does **not** provide:

- Live Wazuh API integration or manager polling (file-based processing only)
- Real-time alert collection or a continuous monitoring service
- Autonomous containment or SOAR functionality
- A full case-management system
- A dedicated cross-event correlation engine

Local MITRE ATT&CK mappings currently cover only 7 custom Sysmon rules. They are not comprehensive.

## Relationship to SENTINEL

[SENTINEL](https://github.com/andyydz/Sentinel-SOC-Lab) is a separate repository: a virtual SOC lab built around Wazuh and Sysmon. This tool can process alert files exported from that kind of environment. The two are connected only through exported files.

## Author

[andyydz](https://github.com/andyydz)
