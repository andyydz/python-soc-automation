"""Unit tests for the alert triage and summary reporting module."""

import json
import pytest

from soc_automation.triage import filter_by_severity, generate_summary_report


@pytest.fixture
def sample_fim_telemetry():
    """Provides representative FIM telemetry based on SENTINEL v0.3 lab records."""
    return [
        {
            "timestamp": "2026-11-02T10:15:30.100Z",
            "rule": {"id": "100003", "level": 8, "description": "FIM: File creation detected"},
            "syscheck": {"path": "/home/sentinel-admin/test.txt", "event": "added"},
        },
        {
            "timestamp": "2026-11-02T10:16:00.200Z",
            "rule": {"id": "100002", "level": 8, "description": "FIM: File modified"},
            "syscheck": {"path": "/home/sentinel-admin/test.txt", "event": "modified"},
        },
        {
            "timestamp": "2026-11-02T10:16:30.300Z",
            "rule": {"id": "100004", "level": 8, "description": "FIM: File deleted"},
            "syscheck": {"path": "/home/sentinel-admin/test.txt", "event": "deleted"},
        },
        {
            "timestamp": "2026-11-02T10:17:00.000Z",
            "rule": {"id": "550", "level": 3, "description": "Integrity checksum changed"},
            "syscheck": {"path": "/etc/issue", "event": "modified"},
        },
    ]


def test_filter_by_severity_threshold(sample_fim_telemetry):
    """Verifies that alerts below the threshold are filtered out cleanly."""
    high_sev = filter_by_severity(sample_fim_telemetry, min_level=8)
    assert len(high_sev) == 3
    for record in high_sev:
        assert record["rule"]["level"] >= 8

    critical = filter_by_severity(sample_fim_telemetry, min_level=12)
    assert len(critical) == 0


def test_filter_edge_cases_and_malformed_records():
    """Validates resilience against malformed fields, strings, and missing keys."""
    malformed_inputs = [
        {},
        {"rule": "invalid_type"},
        {"rule": {"level": "invalid_int"}},
        {"rule": {"level": None}},
        {"alert": {"rule": {"level": 10}}},
        None,
    ]

    triaged = filter_by_severity(malformed_inputs, min_level=8)
    assert len(triaged) == 1
    assert triaged[0]["alert"]["rule"]["level"] == 10

    assert filter_by_severity([], min_level=8) == []
    assert filter_by_severity(None, min_level=8) == []


def test_generate_summary_report_markdown_and_dict(sample_fim_telemetry):
    """Verifies aggregation counts, file path deduplication, and markdown format."""
    triaged = filter_by_severity(sample_fim_telemetry, min_level=8)
    
    # 1. Test dictionary output
    summary_dict = generate_summary_report(triaged, output_format="dict")
    assert summary_dict["total_alerts"] == 3
    assert summary_dict["unique_rules"] == 3
    assert "100003" in summary_dict["rules"]
    assert summary_dict["rules"]["100003"]["count"] == 1
    assert summary_dict["rules"]["100003"]["affected_paths"] == ["/home/sentinel-admin/test.txt"]

    # 2. Test Markdown report formatting
    markdown_report = generate_summary_report(triaged, output_format="markdown")
    assert isinstance(markdown_report, str)
    assert "| `100003` | 8 | 1 |" in markdown_report
    assert "`/home/sentinel-admin/test.txt`" in markdown_report

    # 3. Test empty report handling
    empty_md = generate_summary_report([], output_format="markdown")
    assert "No matching alerts found." in empty_md