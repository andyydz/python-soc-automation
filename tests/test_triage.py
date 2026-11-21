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

def test_v07_triage_context_noise_ssh_and_evasion():
    """Verifies v0.7 triage context across FIM noise, hidden paths, SSH 100200, and evasion."""
    from soc_automation.triage import build_v07_triage_context, format_v07_context_markdown

    alerts = [
        {
            "timestamp": "2026-11-20T21:44:14.163+0530",
            "rule": {"id": "100004", "level": 8, "description": "FIM deleted"},
            "syscheck": {"path": "/home/sentinel-admin/.cache/tracker3/meta.db"},
        },
        {
            "timestamp": "2026-11-20T21:45:00.000+0530",
            "rule": {"id": "100003", "level": 8, "description": "FIM created"},
            "syscheck": {"path": "/home/.v07-hidden-dir/.v07-payload.sh"},
        },
        {
            "timestamp": "2026-11-20T21:46:00.000+0530",
            "rule": {"id": "100200", "level": 5, "description": "SSH auth failed"},
            "data": {"srcip": "192.168.56.101"},
        },
        {
            "timestamp": "2026-11-20T21:46:10.000+0530",
            "rule": {"id": "100200", "level": 5, "description": "SSH auth failed"},
            "data": {"srcip": "192.168.56.101"},
        },
        {
            "timestamp": "2026-11-20T21:47:00.000+0530",
            "rule": {"id": "100112", "level": 10, "description": "LSASS access"},
            "data": {"win": {"eventdata": {"Image": "C:\\Windows\\System32\\rundll32.exe", "CommandLine": "rundll32.exe comsvcs.dll, #24"}}},
        },
    ]

    ctx = build_v07_triage_context(alerts)
    assert "/home/sentinel-admin/.cache/tracker3/meta.db" in ctx["fim_noise_paths"]
    assert "/home/.v07-hidden-dir/.v07-payload.sh" in ctx["fim_suspicious_paths"]
    assert ctx["subthreshold_ssh_100200"] == {"192.168.56.101": 2}
    assert len(ctx["evasion_indicators"]) == 1

    md = format_v07_context_markdown(ctx)
    assert "v0.7 Triage Context" in md
    assert "192.168.56.101" in md


def test_sysmon_eid_semantics_and_timestamps():
    """Separates process/target images, target files, and alert vs. event timestamps."""
    from soc_automation.triage import _extract_alert_data

    eid1_alert = {
        "timestamp": "2026-11-21T12:39:48.344+0530",
        "rule": {"id": "100110", "level": 12, "description": "SENTINEL Sysmon: Suspicious shell"},
        "syscheck": {"path": None},
        "data": {
            "win": {
                "system": {"systemTime": "2026-11-21T07:09:40.1000000Z"},
                "eventdata": {
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                },
            }
        },
    }
    eid10_alert = {
        "timestamp": "2026-11-21T12:42:10.000+0530",
        "rule": {"id": "100130", "level": 12, "description": "SENTINEL Sysmon: Process access"},
        "syscheck": {"path": "   "},
        "data": {
            "win": {
                "system": {"systemTime": "2026-11-21T07:12:05.0000000Z"},
                "eventdata": {
                    "sourceImage": "C:\\Windows\\System32\\rundll32.exe",
                    "targetImage": "C:\\Windows\\System32\\lsass.exe",
                },
            }
        },
    }
    eid11_alert = {
        "timestamp": "2026-11-21T12:46:33.672+0530",
        "rule": {"id": "100140", "level": 10, "description": "SENTINEL Sysmon: Dump file created"},
        "data": {
            "win": {
                "system": {"systemTime": "2026-11-21T07:16:30.0000000Z"},
                "eventdata": {
                    "image": "C:\\Windows\\System32\\rundll32.exe",
                    "targetFilename": "C:\\Windows\\System32\\lsass.dmp",
                },
            }
        },
    }

    d1 = _extract_alert_data(eid1_alert)
    assert d1["fim_path"] is None
    assert d1["process_image"] == "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    assert d1["file_path"] == "N/A"
    assert d1["alert_timestamp"] == "2026-11-21T12:39:48.344+0530"
    assert d1["event_timestamp"] == "2026-11-21T07:09:40.1000000Z"

    d10 = _extract_alert_data(eid10_alert)
    assert d10["fim_path"] is None
    assert d10["process_image"] == "C:\\Windows\\System32\\rundll32.exe"
    assert d10["target_process_image"] == "C:\\Windows\\System32\\lsass.exe"
    assert d10["file_path"] == "N/A"

    d11 = _extract_alert_data(eid11_alert)
    assert d11["target_file"] == "C:\\Windows\\System32\\lsass.dmp"
    assert d11["process_image"] == "C:\\Windows\\System32\\rundll32.exe"
    assert d11["file_path"] == "C:\\Windows\\System32\\lsass.dmp"

    summary = generate_summary_report([eid1_alert, eid10_alert, eid11_alert], output_format="dict")
    assert summary["rules"]["100110"]["affected_paths"] == []
    assert summary["rules"]["100130"]["affected_paths"] == []
    assert summary["rules"]["100140"]["affected_paths"] == ["C:\\Windows\\System32\\lsass.dmp"]
