from soc_automation.enrichment.artifacts import extract_artifacts
from soc_automation.pipeline import process_wazuh_alert


def test_extract_artifacts_from_fim_and_sysmon_alerts():
    fim_alert = {
        "timestamp": "2026-11-02T10:15:30.100Z",
        "rule": {"id": "100003", "level": 8, "description": "FIM file created"},
        "agent": {"name": "SENTINEL-LINUX01"},
        "syscheck": {"path": "/home/sentinel-admin/notes.txt"},
    }
    fim_artifacts = extract_artifacts(fim_alert)
    assert fim_artifacts["file_paths"] == ["/home/sentinel-admin/notes.txt"]
    assert fim_artifacts["process_images"] == []
    assert fim_artifacts["target_process_images"] == []
    assert fim_artifacts["ip_addresses"] == []

    sysmon_alert = {
        "timestamp": "2026-11-21T07:10:00.000+0530",
        "rule": {"id": "100130", "level": 12, "description": "Sysmon process access"},
        "agent": {"name": "WIN-REPLAY"},
        "data": {
            "win": {
                "eventdata": {
                    "image": "C:\\Windows\\System32\\rundll32.exe",
                    "targetImage": "C:\\Windows\\System32\\lsass.exe",
                    "targetFilename": "C:\\Windows\\System32\\lsass.dmp",
                    "sourceIp": "10.10.10.20",
                }
            }
        },
    }
    processed = process_wazuh_alert(sysmon_alert)
    artifacts = extract_artifacts(processed)
    assert artifacts["file_paths"] == ["C:\\Windows\\System32\\lsass.dmp"]
    assert artifacts["process_images"] == ["C:\\Windows\\System32\\rundll32.exe"]
    assert artifacts["target_process_images"] == ["C:\\Windows\\System32\\lsass.exe"]
    assert artifacts["ip_addresses"] == ["10.10.10.20"]


def test_extract_artifacts_handles_malformed_and_empty_inputs():
    assert extract_artifacts(None) == {
        "file_paths": [],
        "process_images": [],
        "target_process_images": [],
        "ip_addresses": [],
    }
    assert extract_artifacts({})["file_paths"] == []
    assert extract_artifacts({"syscheck": {"path": "   "}, "data": {"srcip": ""}})["ip_addresses"] == []


def test_collect_triage_artifacts_and_summary():
    from soc_automation.triage import generate_summary_report

    alerts = [
        {
            "timestamp": "2026-11-21T07:10:00Z",
            "rule": {"id": "100130", "level": 12, "description": "Sysmon process access"},
            "data": {
                "srcip": "10.0.0.5",
                "win": {
                    "eventdata": {
                        "image": "C:\\Windows\\System32\\rundll32.exe",
                        "targetImage": "C:\\Windows\\System32\\lsass.exe",
                        "targetFilename": "C:\\Temp\\dump.dmp",
                    }
                },
            },
        }
    ]
    summary = generate_summary_report(alerts, output_format="dict")
    assert summary["artifacts"]["ip_addresses"] == ["10.0.0.5"]
    assert summary["artifacts"]["file_paths"] == ["C:\\Temp\\dump.dmp"]
    assert summary["artifacts"]["process_images"] == ["C:\\Windows\\System32\\rundll32.exe"]
    assert summary["artifacts"]["target_process_images"] == ["C:\\Windows\\System32\\lsass.exe"]
