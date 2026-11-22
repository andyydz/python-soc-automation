import json
import subprocess
import sys
from pathlib import Path


def _fim_probe_alerts() -> list[dict]:
    path = "/home/sentinel-admin/.fim_probe_test.txt"
    return [
        {
            "id": "1700000001.101",
            "timestamp": "2026-11-22T22:21:16.923+0530",
            "rule": {
                "id": "100003",
                "level": 8,
                "description": "SENTINEL: New file created in monitored home directory.",
            },
            "agent": {"id": "002", "name": "sentinel-linux01", "ip": "10.10.10.40"},
            "syscheck": {"path": path, "event": "added"},
        },
        {
            "id": "1700000001.102",
            "timestamp": "2026-11-22T22:21:18.925+0530",
            "rule": {
                "id": "100002",
                "level": 8,
                "description": "SENTINEL: File integrity modification detected in monitored home directory.",
            },
            "agent": {"id": "002", "name": "sentinel-linux01", "ip": "10.10.10.40"},
            "syscheck": {"path": path, "event": "modified"},
        },
        {
            "id": "1700000001.103",
            "timestamp": "2026-11-22T22:21:20.927+0530",
            "rule": {
                "id": "100004",
                "level": 8,
                "description": "SENTINEL: File deleted from monitored home directory.",
            },
            "agent": {"id": "002", "name": "sentinel-linux01", "ip": "10.10.10.40"},
            "syscheck": {"path": path, "event": "deleted"},
        },
    ]


def test_json_triage_report_linux_fim_probe_and_empty_process_fields(tmp_path: Path):
    alerts_file = tmp_path / "fim_probe_alerts.json"
    alerts_file.write_text(json.dumps(_fim_probe_alerts()), encoding="utf-8")

    repo_root = Path(__file__).resolve().parents[1]
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "soc_automation.cli",
            str(alerts_file),
            "--sha256",
            "--enrich",
            "--triage",
            "--min-level",
            "8",
            "--report-format",
            "json",
        ],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    )

    report = json.loads(proc.stdout)
    target = "/home/sentinel-admin/.fim_probe_test.txt"

    assert report["total_alerts"] == 3
    assert report["unique_rules"] == 3
    assert set(report["rules"].keys()) == {"100003", "100002", "100004"}

    for rule_id in ("100003", "100002", "100004"):
        rule_entry = report["rules"][rule_id]
        assert rule_entry["level"] == 8
        assert rule_entry["count"] == 1
        assert rule_entry["affected_paths"] == [target]
        assert rule_entry["process_images"] == []
        assert rule_entry["target_process_images"] == []
        assert rule_entry["event_timestamps"] == []
        assert rule_entry["first_seen"] == rule_entry["last_seen"]

    assert report["rules"]["100003"]["first_seen"] == "2026-11-22T22:21:16.923+0530"
    assert report["rules"]["100002"]["first_seen"] == "2026-11-22T22:21:18.925+0530"
    assert report["rules"]["100004"]["first_seen"] == "2026-11-22T22:21:20.927+0530"

    assert report["artifacts"]["file_paths"] == [target]
    assert report["artifacts"]["process_images"] == []
    assert report["artifacts"]["target_process_images"] == []
    assert report["artifacts"]["ip_addresses"] == []

    assert target in report["v07_triage_context"]["fim_suspicious_paths"]
    assert report["v07_triage_context"]["fim_noise_paths"] == []


def test_json_triage_report_unknown_timestamps_when_omitted(tmp_path: Path):
    alerts = [
        {
            "rule": {"id": "100002", "level": 8, "description": "FIM modified"},
            "agent": {"id": "002", "name": "sentinel-linux01"},
            "syscheck": {"path": "/home/sentinel-admin/.fim_probe_test.txt", "event": "modified"},
        }
    ]
    alerts_file = tmp_path / "no_ts.json"
    alerts_file.write_text(json.dumps(alerts), encoding="utf-8")

    repo_root = Path(__file__).resolve().parents[1]
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "soc_automation.cli",
            str(alerts_file),
            "--triage",
            "--min-level",
            "8",
            "--report-format",
            "json",
        ],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    )

    report = json.loads(proc.stdout)
    rule_entry = report["rules"]["100002"]
    assert rule_entry["first_seen"] == "UNKNOWN"
    assert rule_entry["last_seen"] == "UNKNOWN"


def test_json_triage_report_supports_schema_1_2_envelopes(tmp_path: Path):
    target = "/home/sentinel-admin/.fim_probe_test.txt"
    envelopes = [
        {
            "schema_version": "1.2",
            "record_type": "normalized_alert",
            "alert": {
                "rule_id": "100002",
                "severity": 8,
                "agent": "sentinel-linux01",
                "description": "SENTINEL: File integrity modification detected in monitored home directory.",
                "timestamp_original": "2026-11-22T22:21:18.925+0530",
                "timestamp_utc": "2026-11-22T16:51:18.925000Z",
            },
            "raw_alert": {
                "timestamp": "2026-11-22T22:21:18.925+0530",
                "syscheck": {"path": target, "event": "modified"},
            },
        }
    ]
    alerts_file = tmp_path / "normalized_1_2.json"
    alerts_file.write_text(json.dumps(envelopes), encoding="utf-8")

    repo_root = Path(__file__).resolve().parents[1]
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "soc_automation.cli",
            str(alerts_file),
            "--triage",
            "--min-level",
            "8",
            "--report-format",
            "json",
        ],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    )

    report = json.loads(proc.stdout)
    assert report["total_alerts"] == 1
    assert "100002" in report["rules"]
    assert report["rules"]["100002"]["level"] == 8
    assert report["rules"]["100002"]["affected_paths"] == [target]
    assert target in report["v07_triage_context"]["fim_suspicious_paths"]


def test_triage_mode_honors_sha256_and_enrich_flags(tmp_path: Path):
    import hashlib

    sample = [
        {
            "schema_version": "1.2",
            "record_type": "normalized_alert",
            "alert": {
                "rule_id": "100002",
                "severity": 8,
                "agent": "sentinel-linux01",
                "description": "SENTINEL FIM modification test",
                "timestamp_utc": "2026-11-22T16:51:18.925000Z",
            },
        }
    ]
    raw_bytes = json.dumps(sample).encode("utf-8")
    expected_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    alerts_file = tmp_path / "triage_enriched.json"
    alerts_file.write_bytes(raw_bytes)

    repo_root = Path(__file__).resolve().parents[1]
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "soc_automation.cli",
            str(alerts_file),
            "--sha256",
            "--enrich",
            "--triage",
            "--min-level",
            "8",
            "--report-format",
            "json",
        ],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    )

    report = json.loads(proc.stdout)
    assert report["source_sha256"] == expected_sha256
    assert isinstance(report.get("enrichments"), list)
    assert len(report["enrichments"]) == 1
