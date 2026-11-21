import json
import sys

import pytest

from soc_automation.cli import main


@pytest.fixture
def sample_alert_file(tmp_path):
    """Create a valid sample Wazuh alert JSON file."""

    alert = {
        "timestamp": "2026-11-04T10:30:00Z",
        "rule": {
            "id": "550",
            "level": 7,
            "description": "Integrity checksum changed",
            "groups": ["syscheck"],
        },
        "agent": {
            "id": "001",
            "name": "SENTINEL-LINUX01",
        },
        "syscheck": {
            "path": "/home/test.txt",
        },
    }

    alert_file = tmp_path / "wazuh_alert.json"

    alert_file.write_text(
        json.dumps(alert),
        encoding="utf-8",
    )

    return alert_file


def run_cli(monkeypatch, arguments):
    """Run the CLI with simulated command-line arguments."""

    monkeypatch.setattr(
        sys,
        "argv",
        ["soc-automation"] + arguments,
    )

    return main()


def test_cli_help(monkeypatch, capsys):
    """Verify that the CLI displays help information."""

    with pytest.raises(SystemExit) as exit_info:
        run_cli(monkeypatch, ["--help"])

    assert exit_info.value.code == 0

    captured = capsys.readouterr()

    assert "Wazuh Alert Processor" in captured.out
    assert "--sha256" in captured.out
    assert "--enrich" in captured.out
    assert "--output" in captured.out
    assert "--triage" in captured.out


def test_cli_process_alert_to_stdout(
    monkeypatch,
    capsys,
    sample_alert_file,
):
    """Verify normal alert processing and JSON terminal output."""

    exit_code = run_cli(
        monkeypatch,
        [str(sample_alert_file)],
    )

    captured = capsys.readouterr()

    assert exit_code == 0

    result = json.loads(captured.out)

    assert result["schema_version"] == "1.2"
    assert result["alert"]["rule_id"] == "550"
    assert result["investigation"]["status"] == "new"


def test_cli_with_sha256(
    monkeypatch,
    capsys,
    sample_alert_file,
):
    """Verify that the SHA-256 option adds an integrity hash."""

    exit_code = run_cli(
        monkeypatch,
        [
            str(sample_alert_file),
            "--sha256",
        ],
    )

    captured = capsys.readouterr()

    assert exit_code == 0

    result = json.loads(captured.out)

    integrity = result["processing"]["integrity"]

    assert integrity["algorithm"] == "SHA-256"
    assert integrity["hash"] is not None
    assert len(integrity["hash"]) == 64


def test_cli_with_enrichment(
    monkeypatch,
    capsys,
    sample_alert_file,
):
    """Verify that the enrichment option enables enrichment."""

    exit_code = run_cli(
        monkeypatch,
        [
            str(sample_alert_file),
            "--enrich",
        ],
    )

    captured = capsys.readouterr()

    assert exit_code == 0

    result = json.loads(captured.out)

    assert "enrichment" in result
    assert result["enrichment"]["status"] == "complete"
    assert (
        result["enrichment"]["severity_context"]["severity_label"]
        == "Medium"
    )


def test_cli_save_output_file(
    monkeypatch,
    capsys,
    sample_alert_file,
    tmp_path,
):
    """Verify that processed JSON can be saved to a file."""

    output_file = tmp_path / "processed_alert.json"

    exit_code = run_cli(
        monkeypatch,
        [
            str(sample_alert_file),
            "--output",
            str(output_file),
        ],
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Successfully processed alert." in captured.out
    assert output_file.exists()

    result = json.loads(
        output_file.read_text(encoding="utf-8")
    )

    assert result["alert"]["rule_id"] == "550"


def test_cli_create_nested_output_directory(
    monkeypatch,
    capsys,
    sample_alert_file,
    tmp_path,
):
    """Verify that missing output directories are created automatically."""

    output_file = (
        tmp_path
        / "reports"
        / "cli"
        / "processed_alert.json"
    )

    exit_code = run_cli(
        monkeypatch,
        [
            str(sample_alert_file),
            "--output",
            str(output_file),
        ],
    )

    capsys.readouterr()

    assert exit_code == 0
    assert output_file.exists()
    assert output_file.parent.exists()


def test_cli_with_combined_options(
    monkeypatch,
    capsys,
    sample_alert_file,
    tmp_path,
):
    """Verify that enrichment, SHA-256, and output work together."""

    output_file = tmp_path / "combined_output.json"

    exit_code = run_cli(
        monkeypatch,
        [
            str(sample_alert_file),
            "--sha256",
            "--enrich",
            "--output",
            str(output_file),
        ],
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert output_file.exists()
    assert "Successfully processed alert." in captured.out

    result = json.loads(
        output_file.read_text(encoding="utf-8")
    )

    integrity = result["processing"]["integrity"]

    assert integrity["algorithm"] == "SHA-256"
    assert integrity["hash"] is not None
    assert len(integrity["hash"]) == 64

    assert result["enrichment"]["status"] == "complete"
    assert result["investigation"]["status"] == "new"


def test_cli_missing_input_file(
    monkeypatch,
    capsys,
    tmp_path,
):
    """Verify error handling when the input file does not exist."""

    missing_file = tmp_path / "missing_alert.json"

    exit_code = run_cli(
        monkeypatch,
        [str(missing_file)],
    )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Error:" in captured.err


def test_cli_invalid_json(
    monkeypatch,
    capsys,
    tmp_path,
):
    """Verify error handling for malformed JSON."""

    invalid_file = tmp_path / "invalid_alert.json"

    invalid_file.write_text(
        '{"rule": invalid json}',
        encoding="utf-8",
    )

    exit_code = run_cli(
        monkeypatch,
        [str(invalid_file)],
    )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Error:" in captured.err


def test_cli_invalid_json_root(
    monkeypatch,
    capsys,
    tmp_path,
):
    """Verify error handling when JSON root is not an object."""

    invalid_file = tmp_path / "invalid_root.json"

    invalid_file.write_text(
        json.dumps(["not", "an", "object"]),
        encoding="utf-8",
    )

    exit_code = run_cli(
        monkeypatch,
        [str(invalid_file)],
    )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Error:" in captured.err


def test_cli_triage_markdown_stdout(
    monkeypatch,
    capsys,
    tmp_path,
):
    """Verify that --triage outputs a Markdown summary report to stdout."""

    telemetry = [
        {
            "timestamp": "2026-11-02T10:15:30Z",
            "rule": {"id": "100003", "level": 8, "description": "FIM File Created"},
            "syscheck": {"path": "/home/sentinel-admin/test.txt"},
        },
        {
            "timestamp": "2026-11-02T10:16:30Z",
            "rule": {"id": "550", "level": 3, "description": "Checksum changed"},
            "syscheck": {"path": "/etc/issue"},
        },
    ]

    telemetry_file = tmp_path / "fim_telemetry.json"
    telemetry_file.write_text(json.dumps(telemetry), encoding="utf-8")

    exit_code = run_cli(
        monkeypatch,
        [str(telemetry_file), "--triage"],
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Wazuh FIM Triage Summary Report" in captured.out
    assert "| `100003` | 8 | 1 |" in captured.out
    assert "`/home/sentinel-admin/test.txt`" in captured.out
    # Level 3 alert must be filtered out
    assert "550" not in captured.out


def test_cli_triage_json_custom_min_level(
    monkeypatch,
    capsys,
    tmp_path,
):
    """Verify --triage with --report-format json and custom --min-level."""

    telemetry = [
        {
            "timestamp": "2026-11-02T10:15:30Z",
            "rule": {"id": "550", "level": 5, "description": "Medium severity event"},
            "syscheck": {"path": "/etc/passwd"},
        },
        {
            "timestamp": "2026-11-02T10:16:30Z",
            "rule": {"id": "100", "level": 2, "description": "Low severity event"},
            "syscheck": {"path": "/var/log/syslog"},
        },
    ]

    telemetry_file = tmp_path / "custom_telemetry.json"
    telemetry_file.write_text(json.dumps(telemetry), encoding="utf-8")

    exit_code = run_cli(
        monkeypatch,
        [
            str(telemetry_file),
            "--triage",
            "--min-level",
            "5",
            "--report-format",
            "json",
        ],
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    result = json.loads(captured.out)

    assert result["total_alerts"] == 1
    assert result["unique_rules"] == 1
    assert "550" in result["rules"]
    assert "100" not in result["rules"]


def test_cli_triage_save_output_file(
    monkeypatch,
    capsys,
    tmp_path,
):
    """Verify that --triage saves the report when --output is provided."""

    telemetry = [
        {
            "timestamp": "2026-11-02T10:15:30Z",
            "rule": {"id": "100004", "level": 8, "description": "FIM File Deleted"},
            "syscheck": {"path": "/home/sentinel-admin/deleted.txt"},
        }
    ]

    telemetry_file = tmp_path / "telemetry.json"
    telemetry_file.write_text(json.dumps(telemetry), encoding="utf-8")

    report_output = tmp_path / "reports" / "triage_summary.md"

    exit_code = run_cli(
        monkeypatch,
        [
            str(telemetry_file),
            "--triage",
            "--output",
            str(report_output),
        ],
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Successfully generated triage summary report." in captured.out
    assert report_output.exists()
    assert "| `100004` | 8 | 1 |" in report_output.read_text(encoding="utf-8")


def test_cli_triage_sysmon_process_and_malformed_records(
    monkeypatch,
    capsys,
    tmp_path,
):
    """Verify --triage surfaces process/event context and tolerates malformed records."""
    telemetry = [
        None,
        {},
        {
            "timestamp": "2026-11-21T07:10:00.000+0530",
            "rule": {
                "id": "100130",
                "level": 12,
                "description": "Sysmon LSASS process access",
            },
            "data": {
                "win": {
                    "eventdata": {
                        "utcTime": "2026-11-21 01:40:00.123",
                        "sourceImage": "C:\\Windows\\System32\\rundll32.exe",
                        "targetImage": "C:\\Windows\\System32\\lsass.exe",
                    }
                }
            },
        },
    ]

    telemetry_file = tmp_path / "sysmon_mixed.json"
    telemetry_file.write_text(json.dumps(telemetry), encoding="utf-8")

    # 1. JSON format check
    exit_code_json = run_cli(
        monkeypatch,
        [
            str(telemetry_file),
            "--triage",
            "--min-level",
            "8",
            "--report-format",
            "json",
        ],
    )
    captured_json = capsys.readouterr()
    assert exit_code_json == 0
    parsed = json.loads(captured_json.out)
    assert parsed["total_alerts"] == 1
    rule_100130 = parsed["rules"]["100130"]
    assert rule_100130["process_images"] == ["C:\\Windows\\System32\\rundll32.exe"]
    assert rule_100130["target_process_images"] == ["C:\\Windows\\System32\\lsass.exe"]
    assert rule_100130["event_timestamps"] == ["2026-11-21 01:40:00.123"]

    # 2. Markdown format check
    exit_code_md = run_cli(
        monkeypatch,
        [
            str(telemetry_file),
            "--triage",
            "--min-level",
            "8",
            "--report-format",
            "markdown",
        ],
    )
    captured_md = capsys.readouterr()
    assert exit_code_md == 0
    assert "Process & Event Timestamp Context" in captured_md.out
    assert "C:\\Windows\\System32\\rundll32.exe" in captured_md.out
    assert "C:\\Windows\\System32\\lsass.exe" in captured_md.out
    assert "2026-11-21 01:40:00.123" in captured_md.out
