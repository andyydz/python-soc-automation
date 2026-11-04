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