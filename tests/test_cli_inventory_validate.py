from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from triage_lab.cli import main, print_output

ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", "triage_lab", *args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_inventory_json_output() -> None:
    result = run_cli("inventory", "--input", "alerts", "--format", "json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["alerts_loaded"] == 22
    assert payload["records_seen"] == 22
    assert payload["event_type_counts"]["brute_force"] == 2


def test_validate_alerts_json_output() -> None:
    result = run_cli(
        "validate-alerts",
        "--input",
        "alerts/sample_alerts.json",
        "--format",
        "json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["valid"] is True
    assert payload["alerts_loaded"] == 22
    assert payload["error_count"] == 0


def test_validate_alerts_text_output() -> None:
    result = run_cli(
        "validate-alerts",
        "--input",
        "alerts/sample_alerts.json",
        "--format",
        "text",
    )

    assert result.returncode == 0
    assert "Alert validation" in result.stdout
    assert "valid: True" in result.stdout
    assert "alerts_loaded: 22" in result.stdout


def test_validate_alerts_invalid_output_redacts_sensitive_marker() -> None:
    result = run_cli(
        "validate-alerts",
        "--input",
        "tests/fixtures/malformed_alerts.json",
        "--format",
        "json",
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["valid"] is False
    assert payload["error_count"] >= 1


def test_inventory_main_json_output(capsys) -> None:
    exit_code = main(["inventory", "--input", "alerts", "--format", "json"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["alerts_loaded"] == 22


def test_validate_main_text_output(capsys) -> None:
    exit_code = main(
        [
            "validate-alerts",
            "--input",
            "alerts/sample_alerts.json",
            "--format",
            "text",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Alert validation" in captured.out
    assert "errors: 0" in captured.out


def test_validate_main_invalid_returns_nonzero(capsys) -> None:
    exit_code = main(
        [
            "validate-alerts",
            "--input",
            "tests/fixtures/malformed_alerts.json",
            "--format",
            "text",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "validation_error" in captured.out


def test_print_output_json(capsys) -> None:
    print_output({"valid": True, "errors": []}, "json", title="Test")

    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"errors": [], "valid": True}
