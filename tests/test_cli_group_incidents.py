from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from triage_lab.cli import main

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


def test_group_incidents_json_output() -> None:
    result = run_cli(
        "group-incidents",
        "--input",
        "alerts/sample_alerts.json",
        "--format",
        "json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["incident_count"] == 1
    assert payload["grouped_alert_count"] == 22
    assert payload["highest_incident_severity"] == "CRITICAL"
    assert "raw_message" not in result.stdout


def test_group_incidents_text_output() -> None:
    result = run_cli(
        "group-incidents",
        "--input",
        "alerts/sample_alerts.json",
        "--format",
        "text",
    )

    assert result.returncode == 0
    assert "Incident grouping" in result.stdout
    assert "incident_count: 1" in result.stdout
    assert "errors: 0" in result.stdout


def test_group_incidents_rejects_unsafe_config_path() -> None:
    result = run_cli(
        "group-incidents",
        "--input",
        "alerts/sample_alerts.json",
        "--grouping-config",
        "https://example.com/grouping.yaml",
        "--format",
        "json",
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["errors"][0]["error_type"] == "grouping_config_error"


def test_cli_group_command_direct_main() -> None:
    exit_code = main(
        [
            "group-incidents",
            "--input",
            "alerts/sample_alerts.json",
            "--format",
            "json",
        ]
    )

    assert exit_code == 0


def test_existing_cli_commands_still_work() -> None:
    commands = [
        ("--help",),
        ("--version",),
        ("inventory", "--input", "alerts", "--format", "json"),
        ("validate-alerts", "--input", "alerts/sample_alerts.json", "--format", "json"),
        ("classify-alerts", "--input", "alerts/sample_alerts.json", "--format", "json"),
        ("map-mitre", "--input", "alerts/sample_alerts.json", "--format", "json"),
        ("explain-alerts", "--input", "alerts/sample_alerts.json", "--format", "json"),
    ]

    for command in commands:
        result = run_cli(*command)
        assert result.returncode == 0
