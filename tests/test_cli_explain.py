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


def test_explain_alerts_json_output() -> None:
    result = run_cli(
        "explain-alerts",
        "--input",
        "alerts/sample_alerts.json",
        "--format",
        "json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["alerts_loaded"] == 22
    assert len(payload["explained_alerts"]) == 22
    assert payload["severity_counts"]["CRITICAL"] == 14
    assert "raw_message" not in result.stdout


def test_explain_alerts_text_output() -> None:
    result = run_cli(
        "explain-alerts",
        "--input",
        "alerts/sample_alerts.json",
        "--format",
        "text",
    )

    assert result.returncode == 0
    assert "Alert explanations" in result.stdout
    assert "alerts_loaded: 22" in result.stdout


def test_explain_alerts_custom_config_flags() -> None:
    result = run_cli(
        "explain-alerts",
        "--input",
        "alerts/sample_alerts.json",
        "--rules",
        "config/rules.yaml",
        "--mitre-config",
        "config/mitre_mapping.yaml",
        "--triage-config",
        "config/triage_steps.yaml",
        "--format",
        "json",
    )

    assert result.returncode == 0
    assert json.loads(result.stdout)["errors"] == []


def test_explain_main_json_output(capsys) -> None:
    exit_code = main(
        [
            "explain-alerts",
            "--input",
            "alerts/sample_alerts.json",
            "--format",
            "json",
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["alerts_loaded"] == 22


def test_existing_cli_commands_still_work() -> None:
    commands = [
        ("--help",),
        ("--version",),
        ("inventory", "--input", "alerts", "--format", "json"),
        ("validate-alerts", "--input", "alerts/sample_alerts.json", "--format", "json"),
        ("classify-alerts", "--input", "alerts/sample_alerts.json", "--format", "json"),
        ("map-mitre", "--input", "alerts/sample_alerts.json", "--format", "json"),
    ]

    for command in commands:
        result = run_cli(*command)
        assert result.returncode == 0
