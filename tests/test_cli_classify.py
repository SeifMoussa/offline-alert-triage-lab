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


def test_classify_alerts_json_output() -> None:
    result = run_cli(
        "classify-alerts",
        "--input",
        "alerts/sample_alerts.json",
        "--format",
        "json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["alerts_loaded"] == 22
    assert len(payload["classified_alerts"]) == 22
    assert payload["highest_severity"] == "CRITICAL"
    assert payload["ruleset"]["name"] == "offline-alert-triage-default-rules"
    assert payload["severity_counts"]["CRITICAL"] >= 1
    assert "raw_message" not in result.stdout


def test_classify_alerts_text_output() -> None:
    result = run_cli(
        "classify-alerts",
        "--input",
        "alerts/sample_alerts.json",
        "--format",
        "text",
    )

    assert result.returncode == 0
    assert "Alert classification" in result.stdout
    assert "highest_severity: CRITICAL" in result.stdout


def test_classify_alerts_custom_config_output() -> None:
    result = run_cli(
        "classify-alerts",
        "--input",
        "alerts/sample_alerts.json",
        "--config",
        "config/rules.yaml",
        "--format",
        "json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["ruleset"]["version"] == 1


def test_classify_main_json_output(capsys) -> None:
    exit_code = main(
        [
            "classify-alerts",
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


def test_cli_help_and_version_still_work() -> None:
    help_result = run_cli("--help")
    version_result = run_cli("--version")

    assert help_result.returncode == 0
    assert "classify-alerts" in help_result.stdout
    assert version_result.returncode == 0
    assert version_result.stdout.startswith("triage-lab ")
