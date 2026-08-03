from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from triage_lab.cli import main

ROOT = Path(__file__).resolve().parents[1]
HISTORY_DIR = "tests/fixtures/trend_history"
ERROR_HISTORY_DIR = "tests/fixtures/trend_history_errors"


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


def test_trend_report_json_output() -> None:
    result = run_cli(
        "trend-report",
        "--history-dir",
        HISTORY_DIR,
        "--format",
        "json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["run_count"] == 3
    assert payload["top_mitre_techniques"][0]["technique_id"] == "T1046"
    assert payload["errors"] == []


def test_trend_report_text_output() -> None:
    result = run_cli(
        "trend-report",
        "--history-dir",
        HISTORY_DIR,
        "--format",
        "text",
    )

    assert result.returncode == 0
    assert "Trend analytics" in result.stdout
    assert "run_count: 3" in result.stdout
    assert "errors: 0" in result.stdout


def test_trend_report_nonzero_exit_on_run_errors() -> None:
    result = run_cli(
        "trend-report",
        "--history-dir",
        ERROR_HISTORY_DIR,
        "--format",
        "json",
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["errors"]


def test_trend_report_rejects_unsafe_history_dir() -> None:
    result = run_cli(
        "trend-report",
        "--history-dir",
        "https://example.com/history",
        "--format",
        "json",
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["errors"][0]["error_type"] == "trend_history_error"


def test_cli_trend_report_direct_main() -> None:
    exit_code = main(
        [
            "trend-report",
            "--history-dir",
            HISTORY_DIR,
            "--format",
            "json",
        ]
    )

    assert exit_code == 0


def test_existing_cli_commands_still_work_with_trend_report_added() -> None:
    commands = [
        ("--help",),
        ("--version",),
        ("inventory", "--input", "alerts", "--format", "json"),
        ("group-incidents", "--input", "alerts/sample_alerts.json", "--format", "json"),
    ]

    for command in commands:
        result = run_cli(*command)
        assert result.returncode == 0
