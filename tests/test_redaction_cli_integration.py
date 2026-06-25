from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = (
    "SYNTHETIC_PASSWORD_MARKER",
    "SYNTHETIC_TOKEN_MARKER",
    "SYNTHETIC_SECRET_MARKER",
    "password=",
    "token=",
    "secret=",
    "api_key=",
)


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


def assert_no_forbidden_output(text: str) -> None:
    for value in FORBIDDEN:
        assert value not in text


def test_pipeline_cli_outputs_are_redaction_safe() -> None:
    commands = [
        ("classify-alerts", "--input", "alerts/sample_alerts.json", "--format", "json"),
        ("map-mitre", "--input", "alerts/sample_alerts.json", "--format", "json"),
        ("explain-alerts", "--input", "alerts/sample_alerts.json", "--format", "json"),
        ("group-incidents", "--input", "alerts/sample_alerts.json", "--format", "json"),
        ("group-incidents", "--input", "alerts/sample_alerts.json", "--format", "text"),
    ]

    for command in commands:
        result = run_cli(*command)
        assert result.returncode == 0
        assert "raw_message" not in result.stdout
        assert_no_forbidden_output(result.stdout)


def test_redact_check_command_reports_safe_summary() -> None:
    result = run_cli(
        "redact-check",
        "--input",
        "alerts/sample_alerts.json",
        "--format",
        "json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["safe_for_output"] is True
    assert payload["prohibited_values_found"] == []
    assert payload["validation_errors"] == []
    assert payload["redaction_summary"]["redaction_policy"] == "default-report-safe-v1"
    assert "errors" in payload
    assert_no_forbidden_output(result.stdout)


def test_help_and_version_still_work_with_redact_check() -> None:
    help_result = run_cli("--help")
    version_result = run_cli("--version")

    assert help_result.returncode == 0
    assert "redact-check" in help_result.stdout
    assert version_result.returncode == 0
    assert version_result.stdout.startswith("triage-lab ")
