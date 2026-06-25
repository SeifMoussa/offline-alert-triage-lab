from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

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


def test_report_command_json_markdown_and_both(tmp_path: Path) -> None:
    for report_format in ("json", "markdown", "both"):
        output_dir = tmp_path / report_format
        result = run_cli(
            "report",
            "--input",
            "alerts/sample_alerts.json",
            "--output",
            str(output_dir),
            "--format",
            report_format,
        )

        assert result.returncode == 0
        payload = json.loads(result.stdout)
        assert payload["safe_for_output"] is True
        assert payload["alerts_loaded"] == 22
        assert payload["incident_count"] == 1
        if report_format in {"json", "both"}:
            assert payload["json_report_path"].endswith(
                "security_alert_triage_report.json"
            )
            assert Path(payload["json_report_path"]).exists()
        if report_format in {"markdown", "both"}:
            assert payload["markdown_report_path"].endswith(
                "security_alert_triage_report.md"
            )
            assert Path(payload["markdown_report_path"]).exists()


def test_report_command_supports_optional_config_flags(tmp_path: Path) -> None:
    result = run_cli(
        "report",
        "--input",
        "alerts/sample_alerts.json",
        "--output",
        str(tmp_path),
        "--format",
        "json",
        "--rules",
        "config/rules.yaml",
        "--mitre-config",
        "config/mitre_mapping.yaml",
        "--triage-config",
        "config/triage_steps.yaml",
        "--grouping-config",
        "config/grouping_rules.yaml",
    )

    assert result.returncode == 0
    assert json.loads(result.stdout)["json_report_path"]


def test_report_command_rejects_unsafe_output_path() -> None:
    result = run_cli(
        "report",
        "--input",
        "alerts/sample_alerts.json",
        "--output",
        "https://example.com/reports",
        "--format",
        "json",
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["safe_for_output"] is False
    assert payload["errors"][0]["error_type"] == "report_output_error"


def test_existing_cli_commands_still_work_with_report_command() -> None:
    commands = [
        ("--help",),
        ("--version",),
        ("inventory", "--input", "alerts", "--format", "json"),
        ("validate-alerts", "--input", "alerts/sample_alerts.json", "--format", "json"),
        ("classify-alerts", "--input", "alerts/sample_alerts.json", "--format", "json"),
        ("map-mitre", "--input", "alerts/sample_alerts.json", "--format", "json"),
        ("explain-alerts", "--input", "alerts/sample_alerts.json", "--format", "json"),
        ("group-incidents", "--input", "alerts/sample_alerts.json", "--format", "json"),
        ("redact-check", "--input", "alerts/sample_alerts.json", "--format", "json"),
    ]

    for command in commands:
        result = run_cli(*command)
        assert result.returncode == 0
    assert "report" in run_cli("--help").stdout
