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


def test_map_mitre_json_output() -> None:
    result = run_cli(
        "map-mitre",
        "--input",
        "alerts/sample_alerts.json",
        "--format",
        "json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["alerts_loaded"] == 22
    assert len(payload["mapped_alerts"]) == 22
    assert payload["mapping_counts"] == {"fallback": 4, "mapped": 18}
    assert "T1110" in payload["techniques_observed"]
    assert "raw_message" not in result.stdout


def test_map_mitre_text_output() -> None:
    result = run_cli(
        "map-mitre",
        "--input",
        "alerts/sample_alerts.json",
        "--format",
        "text",
    )

    assert result.returncode == 0
    assert "MITRE mapping" in result.stdout
    assert "alerts_loaded: 22" in result.stdout


def test_map_mitre_custom_config_output() -> None:
    result = run_cli(
        "map-mitre",
        "--input",
        "alerts/sample_alerts.json",
        "--config",
        "config/mitre_mapping.yaml",
        "--format",
        "json",
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["mapping_config"]["version"] == 1


def test_map_mitre_main_json_output(capsys) -> None:
    exit_code = main(
        [
            "map-mitre",
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
    help_result = run_cli("--help")
    version_result = run_cli("--version")
    classify_result = run_cli(
        "classify-alerts",
        "--input",
        "alerts/sample_alerts.json",
        "--format",
        "json",
    )
    inventory_result = run_cli("inventory", "--input", "alerts", "--format", "json")
    validate_result = run_cli(
        "validate-alerts",
        "--input",
        "alerts/sample_alerts.json",
        "--format",
        "json",
    )

    assert help_result.returncode == 0
    assert "map-mitre" in help_result.stdout
    assert version_result.returncode == 0
    assert classify_result.returncode == 0
    assert inventory_result.returncode == 0
    assert validate_result.returncode == 0
