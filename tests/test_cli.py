from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from triage_lab.cli import build_parser, main

ROOT = Path(__file__).resolve().parents[1]


def run_module(*args: str) -> subprocess.CompletedProcess[str]:
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


def test_cli_help_works() -> None:
    result = run_module("--help")
    assert result.returncode == 0
    assert "offline-only deterministic security alert triage lab" in result.stdout
    assert "No network calls" in result.stdout
    assert "No external AI API" in result.stdout


def test_cli_version_works() -> None:
    result = run_module("--version")
    assert result.returncode == 0
    assert result.stdout.startswith("triage-lab ")


def test_cli_parser_description_and_main() -> None:
    parser = build_parser()
    assert "offline-only deterministic security alert triage lab" in parser.description
    assert main([]) == 0
