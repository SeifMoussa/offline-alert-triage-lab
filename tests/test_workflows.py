from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_ci_workflow_has_stable_jobs_and_coverage_gate() -> None:
    path = ROOT / ".github" / "workflows" / "ci.yml"
    assert path.exists()
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))

    assert workflow["name"] == "CI"
    jobs = workflow["jobs"]
    job_names = {job["name"] for job in jobs.values()}
    assert {"Tests", "Docs Safety Checks", "CLI Smoke"}.issubset(job_names)
    rendered = path.read_text(encoding="utf-8")
    assert "--cov-fail-under=97" in rendered
    assert "python -m pytest" in rendered
    assert "python -m ruff check ." in rendered
    assert "python -m ruff format --check ." in rendered
    assert "python scripts/check-docs.py" in rendered
    assert "python -m triage_lab report" in rendered
    assert "raw_message" in rendered


def test_codeql_workflow_targets_python() -> None:
    path = ROOT / ".github" / "workflows" / "codeql.yml"
    assert path.exists()
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))

    assert workflow["name"] == "CodeQL"
    rendered = path.read_text(encoding="utf-8")
    assert "language: [python]" in rendered
    assert "github/codeql-action/init" in rendered
    assert "github/codeql-action/analyze" in rendered
    assert "security-and-quality" in rendered


def test_dependabot_tracks_pip_and_github_actions() -> None:
    path = ROOT / ".github" / "dependabot.yml"
    assert path.exists()
    config = yaml.safe_load(path.read_text(encoding="utf-8"))

    ecosystems = {item["package-ecosystem"] for item in config["updates"]}
    assert ecosystems == {"pip", "github-actions"}
    assert all(item["schedule"]["interval"] == "weekly" for item in config["updates"])
