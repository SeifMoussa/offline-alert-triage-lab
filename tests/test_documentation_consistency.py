from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_documentation_does_not_claim_hosted_ci_or_release_success() -> None:
    docs = "\n".join(
        path.read_text(encoding="utf-8")
        for path in [
            ROOT / "README.md",
            ROOT / "TESTING_REPORT.md",
            ROOT / "docs" / "testing-guide.md",
            ROOT / "docs" / "release-checklist.md",
        ]
    ).lower()

    assert "hosted ci passed" not in docs
    assert "github actions passed" not in docs
    assert "codeql passed on github" not in docs
    assert "release has been created" not in docs
    assert "repository is published" not in docs


def test_readme_and_reports_are_consistent() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    json_report = (
        ROOT / "reports" / "examples" / "security_alert_triage_report.json"
    ).read_text(encoding="utf-8")
    markdown_report = (
        ROOT / "reports" / "examples" / "security_alert_triage_report.md"
    ).read_text(encoding="utf-8")

    assert "CI, CodeQL, and Dependabot are configured locally" in readme
    assert "Hosted GitHub CI and CodeQL have not been verified yet" in readme
    assert "security_alert_triage_report.json" in readme
    assert "security_alert_triage_report.md" in readme
    assert "Safety Disclaimer" in markdown_report
    assert "default-report-safe-v1" in json_report
