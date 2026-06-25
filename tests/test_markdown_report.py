from __future__ import annotations

from triage_lab.reporting.markdown_report import render_markdown_report
from triage_lab.reporting.pipeline import build_security_report


def test_markdown_report_contains_expected_sections_and_safe_metadata() -> None:
    report = build_security_report(
        "alerts/sample_alerts.json",
        generated_at="2026-06-25T00:00:00Z",
    )

    rendered = render_markdown_report(report)

    assert "# Security Alert Triage Report" in rendered
    assert "## Safety Disclaimer" in rendered
    assert "## Executive Summary" in rendered
    assert "## MITRE Mapping Summary" in rendered
    assert "## Incident Summary" in rendered
    assert "## Incident Details" in rendered
    assert "## Explained Alert Summaries" in rendered
    assert "## Redaction Summary" in rendered
    assert "## Limitations" in rendered
    assert "deterministic rule-based logic" in rendered
    assert "external AI APIs" in rendered
    assert "INC-0001" in rendered
    assert "T1110" in rendered
    assert "Triage recommendations" in rendered
    assert "workstation-01.test" in rendered


def test_markdown_report_excludes_sensitive_values() -> None:
    report = build_security_report("alerts/sample_alerts.json")
    rendered = render_markdown_report(report)

    assert "raw_message" not in rendered
    assert "SYNTHETIC_PASSWORD_MARKER" not in rendered
    assert "SYNTHETIC_TOKEN_MARKER" not in rendered
    assert "SYNTHETIC_SECRET_MARKER" not in rendered
    assert "password=" not in rendered
    assert "token=" not in rendered
    assert "secret=" not in rendered
    assert "api_key=" not in rendered
    assert "private_key" not in rendered
    assert "10.0." not in rendered
    assert "192.168." not in rendered
