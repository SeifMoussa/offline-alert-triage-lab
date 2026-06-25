from __future__ import annotations

from triage_lab.reporting.json_report import render_json_report
from triage_lab.reporting.markdown_report import render_markdown_report
from triage_lab.reporting.pipeline import build_security_report

FORBIDDEN = (
    "SYNTHETIC_PASSWORD_MARKER",
    "SYNTHETIC_TOKEN_MARKER",
    "SYNTHETIC_SECRET_MARKER",
    "password=",
    "token=",
    "secret=",
    "api_key=",
    "private_key",
    "raw_message",
)
RAW_VALUES = (
    "10.1.1.10",
    "10.1.1.20",
    "192.168.",
    "198.51.100.25",
    "test_admin",
    "analyst_user",
)


def test_generated_reports_do_not_expose_sensitive_values() -> None:
    report = build_security_report("alerts/sample_alerts.json")
    rendered = render_json_report(report) + "\n" + render_markdown_report(report)

    for value in FORBIDDEN:
        assert value not in rendered
    for value in RAW_VALUES:
        assert value not in rendered
    assert "workstation-01.test" in rendered
    assert "T1110" in rendered
    assert "INC-0001" in rendered
    assert "CRITICAL" in rendered


def test_reports_document_no_external_ai_or_network_behavior() -> None:
    report = build_security_report("alerts/sample_alerts.json")
    rendered = render_markdown_report(report)

    assert "does not use external AI APIs" in rendered
    assert "LLM calls" in rendered
    assert "network calls" in rendered
    assert "external MITRE APIs" in rendered
    assert "synthetic local alert data only" in rendered
