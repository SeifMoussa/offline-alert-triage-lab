from __future__ import annotations

import json

from triage_lab.reporting.pipeline import build_security_report


def test_reporting_pipeline_builds_safe_report() -> None:
    report = build_security_report(
        "alerts/sample_alerts.json",
        generated_at="2026-06-25T12:00:00Z",
    )
    rendered = json.dumps(report.to_safe_dict(), sort_keys=True)

    assert report.metadata.generated_at == "2026-06-25T12:00:00Z"
    assert report.metadata.offline_only
    assert report.metadata.synthetic_data_only
    assert report.metadata.deterministic_ai
    assert report.summary.alerts_loaded == 22
    assert report.summary.classified_alerts == 22
    assert report.summary.explained_alerts == 22
    assert report.summary.incident_count == 1
    assert report.summary.highest_alert_severity == "CRITICAL"
    assert report.summary.highest_incident_severity == "CRITICAL"
    assert report.summary.safe_for_output
    assert report.validation_errors == []
    assert "raw_message" not in rendered
    assert "SYNTHETIC_TOKEN_MARKER" not in rendered
    assert "password=" not in rendered


def test_reporting_pipeline_collects_errors_for_bad_input() -> None:
    report = build_security_report(
        "tests/fixtures/malformed_alerts.json",
        generated_at="2026-06-25T12:00:00Z",
    )

    assert report.summary.alerts_loaded == 0
    assert report.errors
    assert report.summary.safe_for_output
