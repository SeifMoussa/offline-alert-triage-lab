from __future__ import annotations

from triage_lab.models.redaction import RedactionSummary
from triage_lab.models.report import ReportMetadata, ReportSummary, SecurityReport


def test_report_model_creation_and_safe_dict() -> None:
    report = SecurityReport(
        metadata=ReportMetadata(
            generated_at="2026-06-25T00:00:00Z",
            project_name="AI-Assisted Security Alert Triage Lab",
            report_type="security_alert_triage",
            input_path="alerts/sample_alerts.json",
            synthetic_data_only=True,
            offline_only=True,
            deterministic_ai=True,
            redaction_policy="default-report-safe-v1",
            tool_version="0.1.0",
        ),
        summary=ReportSummary(
            alerts_loaded=1,
            malformed_records=0,
            classified_alerts=1,
            explained_alerts=1,
            incident_count=0,
            grouped_alert_count=0,
            ungrouped_alert_count=1,
            highest_alert_severity="LOW",
            highest_incident_severity=None,
            severity_counts={"LOW": 1},
            tactics_observed=[],
            techniques_observed=[],
            safe_for_output=True,
        ),
        redaction_summary=RedactionSummary(),
    )

    safe = report.to_safe_dict()

    assert safe["metadata"]["offline_only"] is True
    assert safe["summary"]["safe_for_output"] is True
    assert safe["redaction_summary"]["redaction_policy"] == "default-report-safe-v1"
