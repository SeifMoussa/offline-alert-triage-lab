"""Build deterministic report models from the local triage pipeline."""

from __future__ import annotations

from pathlib import Path

from triage_lab import __version__
from triage_lab.classification.engine import classify_loaded_alerts
from triage_lab.explanations.engine import explain_loaded_alerts
from triage_lab.grouping.engine import group_loaded_alerts
from triage_lab.mitre.mapping import map_loaded_alerts_to_mitre
from triage_lab.models.report import ReportMetadata, SecurityReport
from triage_lab.redaction.serializer import serialize_for_output
from triage_lab.reporting.summary import build_report_summary, collect_errors

DEFAULT_REPORT_GENERATED_AT = "2026-06-25T00:00:00Z"
PROJECT_NAME = "AI-Assisted Security Alert Triage Lab"


def build_security_report(
    input_path: str | Path,
    *,
    rules_config_path: str | Path | None = None,
    mitre_config_path: str | Path | None = None,
    triage_config_path: str | Path | None = None,
    grouping_config_path: str | Path | None = None,
    generated_at: str = DEFAULT_REPORT_GENERATED_AT,
) -> SecurityReport:
    """Run the local pipeline and return a redacted report model."""
    classification = classify_loaded_alerts(input_path, rules_config_path)
    mitre = map_loaded_alerts_to_mitre(input_path, mitre_config_path)
    explanations = explain_loaded_alerts(
        input_path,
        rules_config_path=rules_config_path,
        mitre_config_path=mitre_config_path,
        triage_config_path=triage_config_path,
    )
    grouping = group_loaded_alerts(
        input_path,
        rules_config_path=rules_config_path,
        mitre_config_path=mitre_config_path,
        triage_config_path=triage_config_path,
        grouping_config_path=grouping_config_path,
    )
    raw_report_payload = {
        "incidents": grouping.get("incidents", []),
        "explained_alerts": explanations.get("explained_alerts", []),
        "errors": collect_errors(classification, mitre, explanations, grouping),
    }
    redaction = serialize_for_output(raw_report_payload)
    metadata = ReportMetadata(
        generated_at=generated_at,
        project_name=PROJECT_NAME,
        report_type="security_alert_triage",
        input_path=str(input_path),
        synthetic_data_only=True,
        offline_only=True,
        deterministic_ai=True,
        redaction_policy=redaction.summary.redaction_policy,
        tool_version=__version__,
    )
    summary = build_report_summary(
        classification,
        mitre,
        explanations,
        grouping,
        safe_for_output=redaction.safe_for_output,
    )
    report = SecurityReport(
        metadata=metadata,
        summary=summary,
        incidents=redaction.payload["incidents"],
        explained_alerts=redaction.payload["explained_alerts"],
        redaction_summary=redaction.summary,
        validation_errors=redaction.validation_errors,
        errors=redaction.payload["errors"],
    )
    final_validation = serialize_for_output(report)
    if final_validation.safe_for_output:
        return report
    return report.model_copy(
        update={
            "summary": report.summary.model_copy(update={"safe_for_output": False}),
            "validation_errors": final_validation.validation_errors,
        }
    )
