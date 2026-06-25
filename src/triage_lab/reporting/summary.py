"""Report summary helpers."""

from __future__ import annotations

from typing import Any

from triage_lab.models.report import ReportSummary


def build_report_summary(
    classification_payload: dict[str, Any],
    mitre_payload: dict[str, Any],
    explanation_payload: dict[str, Any],
    grouping_payload: dict[str, Any],
    *,
    safe_for_output: bool,
) -> ReportSummary:
    """Build deterministic aggregate counts from pipeline stage payloads."""
    return ReportSummary(
        alerts_loaded=int(grouping_payload.get("alerts_loaded", 0)),
        malformed_records=int(grouping_payload.get("malformed_records", 0)),
        classified_alerts=len(classification_payload.get("classified_alerts", [])),
        explained_alerts=len(explanation_payload.get("explained_alerts", [])),
        incident_count=int(grouping_payload.get("incident_count", 0)),
        grouped_alert_count=int(grouping_payload.get("grouped_alert_count", 0)),
        ungrouped_alert_count=int(grouping_payload.get("ungrouped_alert_count", 0)),
        highest_alert_severity=classification_payload.get("highest_severity"),
        highest_incident_severity=grouping_payload.get("highest_incident_severity"),
        severity_counts=dict(classification_payload.get("severity_counts", {})),
        tactics_observed=list(mitre_payload.get("tactics_observed", [])),
        techniques_observed=list(mitre_payload.get("techniques_observed", [])),
        safe_for_output=safe_for_output,
    )


def collect_errors(*payloads: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect structured errors from pipeline payloads in stable order."""
    errors: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for payload in payloads:
        for error in payload.get("errors", []):
            key = (
                str(error.get("file_path")),
                str(error.get("error_type")),
                str(error.get("message")),
            )
            if key in seen:
                continue
            seen.add(key)
            errors.append(error)
    return errors
