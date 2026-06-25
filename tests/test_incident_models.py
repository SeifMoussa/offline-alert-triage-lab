from __future__ import annotations

from triage_lab.models.grouping import GroupingResult
from triage_lab.models.incident import (
    CorrelationReason,
    Incident,
    priority_for_severity,
)
from triage_lab.models.severity import Severity


def test_incident_model_creation_and_priority_mapping() -> None:
    reason = CorrelationReason(
        rule_id="same_username_within_60m",
        description="Grouped by synthetic username.",
        matched_fields=["username"],
        time_window_minutes=60,
        contributing_alert_ids=["alert-1", "alert-2"],
    )
    incident = Incident(
        incident_id="INC-0001",
        title="CRITICAL synthetic incident with 2 alerts",
        severity=Severity.CRITICAL,
        suggested_priority=priority_for_severity(Severity.CRITICAL),
        alert_ids=["alert-1", "alert-2"],
        event_types=["brute_force", "privilege_escalation"],
        timeline_start="2026-01-15T08:00:00+00:00",
        timeline_end="2026-01-15T08:10:00+00:00",
        source_ips_redacted=["[REDACTED:source_ip:1]"],
        usernames_redacted=["[REDACTED:username:1]"],
        hostnames=["server-01.test"],
        mitre_tactics_observed=["Credential Access"],
        mitre_techniques_observed=["T1110"],
        correlation_reasons=[reason],
        member_count=2,
        summary="CRITICAL synthetic incident.",
    )
    result = GroupingResult(
        incidents=[incident],
        ungrouped_alert_ids=[],
        incident_count=1,
        grouped_alert_count=2,
        ungrouped_alert_count=0,
        highest_incident_severity=Severity.CRITICAL,
    )

    payload = result.to_safe_dict()

    assert payload["highest_incident_severity"] == "CRITICAL"
    assert payload["incidents"][0]["suggested_priority"] == "P1"
    assert priority_for_severity(Severity.HIGH) == "P2"
    assert priority_for_severity(Severity.MEDIUM) == "P3"
    assert priority_for_severity(Severity.LOW) == "P4"
