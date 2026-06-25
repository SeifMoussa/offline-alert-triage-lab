"""Models for deterministic incident grouping output."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from triage_lab.models.severity import Severity


class CorrelationReason(BaseModel):
    """Trace entry explaining why alerts were grouped."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    description: str
    matched_fields: list[str] = Field(default_factory=list)
    time_window_minutes: int
    contributing_alert_ids: list[str] = Field(default_factory=list)

    def to_safe_dict(self) -> dict[str, Any]:
        """Return CLI-safe correlation reason data."""
        return self.model_dump(mode="json")


class Incident(BaseModel):
    """A deterministic incident made from correlated synthetic alerts."""

    model_config = ConfigDict(frozen=True)

    incident_id: str
    title: str
    severity: Severity
    suggested_priority: str
    alert_ids: list[str] = Field(default_factory=list)
    event_types: list[str] = Field(default_factory=list)
    timeline_start: str
    timeline_end: str
    source_ips_redacted: list[str] = Field(default_factory=list)
    usernames_redacted: list[str] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    mitre_tactics_observed: list[str] = Field(default_factory=list)
    mitre_techniques_observed: list[str] = Field(default_factory=list)
    correlation_reasons: list[CorrelationReason] = Field(default_factory=list)
    member_count: int
    summary: str

    def to_safe_dict(self) -> dict[str, Any]:
        """Return CLI-safe incident details without raw alert messages."""
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "severity": self.severity.value,
            "suggested_priority": self.suggested_priority,
            "alert_ids": self.alert_ids,
            "event_types": self.event_types,
            "timeline_start": self.timeline_start,
            "timeline_end": self.timeline_end,
            "source_ips_redacted": self.source_ips_redacted,
            "usernames_redacted": self.usernames_redacted,
            "hostnames": self.hostnames,
            "mitre_tactics_observed": self.mitre_tactics_observed,
            "mitre_techniques_observed": self.mitre_techniques_observed,
            "correlation_reasons": [
                reason.to_safe_dict() for reason in self.correlation_reasons
            ],
            "member_count": self.member_count,
            "summary": self.summary,
        }


def priority_for_severity(severity: Severity) -> str:
    """Map severity to deterministic incident priority."""
    return {
        Severity.CRITICAL: "P1",
        Severity.HIGH: "P2",
        Severity.MEDIUM: "P3",
        Severity.LOW: "P4",
    }[severity]
