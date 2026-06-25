"""Models for deterministic JSON and Markdown security reports."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from triage_lab.models.redaction import RedactionSummary


class ReportMetadata(BaseModel):
    """Static metadata describing report safety and generation mode."""

    model_config = ConfigDict(frozen=True)

    generated_at: str
    project_name: str
    report_type: str
    input_path: str
    synthetic_data_only: bool
    offline_only: bool
    deterministic_ai: bool
    redaction_policy: str
    tool_version: str


class ReportSummary(BaseModel):
    """Aggregate report counts and observed local mapping context."""

    model_config = ConfigDict(frozen=True)

    alerts_loaded: int
    malformed_records: int
    classified_alerts: int
    explained_alerts: int
    incident_count: int
    grouped_alert_count: int
    ungrouped_alert_count: int
    highest_alert_severity: str | None = None
    highest_incident_severity: str | None = None
    severity_counts: dict[str, int] = Field(default_factory=dict)
    tactics_observed: list[str] = Field(default_factory=list)
    techniques_observed: list[str] = Field(default_factory=list)
    safe_for_output: bool


class SecurityReport(BaseModel):
    """Final report object used by JSON and Markdown renderers."""

    model_config = ConfigDict(frozen=True)

    metadata: ReportMetadata
    summary: ReportSummary
    incidents: list[dict[str, Any]] = Field(default_factory=list)
    explained_alerts: list[dict[str, Any]] = Field(default_factory=list)
    redaction_summary: RedactionSummary
    validation_errors: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[dict[str, Any]] = Field(default_factory=list)

    def to_safe_dict(self) -> dict[str, Any]:
        """Return report data for deterministic rendering."""
        payload = self.model_dump(mode="json")
        redaction = dict(payload["redaction_summary"])
        redaction["raw_content_removed"] = redaction.pop("raw_messages_removed")
        payload["redaction_summary"] = redaction
        return payload
