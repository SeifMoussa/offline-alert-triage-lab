"""Models for deterministic grouping run results."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from triage_lab.models.incident import Incident
from triage_lab.models.severity import Severity


class GroupingResult(BaseModel):
    """Result of grouping classified and mapped synthetic alerts."""

    model_config = ConfigDict(frozen=True)

    incidents: list[Incident] = Field(default_factory=list)
    ungrouped_alert_ids: list[str] = Field(default_factory=list)
    incident_count: int
    grouped_alert_count: int
    ungrouped_alert_count: int
    highest_incident_severity: Severity | None = None
    errors: list[dict[str, Any]] = Field(default_factory=list)

    def to_safe_dict(self) -> dict[str, Any]:
        """Return CLI-safe grouping details."""
        return {
            "incidents": [incident.to_safe_dict() for incident in self.incidents],
            "ungrouped_alert_ids": self.ungrouped_alert_ids,
            "incident_count": self.incident_count,
            "grouped_alert_count": self.grouped_alert_count,
            "ungrouped_alert_count": self.ungrouped_alert_count,
            "highest_incident_severity": (
                self.highest_incident_severity.value
                if self.highest_incident_severity
                else None
            ),
            "errors": self.errors,
        }
