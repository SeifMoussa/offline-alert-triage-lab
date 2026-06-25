"""Models for deterministic defensive triage recommendations."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class TriageStep(BaseModel):
    """One defensive triage step selected from local playbooks."""

    model_config = ConfigDict(frozen=True)

    step_id: str
    title: str
    description: str
    safety_note: str
    order: int

    def to_safe_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class TriageRecommendation(BaseModel):
    """Triage recommendation for one alert."""

    model_config = ConfigDict(frozen=True)

    alert_id: str
    event_type: str
    severity: str
    steps: list[TriageStep] = Field(default_factory=list)
    escalation_required: bool
    suggested_priority: str
    playbook_id: str
    playbook_source: str

    def to_safe_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "event_type": self.event_type,
            "severity": self.severity,
            "steps": [step.to_safe_dict() for step in self.steps],
            "escalation_required": self.escalation_required,
            "suggested_priority": self.suggested_priority,
            "playbook_id": self.playbook_id,
            "playbook_source": self.playbook_source,
        }
