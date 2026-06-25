"""Models for deterministic analyst-style explanations."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from triage_lab.models.triage_step import TriageRecommendation


class AnalystExplanation(BaseModel):
    """Template-generated explanation for one synthetic alert."""

    model_config = ConfigDict(frozen=True)

    alert_id: str
    event_type: str
    final_severity: str
    summary: str
    reasoning: str
    evidence_points: list[str] = Field(default_factory=list)
    mitre_context: str
    modifiers_referenced: list[str] = Field(default_factory=list)
    template_id: str
    generated_by: str = "deterministic_template_engine"
    triage: TriageRecommendation

    def to_safe_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "event_type": self.event_type,
            "final_severity": self.final_severity,
            "mitre_technique_id": _first_technique_id(self.mitre_context),
            "mitre_tactic": _first_tactic(self.mitre_context),
            "summary": self.summary,
            "reasoning": self.reasoning,
            "evidence_points": self.evidence_points,
            "mitre_context": self.mitre_context,
            "modifiers_referenced": self.modifiers_referenced,
            "triage_steps": [step.to_safe_dict() for step in self.triage.steps],
            "suggested_priority": self.triage.suggested_priority,
            "escalation_required": self.triage.escalation_required,
            "template_id": self.template_id,
            "playbook_id": self.triage.playbook_id,
            "generated_by": self.generated_by,
        }


def _first_technique_id(context: str) -> str | None:
    marker = "technique "
    if marker not in context:
        return None
    value = context.split(marker, 1)[1].split(" ", 1)[0].strip(".")
    return value if value.startswith("T") else None


def _first_tactic(context: str) -> str | None:
    marker = " under "
    if marker not in context:
        return None
    return context.split(marker, 1)[1].split(".", 1)[0]
