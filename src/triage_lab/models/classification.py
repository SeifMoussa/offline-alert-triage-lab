"""Models for deterministic severity classification results."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from triage_lab.models.severity import Severity


class ModifierResult(BaseModel):
    """Trace entry for one modifier that changed severity."""

    model_config = ConfigDict(frozen=True)

    modifier_id: str
    description: str
    effect: str
    before_severity: Severity
    after_severity: Severity


class OverrideResult(BaseModel):
    """Trace entry for one override that set final severity."""

    model_config = ConfigDict(frozen=True)

    override_id: str
    description: str
    effect: str
    before_severity: Severity
    after_severity: Severity


class ClassificationResult(BaseModel):
    """Deterministic classification output for one alert."""

    model_config = ConfigDict(frozen=True)

    alert_id: str
    event_type: str
    base_severity: Severity
    final_severity: Severity
    severity_rank: int
    modifiers_applied: list[ModifierResult] = Field(default_factory=list)
    overrides_applied: list[OverrideResult] = Field(default_factory=list)
    reason: str
    trace: list[str] = Field(default_factory=list)

    def to_safe_dict(self) -> dict[str, Any]:
        """Return CLI-safe classification details."""
        return {
            "alert_id": self.alert_id,
            "event_type": self.event_type,
            "base_severity": self.base_severity.value,
            "final_severity": self.final_severity.value,
            "severity_rank": self.severity_rank,
            "modifiers_applied": [
                modifier.model_dump(mode="json") for modifier in self.modifiers_applied
            ],
            "overrides_applied": [
                override.model_dump(mode="json") for override in self.overrides_applied
            ],
            "reason": self.reason,
            "trace": self.trace,
        }
