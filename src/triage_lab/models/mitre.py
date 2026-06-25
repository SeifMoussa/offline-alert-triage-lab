"""Models for local static MITRE ATT&CK mapping results."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class MitreTechnique(BaseModel):
    """A local static MITRE technique mapping."""

    model_config = ConfigDict(frozen=True)

    tactic: str
    technique_id: str | None
    technique_name: str
    mitre_url: str | None
    mapping_source: str
    confidence: str


class MitreMappingResult(BaseModel):
    """MITRE mapping result for one alert."""

    model_config = ConfigDict(frozen=True)

    alert_id: str
    event_type: str
    final_severity: str | None = None
    techniques: list[MitreTechnique] = Field(default_factory=list)
    mapping_found: bool
    fallback_used: bool
    reason: str

    def to_safe_dict(self) -> dict[str, Any]:
        """Return CLI-safe MITRE mapping output."""
        first = self.techniques[0] if self.techniques else None
        return {
            "alert_id": self.alert_id,
            "event_type": self.event_type,
            "final_severity": self.final_severity,
            "mitre_tactic": first.tactic if first else None,
            "mitre_technique_id": first.technique_id if first else None,
            "mitre_technique_name": first.technique_name if first else None,
            "mitre_url": first.mitre_url if first else None,
            "mapping_found": self.mapping_found,
            "fallback_used": self.fallback_used,
            "techniques": [
                technique.model_dump(mode="json") for technique in self.techniques
            ],
            "reason": self.reason,
        }
