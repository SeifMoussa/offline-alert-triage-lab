"""Models for local multi-run trend analytics."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RunSnapshot(BaseModel):
    """One local triage run's summary data used for trend aggregation."""

    model_config = ConfigDict(frozen=True)

    run_id: str
    generated_at: str
    alerts_loaded: int
    incident_count: int
    severity_counts: dict[str, int] = Field(default_factory=dict)
    techniques_observed: list[str] = Field(default_factory=list)
    safe_for_output: bool
    true_positive_count: int = 0
    false_positive_count: int = 0
    unreviewed_count: int = 0
    outcomes_available: bool = False
    false_positive_rate: float | None = None

    def to_safe_dict(self) -> dict[str, Any]:
        """Return safe run snapshot data for CLI and report output."""
        return self.model_dump(mode="json")
