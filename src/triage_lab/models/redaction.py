"""Models for deterministic redaction and safe serialization."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RedactionSummary(BaseModel):
    """Counts of redaction actions without exposing sensitive values."""

    model_config = ConfigDict(frozen=True)

    fields_redacted: int = 0
    markers_redacted: int = 0
    ip_values_redacted: int = 0
    usernames_redacted: int = 0
    credential_patterns_redacted: int = 0
    raw_messages_removed: int = 0
    redaction_applied: bool = False
    redaction_policy: str = "default-report-safe-v1"


class RedactionResult(BaseModel):
    """Redacted payload plus structured safety validation metadata."""

    model_config = ConfigDict(frozen=True)

    payload: Any
    summary: RedactionSummary
    safe_for_output: bool
    validation_errors: list[dict[str, Any]] = Field(default_factory=list)
