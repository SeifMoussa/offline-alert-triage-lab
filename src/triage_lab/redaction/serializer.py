"""Safe serialization helpers for CLI and future reports."""

from __future__ import annotations

from typing import Any

from triage_lab.models.redaction import RedactionResult
from triage_lab.redaction.engine import redact_payload
from triage_lab.redaction.policies import DEFAULT_REDACTION_POLICY, RedactionPolicy


def serialize_for_output(
    payload: Any,
    policy: RedactionPolicy = DEFAULT_REDACTION_POLICY,
) -> RedactionResult:
    """Return a redacted payload plus validation metadata."""
    return redact_payload(payload, policy)


def safe_payload(
    payload: Any,
    policy: RedactionPolicy = DEFAULT_REDACTION_POLICY,
) -> Any:
    """Return only the redacted payload for existing CLI payload shapes."""
    return serialize_for_output(payload, policy).payload
