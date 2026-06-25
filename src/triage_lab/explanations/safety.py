"""Safety helpers for deterministic explanation output."""

from __future__ import annotations

import re

from triage_lab.ingestion.validators import redact_sensitive_text

UNFILLED_PLACEHOLDER_PATTERN = re.compile(r"{[a-zA-Z0-9_]+}")


def sanitize_explanation_text(value: str) -> str:
    """Mask sensitive-looking values in generated explanation text."""
    return redact_sensitive_text(value)


def assert_no_unfilled_placeholders(value: str) -> None:
    """Fail clearly if a deterministic template has missing values."""
    if UNFILLED_PLACEHOLDER_PATTERN.search(value):
        raise ValueError("explanation contains unfilled template placeholders")
