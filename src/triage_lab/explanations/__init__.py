"""Deterministic template-driven explanations."""

from triage_lab.explanations.engine import (
    explain_loaded_alerts,
    explanation_result_is_success,
    generate_explanation,
)

__all__ = [
    "explain_loaded_alerts",
    "explanation_result_is_success",
    "generate_explanation",
]
