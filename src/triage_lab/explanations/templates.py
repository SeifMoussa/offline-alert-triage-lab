"""Deterministic explanation templates."""

from __future__ import annotations

DEFAULT_TEMPLATE_ID = "TPL-GENERIC"

EVENT_TEMPLATES: dict[str, dict[str, str]] = {
    "brute_force": {
        "template_id": "TPL-BRUTE-FORCE",
        "summary": (
            "Repeated authentication failures were detected in the synthetic "
            "dataset for a lab account and host."
        ),
        "reasoning": (
            "The final severity is {severity}. The classifier started from the "
            "configured base severity for {event_type} and applied {modifier_text}. "
            "{mitre_sentence}"
        ),
    },
    "port_scan": {
        "template_id": "TPL-PORT-SCAN",
        "summary": (
            "Multiple connection attempts suggest reconnaissance behavior in "
            "the synthetic dataset."
        ),
        "reasoning": (
            "The final severity is {severity}. The decision reflects the local "
            "base severity and {modifier_text}. {mitre_sentence}"
        ),
    },
    "unknown": {
        "template_id": "TPL-UNKNOWN",
        "summary": (
            "The alert uses an unknown synthetic event type and should be "
            "preserved for analyst review."
        ),
        "reasoning": (
            "The final severity is {severity}. The classifier used configured "
            "fallback behavior and {modifier_text}. {mitre_sentence}"
        ),
    },
}

GENERIC_TEMPLATE = {
    "template_id": DEFAULT_TEMPLATE_ID,
    "summary": (
        "A synthetic {event_type} alert was reviewed by the deterministic "
        "triage pipeline."
    ),
    "reasoning": (
        "The final severity is {severity}. The classifier used the local base "
        "severity for {event_type} and applied {modifier_text}. {mitre_sentence}"
    ),
}


def template_for_event(event_type: str) -> dict[str, str]:
    """Return a deterministic template for an event type."""
    return EVENT_TEMPLATES.get(event_type, GENERIC_TEMPLATE)
