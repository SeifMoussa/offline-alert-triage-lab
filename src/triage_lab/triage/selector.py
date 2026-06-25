"""Select deterministic defensive triage recommendations."""

from __future__ import annotations

from pathlib import Path

from triage_lab.models.alert import AlertRecord
from triage_lab.models.classification import ClassificationResult
from triage_lab.models.triage_step import TriageRecommendation, TriageStep
from triage_lab.triage.playbooks import PlaybookConfig, load_playbooks


def select_triage_recommendation(
    alert: AlertRecord,
    classification: ClassificationResult,
    playbooks: PlaybookConfig,
) -> TriageRecommendation:
    """Select event/severity-specific steps with event and global fallbacks."""
    exact = _matching_steps(
        playbooks,
        event_type=alert.event_type,
        severity=classification.final_severity.value,
    )
    event_fallback = _matching_steps(playbooks, event_type=alert.event_type)
    global_fallback = _global_fallback_steps(playbooks)
    selected = exact or event_fallback or global_fallback
    selected_steps = [
        TriageStep(
            step_id=step["id"],
            title=step["title"],
            description=step["description"],
            safety_note=step["safety_note"],
            order=step["order"],
        )
        for step in selected
    ]
    severity = classification.final_severity.value
    playbook_id = selected_steps[0].step_id if selected_steps else "NO_PLAYBOOK"
    return TriageRecommendation(
        alert_id=alert.alert_id,
        event_type=alert.event_type,
        severity=severity,
        steps=selected_steps,
        escalation_required=severity in {"HIGH", "CRITICAL"},
        suggested_priority=_priority_for_severity(severity),
        playbook_id=playbook_id,
        playbook_source=f"{playbooks.name}:v{playbooks.version}",
    )


def select_loaded_playbooks(config_path: str | Path | None = None) -> PlaybookConfig:
    """Load playbooks for selection."""
    return load_playbooks(config_path)


def _matching_steps(
    playbooks: PlaybookConfig,
    *,
    event_type: str,
    severity: str | None = None,
) -> list[dict]:
    steps = []
    for step in playbooks.steps:
        if step["id"] == "TRIAGE-GLOBAL-FALLBACK":
            continue
        if event_type not in step["applies_to_event_types"]:
            continue
        if severity is not None and severity not in step["applies_to_severities"]:
            continue
        steps.append(step)
    return sorted(steps, key=lambda step: (step["order"], step["id"]))


def _global_fallback_steps(playbooks: PlaybookConfig) -> list[dict]:
    return sorted(
        [step for step in playbooks.steps if step["id"] == "TRIAGE-GLOBAL-FALLBACK"],
        key=lambda step: (step["order"], step["id"]),
    )


def _priority_for_severity(severity: str) -> str:
    return {
        "LOW": "routine",
        "MEDIUM": "standard",
        "HIGH": "urgent",
        "CRITICAL": "immediate",
    }.get(severity, "standard")
