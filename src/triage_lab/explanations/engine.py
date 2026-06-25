"""Deterministic analyst-style explanation generation."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from triage_lab.classification.engine import classify_alert
from triage_lab.classification.rules import RuleConfigError, load_rules
from triage_lab.explanations.safety import (
    assert_no_unfilled_placeholders,
    sanitize_explanation_text,
)
from triage_lab.explanations.templates import template_for_event
from triage_lab.ingestion.inventory import build_inventory
from triage_lab.mitre.loader import MitreConfigError, load_mitre_mapping
from triage_lab.mitre.mapping import map_alert_to_mitre
from triage_lab.models.alert import AlertRecord
from triage_lab.models.classification import ClassificationResult
from triage_lab.models.explanation import AnalystExplanation
from triage_lab.models.mitre import MitreMappingResult
from triage_lab.models.parse_error import ParseError
from triage_lab.triage.playbooks import PlaybookConfigError, load_playbooks
from triage_lab.triage.selector import select_triage_recommendation


def generate_explanation(
    alert: AlertRecord,
    classification: ClassificationResult,
    mitre_mapping: MitreMappingResult,
    playbook_config,
) -> AnalystExplanation:
    """Generate one deterministic analyst explanation."""
    template = template_for_event(alert.event_type)
    modifiers = [item.modifier_id for item in classification.modifiers_applied]
    modifier_text = (
        "modifier(s) " + ", ".join(modifiers) if modifiers else "no severity modifiers"
    )
    mitre_sentence = _mitre_sentence(mitre_mapping)
    summary = template["summary"].format(
        event_type=alert.event_type,
        severity=classification.final_severity.value,
    )
    reasoning = template["reasoning"].format(
        event_type=alert.event_type,
        severity=classification.final_severity.value,
        modifier_text=modifier_text,
        mitre_sentence=mitre_sentence,
    )
    evidence_points = _evidence_points(alert, classification, mitre_mapping)
    triage = select_triage_recommendation(alert, classification, playbook_config)
    text_values = [summary, reasoning, *evidence_points, mitre_sentence]
    for value in text_values:
        assert_no_unfilled_placeholders(value)
    return AnalystExplanation(
        alert_id=alert.alert_id,
        event_type=alert.event_type,
        final_severity=classification.final_severity.value,
        summary=sanitize_explanation_text(summary),
        reasoning=sanitize_explanation_text(reasoning),
        evidence_points=[sanitize_explanation_text(item) for item in evidence_points],
        mitre_context=sanitize_explanation_text(mitre_sentence),
        modifiers_referenced=modifiers,
        template_id=template["template_id"],
        triage=triage,
    )


def explain_loaded_alerts(
    input_path: str | Path,
    rules_config_path: str | Path | None = None,
    mitre_config_path: str | Path | None = None,
    triage_config_path: str | Path | None = None,
) -> dict[str, Any]:
    """Run ingest -> classify -> MITRE map -> explain -> triage."""
    load_result = build_inventory(input_path)
    errors = list(load_result.errors)
    explained: list[AnalystExplanation] = []

    try:
        ruleset = load_rules(rules_config_path)
        mitre_config = load_mitre_mapping(mitre_config_path)
        playbook_config = load_playbooks(triage_config_path)
    except RuleConfigError as exc:
        errors.append(
            _config_error("config/rules.yaml", str(exc), "rules_config_error")
        )
    except MitreConfigError as exc:
        errors.append(
            _config_error(
                str(mitre_config_path or "config/mitre_mapping.yaml"),
                str(exc),
                "mitre_config_error",
            )
        )
    except PlaybookConfigError as exc:
        errors.append(
            _config_error(
                str(triage_config_path or "config/triage_steps.yaml"),
                str(exc),
                "playbook_config_error",
            )
        )
    else:
        for alert in load_result.alerts:
            classification = classify_alert(alert, ruleset)
            mitre_mapping = map_alert_to_mitre(
                alert,
                mitre_config,
                final_severity=classification.final_severity.value,
            )
            explained.append(
                generate_explanation(
                    alert, classification, mitre_mapping, playbook_config
                )
            )

    return {
        "input_path": str(input_path),
        "alerts_loaded": load_result.alerts_loaded,
        "malformed_records": load_result.malformed_records,
        "explained_alerts": [item.to_safe_dict() for item in explained],
        "severity_counts": _severity_counts(explained),
        "tactics_observed": _tactics_observed(explained),
        "errors": [error.model_dump(mode="json") for error in errors],
    }


def explanation_result_is_success(payload: dict[str, Any]) -> bool:
    """Return true when explanation payload has no errors."""
    return not payload["errors"]


def _mitre_sentence(mitre_mapping: MitreMappingResult) -> str:
    first = mitre_mapping.techniques[0] if mitre_mapping.techniques else None
    if first is None or first.technique_id is None:
        return "No direct MITRE ATT&CK technique mapping is configured."
    return (
        f"This maps to MITRE ATT&CK technique {first.technique_id} "
        f"{first.technique_name} under {first.tactic}."
    )


def _evidence_points(
    alert: AlertRecord,
    classification: ClassificationResult,
    mitre_mapping: MitreMappingResult,
) -> list[str]:
    modifiers = [item.modifier_id for item in classification.modifiers_applied]
    points = [
        f"Alert {alert.alert_id} is a synthetic {alert.event_type} event.",
        f"Final severity is {classification.final_severity.value}.",
    ]
    if modifiers:
        points.append("Triggered modifier IDs: " + ", ".join(modifiers) + ".")
    if mitre_mapping.mapping_found:
        ids = [
            item.technique_id
            for item in mitre_mapping.techniques
            if item.technique_id is not None
        ]
        points.append("Mapped MITRE technique IDs: " + ", ".join(ids) + ".")
    else:
        points.append("No direct MITRE technique mapping was configured.")
    return points


def _severity_counts(items: list[AnalystExplanation]) -> dict[str, int]:
    counts = Counter(item.final_severity for item in items)
    return {
        "LOW": counts.get("LOW", 0),
        "MEDIUM": counts.get("MEDIUM", 0),
        "HIGH": counts.get("HIGH", 0),
        "CRITICAL": counts.get("CRITICAL", 0),
    }


def _tactics_observed(items: list[AnalystExplanation]) -> list[str]:
    tactics = []
    marker = " under "
    for item in items:
        if marker in item.mitre_context:
            tactics.append(item.mitre_context.split(marker, 1)[1].rstrip("."))
    return sorted(set(tactics))


def _config_error(file_path: str, message: str, error_type: str) -> ParseError:
    return ParseError(file_path=file_path, message=message, error_type=error_type)
