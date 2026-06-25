"""Map validated alerts to local static MITRE ATT&CK entries."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from triage_lab.classification.engine import classify_alert
from triage_lab.classification.rules import RuleConfigError, load_rules
from triage_lab.ingestion.inventory import build_inventory
from triage_lab.mitre.loader import (
    MitreConfigError,
    MitreMappingConfig,
    load_mitre_mapping,
)
from triage_lab.models.alert import AlertRecord
from triage_lab.models.mitre import MitreMappingResult, MitreTechnique
from triage_lab.models.parse_error import ParseError

MITRE_BASE_URL = "https://attack.mitre.org/techniques"


def mitre_url_for_technique(technique_id: str | None) -> str | None:
    """Generate a static MITRE URL from a technique ID without network access."""
    if technique_id is None:
        return None
    parts = technique_id.split(".")
    if len(parts) == 1:
        return f"{MITRE_BASE_URL}/{parts[0]}/"
    return f"{MITRE_BASE_URL}/{parts[0]}/{parts[1]}/"


def map_alert_to_mitre(
    alert: AlertRecord,
    config: MitreMappingConfig,
    final_severity: str | None = None,
) -> MitreMappingResult:
    """Map one alert to local MITRE entries."""
    fallback_used = alert.event_type not in config.mappings
    entries = config.mappings.get(alert.event_type) or config.mappings["unknown"]
    techniques = [
        MitreTechnique(
            tactic=str(entry["tactic"]),
            technique_id=entry["technique_id"],
            technique_name=str(entry["technique_name"]),
            mitre_url=mitre_url_for_technique(entry["technique_id"]),
            mapping_source=f"{config.name}:v{config.version}",
            confidence=str(entry["confidence"]),
        )
        for entry in entries
    ]
    mapping_found = any(technique.technique_id is not None for technique in techniques)
    reason = _build_mapping_reason(alert.event_type, techniques, fallback_used)
    return MitreMappingResult(
        alert_id=alert.alert_id,
        event_type=alert.event_type,
        final_severity=final_severity,
        techniques=techniques,
        mapping_found=mapping_found,
        fallback_used=fallback_used or not mapping_found,
        reason=reason,
    )


def map_loaded_alerts_to_mitre(
    input_path: str | Path,
    mapping_config_path: str | Path | None = None,
) -> dict[str, Any]:
    """Load, classify, and map local alerts to local MITRE entries."""
    load_result = build_inventory(input_path)
    errors = list(load_result.errors)
    mapped: list[MitreMappingResult] = []
    mapping_config_name: str | None = None
    mapping_config_version: int | None = None

    try:
        mitre_config = load_mitre_mapping(mapping_config_path)
        ruleset = load_rules()
    except MitreConfigError as exc:
        errors.append(
            ParseError(
                file_path=str(mapping_config_path or "config/mitre_mapping.yaml"),
                message=str(exc),
                error_type="mitre_config_error",
            )
        )
    except RuleConfigError as exc:
        errors.append(
            ParseError(
                file_path="config/rules.yaml",
                message=str(exc),
                error_type="rules_config_error",
            )
        )
    else:
        mapping_config_name = mitre_config.name
        mapping_config_version = mitre_config.version
        for alert in load_result.alerts:
            classification = classify_alert(alert, ruleset)
            mapped.append(
                map_alert_to_mitre(
                    alert,
                    mitre_config,
                    final_severity=classification.final_severity.value,
                )
            )

    return {
        "input_path": str(input_path),
        "alerts_loaded": load_result.alerts_loaded,
        "malformed_records": load_result.malformed_records,
        "mapped_alerts": [result.to_safe_dict() for result in mapped],
        "mapping_counts": _mapping_counts(mapped),
        "tactics_observed": _sorted_unique_tactics(mapped),
        "techniques_observed": _sorted_unique_techniques(mapped),
        "mapping_config": {
            "name": mapping_config_name,
            "version": mapping_config_version,
        },
        "errors": [error.model_dump(mode="json") for error in errors],
    }


def mitre_mapping_is_success(payload: dict[str, Any]) -> bool:
    """Return true when MITRE mapping payload has no errors."""
    return not payload["errors"]


def _build_mapping_reason(
    event_type: str, techniques: list[MitreTechnique], fallback_used: bool
) -> str:
    if fallback_used:
        return f"Used local unknown fallback mapping for event type {event_type}."
    ids = [technique.technique_id for technique in techniques if technique.technique_id]
    if ids:
        joined_ids = ", ".join(ids)
        return (
            f"Mapped event type {event_type} to local MITRE technique(s): {joined_ids}."
        )
    return f"Event type {event_type} has no direct ATT&CK technique mapping."


def _mapping_counts(results: list[MitreMappingResult]) -> dict[str, int]:
    counts = Counter(
        "mapped" if result.mapping_found else "fallback" for result in results
    )
    return {"mapped": counts.get("mapped", 0), "fallback": counts.get("fallback", 0)}


def _sorted_unique_tactics(results: list[MitreMappingResult]) -> list[str]:
    return sorted(
        {technique.tactic for result in results for technique in result.techniques}
    )


def _sorted_unique_techniques(results: list[MitreMappingResult]) -> list[str]:
    return sorted(
        {
            technique.technique_id
            for result in results
            for technique in result.techniques
            if technique.technique_id is not None
        }
    )
