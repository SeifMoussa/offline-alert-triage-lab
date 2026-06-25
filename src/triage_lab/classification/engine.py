"""Deterministic severity classification engine."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any

from triage_lab.classification.rules import RuleConfigError, RuleSet, load_rules
from triage_lab.ingestion.inventory import build_inventory
from triage_lab.models.alert import AlertRecord
from triage_lab.models.classification import (
    ClassificationResult,
    ModifierResult,
    OverrideResult,
)
from triage_lab.models.parse_error import ParseError
from triage_lab.models.severity import Severity, highest_severity


def classify_alert(alert: AlertRecord, ruleset: RuleSet) -> ClassificationResult:
    """Classify one alert using deterministic local rules."""
    base = ruleset.base_severity.get(alert.event_type, ruleset.default_severity)
    current = base
    modifiers: list[ModifierResult] = []
    overrides: list[OverrideResult] = []
    trace = [
        f"ruleset={ruleset.name} version={ruleset.version}",
        f"base_severity={base.value} event_type={alert.event_type}",
    ]

    for rule in ruleset.modifier_rules:
        if not _condition_matches(alert, rule.get("condition"), ruleset):
            continue
        before = current
        current = current.raise_by(int(rule.get("severity_delta", 0)))
        modifier = ModifierResult(
            modifier_id=str(rule["id"]),
            description=str(rule["description"]),
            effect=f"raise_by_{int(rule.get('severity_delta', 0))}",
            before_severity=before,
            after_severity=current,
        )
        modifiers.append(modifier)
        trace.append(
            f"modifier={modifier.modifier_id} "
            f"before={before.value} after={current.value}"
        )

    for rule in ruleset.override_rules:
        if not _condition_matches(alert, rule.get("condition"), ruleset):
            continue
        before = current
        current = Severity(str(rule["severity"]))
        override = OverrideResult(
            override_id=str(rule["id"]),
            description=str(rule["description"]),
            effect=f"override_to_{current.value}",
            before_severity=before,
            after_severity=current,
        )
        overrides.append(override)
        trace.append(
            f"override={override.override_id} "
            f"before={before.value} after={current.value}"
        )

    reason = _build_reason(base, current, modifiers, overrides)
    return ClassificationResult(
        alert_id=alert.alert_id,
        event_type=alert.event_type,
        base_severity=base,
        final_severity=current,
        severity_rank=current.rank,
        modifiers_applied=modifiers,
        overrides_applied=overrides,
        reason=reason,
        trace=trace,
    )


def classify_loaded_alerts(
    input_path: str | Path, config_path: str | Path | None = None
) -> dict[str, Any]:
    """Load, validate, and classify alerts for safe CLI output."""
    load_result = build_inventory(input_path)
    errors = list(load_result.errors)
    classified: list[ClassificationResult] = []
    ruleset_name: str | None = None
    ruleset_version: int | None = None

    try:
        ruleset = load_rules(config_path)
    except RuleConfigError as exc:
        errors.append(
            ParseError(
                file_path=str(config_path or "config/rules.yaml"),
                message=str(exc),
                error_type="rules_config_error",
            )
        )
    else:
        ruleset_name = ruleset.name
        ruleset_version = ruleset.version
        classified = [classify_alert(alert, ruleset) for alert in load_result.alerts]

    severities = [result.final_severity for result in classified]
    return {
        "input_path": str(input_path),
        "alerts_loaded": load_result.alerts_loaded,
        "malformed_records": load_result.malformed_records,
        "classified_alerts": [result.to_safe_dict() for result in classified],
        "severity_counts": _severity_counts(severities),
        "highest_severity": (
            highest.value if (highest := highest_severity(severities)) else None
        ),
        "ruleset": {"name": ruleset_name, "version": ruleset_version},
        "errors": [error.model_dump(mode="json") for error in errors],
    }


def classify_result_is_success(payload: dict[str, Any]) -> bool:
    """Return true when classification payload has no errors."""
    return not payload["errors"]


def _severity_counts(values: list[Severity]) -> dict[str, int]:
    counts = Counter(severity.value for severity in values)
    return {severity.value: counts.get(severity.value, 0) for severity in Severity}


def _condition_matches(alert: AlertRecord, condition: object, ruleset: RuleSet) -> bool:
    if not isinstance(condition, dict):
        return False
    field = str(condition.get("field"))
    operator = str(condition.get("operator"))
    value = getattr(alert, field, None)

    if operator == "greater_than_or_equal":
        return value is not None and value >= condition.get("value")
    if operator == "in_config_list":
        config_values = getattr(ruleset, str(condition.get("config_key")), ())
        return value in config_values
    if operator == "contains":
        return isinstance(value, list) and condition.get("value") in value
    if operator == "regex_from_config":
        if not isinstance(value, str):
            return False
        patterns = getattr(ruleset, str(condition.get("config_key")), ())
        return any(
            re.search(pattern["pattern"], value) is not None
            for pattern in patterns
            if "pattern" in pattern
        )
    return False


def _build_reason(
    base: Severity,
    final: Severity,
    modifiers: list[ModifierResult],
    overrides: list[OverrideResult],
) -> str:
    parts = [f"Base severity {base.value} was selected from the event type."]
    if modifiers:
        parts.append(
            "Applied modifiers: "
            + ", ".join(modifier.modifier_id for modifier in modifiers)
            + "."
        )
    if overrides:
        parts.append(
            "Applied overrides: "
            + ", ".join(override.override_id for override in overrides)
            + "."
        )
    parts.append(f"Final severity is {final.value}.")
    return " ".join(parts)
