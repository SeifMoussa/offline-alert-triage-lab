"""Load deterministic local incident grouping rules."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from triage_lab.ingestion.validators import validate_local_input_path
from triage_lab.models.severity import Severity


class GroupingConfigError(ValueError):
    """Raised when local grouping config is invalid or unsafe."""


DEFAULT_GROUPING_RULES_PATH = (
    Path(__file__).resolve().parents[3] / "config" / "grouping_rules.yaml"
)

VALID_MATCH_TYPES = {
    "same_field_time_window",
    "same_field_with_severity",
    "same_mitre_tactic_time_window",
    "event_chain",
    "multi_stage_same_host",
}


@dataclass(frozen=True)
class GroupingConfig:
    """Validated grouping config."""

    name: str
    version: int
    rules: tuple[dict[str, Any], ...]


def load_grouping_config(config_path: str | Path | None = None) -> GroupingConfig:
    """Load local deterministic grouping rules from YAML."""
    path = (
        DEFAULT_GROUPING_RULES_PATH
        if config_path is None
        else _validate_config_path(config_path)
    )
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise GroupingConfigError(f"unable to read grouping config: {exc}") from exc
    except yaml.YAMLError as exc:
        raise GroupingConfigError(f"invalid grouping YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise GroupingConfigError("grouping config must be a YAML mapping")
    return _parse_config(raw)


def _validate_config_path(config_path: str | Path) -> Path:
    try:
        path = validate_local_input_path(str(config_path))
    except ValueError as exc:
        raise GroupingConfigError(str(exc)) from exc
    if path.suffix.lower() not in {".yaml", ".yml"}:
        raise GroupingConfigError("grouping config must be a local YAML file")
    return path


def _parse_config(raw: dict[str, Any]) -> GroupingConfig:
    _validate_safety(raw.get("safety"))
    rules = raw.get("rules")
    if not isinstance(rules, list) or not rules:
        raise GroupingConfigError("rules must be a non-empty list")
    normalized = tuple(_parse_rule(rule) for rule in rules)
    return GroupingConfig(
        name=_optional_name(raw),
        version=_require_int(raw, "version"),
        rules=normalized,
    )


def _validate_safety(value: object) -> None:
    if not isinstance(value, dict):
        raise GroupingConfigError("safety must be configured")
    if (
        value.get("offline_only") is not True
        or value.get("synthetic_data_only") is not True
    ):
        raise GroupingConfigError(
            "grouping config must be offline-only and synthetic-data only"
        )
    for key in ("network_calls", "external_ai", "external_threat_intelligence"):
        if value.get(key) is not False:
            raise GroupingConfigError(f"grouping config must set {key}: false")


def _parse_rule(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GroupingConfigError("each grouping rule must be a mapping")
    match_type = _entry_str(value, "match_type")
    if match_type not in VALID_MATCH_TYPES:
        raise GroupingConfigError(f"unsupported grouping match_type: {match_type}")
    rule = {
        "id": _entry_str(value, "id"),
        "description": _entry_str(value, "description"),
        "enabled": _entry_bool(value, "enabled"),
        "match_type": match_type,
        "time_window_minutes": _entry_int(value, "time_window_minutes"),
        "minimum_alerts": _entry_int(value, "minimum_alerts"),
    }
    for key in (
        "field",
        "required_severity",
        "minimum_distinct_event_types",
        "precursor_event_types",
        "followup_event_types",
        "match_fields",
    ):
        if key in value:
            rule[key] = _normalize_optional(value, key)
    if "required_severity" in rule:
        try:
            Severity(str(rule["required_severity"]))
        except ValueError as exc:
            raise GroupingConfigError("required_severity is invalid") from exc
    return rule


def _normalize_optional(raw: dict[str, Any], key: str) -> str | int | list[str]:
    value = raw[key]
    if isinstance(value, str | int):
        return value
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    raise GroupingConfigError(f"rule {key} has an invalid value")


def _optional_name(raw: dict[str, Any]) -> str:
    value = raw.get("name", "offline-alert-triage-grouping-rules")
    if not isinstance(value, str) or not value:
        raise GroupingConfigError("name must be a non-empty string")
    return value


def _require_int(raw: dict[str, Any], key: str) -> int:
    value = raw.get(key)
    if not isinstance(value, int):
        raise GroupingConfigError(f"{key} must be an integer")
    return value


def _entry_str(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise GroupingConfigError(f"rule {key} must be a non-empty string")
    return value


def _entry_int(raw: dict[str, Any], key: str) -> int:
    value = raw.get(key)
    if not isinstance(value, int) or value < 0:
        raise GroupingConfigError(f"rule {key} must be a non-negative integer")
    return value


def _entry_bool(raw: dict[str, Any], key: str) -> bool:
    value = raw.get(key)
    if not isinstance(value, bool):
        raise GroupingConfigError(f"rule {key} must be a boolean")
    return value
