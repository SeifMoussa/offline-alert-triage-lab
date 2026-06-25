"""Local YAML rules loading for deterministic severity classification."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from triage_lab.ingestion.validators import validate_local_input_path
from triage_lab.models.severity import Severity


class RuleConfigError(ValueError):
    """Raised when the local rules configuration is invalid or unsafe."""


DEFAULT_RULES_PATH = Path(__file__).resolve().parents[3] / "config" / "rules.yaml"
REQUIRED_EVENT_TYPES = {
    "failed_login",
    "brute_force",
    "port_scan",
    "privilege_escalation",
    "data_exfiltration",
    "lateral_movement",
    "malware_detected",
    "c2_beacon",
    "policy_violation",
    "anomalous_login_time",
    "unknown",
}


@dataclass(frozen=True)
class RuleSet:
    """Validated local classification rule configuration."""

    name: str
    version: int
    default_severity: Severity
    base_severity: dict[str, Severity]
    sensitive_destination_ports: tuple[int, ...]
    privileged_usernames: tuple[str, ...]
    known_synthetic_bad_ips: tuple[str, ...]
    synthetic_marker_patterns: tuple[dict[str, str], ...]
    modifier_rules: tuple[dict[str, Any], ...]
    override_rules: tuple[dict[str, Any], ...]


def load_rules(config_path: str | Path | None = None) -> RuleSet:
    """Load and validate local YAML rules."""
    path = (
        DEFAULT_RULES_PATH
        if config_path is None
        else _validate_config_path(config_path)
    )
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuleConfigError(f"unable to read rules config: {exc}") from exc
    except yaml.YAMLError as exc:
        raise RuleConfigError(f"invalid YAML rules config: {exc}") from exc

    if not isinstance(raw, dict):
        raise RuleConfigError("rules config must be a YAML mapping")
    return _parse_rules(raw)


def _validate_config_path(config_path: str | Path) -> Path:
    try:
        path = validate_local_input_path(str(config_path))
    except ValueError as exc:
        raise RuleConfigError(str(exc)) from exc
    if path.suffix.lower() not in {".yaml", ".yml"}:
        raise RuleConfigError("rules config must be a local YAML file")
    return path


def _parse_rules(raw: dict[str, Any]) -> RuleSet:
    _validate_safety(raw.get("safety"))
    base_severity = _parse_base_severity(raw.get("base_severity"))
    missing = REQUIRED_EVENT_TYPES - set(base_severity)
    if missing:
        raise RuleConfigError(f"base_severity missing event types: {sorted(missing)}")

    severity_levels = raw.get("severity_levels")
    if severity_levels != [severity.value for severity in Severity]:
        raise RuleConfigError("severity_levels must be LOW, MEDIUM, HIGH, CRITICAL")

    default_severity = _parse_severity(raw.get("default_severity"), "default_severity")
    modifier_rules = _require_list(raw, "modifier_rules")
    override_rules = _require_list(raw, "override_rules")

    return RuleSet(
        name=_require_str(raw, "name"),
        version=_require_int(raw, "version"),
        default_severity=default_severity,
        base_severity=base_severity,
        sensitive_destination_ports=tuple(
            _require_int_items(raw, "sensitive_destination_ports")
        ),
        privileged_usernames=tuple(_require_str_items(raw, "privileged_usernames")),
        known_synthetic_bad_ips=tuple(
            _require_str_items(raw, "known_synthetic_bad_ips")
        ),
        synthetic_marker_patterns=tuple(
            _require_marker_patterns(raw.get("synthetic_marker_patterns"))
        ),
        modifier_rules=tuple(modifier_rules),
        override_rules=tuple(override_rules),
    )


def _validate_safety(value: object) -> None:
    if not isinstance(value, dict):
        raise RuleConfigError("safety must be configured")
    required_false = ("network_calls", "external_ai", "external_threat_intelligence")
    if (
        value.get("offline_only") is not True
        or value.get("synthetic_data_only") is not True
    ):
        raise RuleConfigError(
            "rules config must be offline-only and synthetic-data only"
        )
    for key in required_false:
        if value.get(key) is not False:
            raise RuleConfigError(f"rules config must set {key}: false")


def _parse_base_severity(value: object) -> dict[str, Severity]:
    if not isinstance(value, dict):
        raise RuleConfigError("base_severity must be a mapping")
    return {
        str(event_type): _parse_severity(severity, f"base_severity.{event_type}")
        for event_type, severity in value.items()
    }


def _parse_severity(value: object, field_name: str) -> Severity:
    try:
        return Severity(str(value))
    except ValueError as exc:
        raise RuleConfigError(
            f"{field_name} has unsupported severity: {value}"
        ) from exc


def _require_str(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise RuleConfigError(f"{key} must be a non-empty string")
    return value


def _require_int(raw: dict[str, Any], key: str) -> int:
    value = raw.get(key)
    if not isinstance(value, int):
        raise RuleConfigError(f"{key} must be an integer")
    return value


def _require_list(raw: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = raw.get(key)
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise RuleConfigError(f"{key} must be a list of mappings")
    return value


def _require_int_items(raw: dict[str, Any], key: str) -> list[int]:
    value = raw.get(key)
    if not isinstance(value, list) or not all(isinstance(item, int) for item in value):
        raise RuleConfigError(f"{key} must be a list of integers")
    return value


def _require_str_items(raw: dict[str, Any], key: str) -> list[str]:
    value = raw.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise RuleConfigError(f"{key} must be a list of strings")
    return value


def _require_marker_patterns(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise RuleConfigError("synthetic_marker_patterns must be a list")
    patterns: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, dict) or not isinstance(item.get("pattern"), str):
            raise RuleConfigError("synthetic_marker_patterns entries need pattern")
        patterns.append({"name": str(item.get("name", "")), "pattern": item["pattern"]})
    return patterns
