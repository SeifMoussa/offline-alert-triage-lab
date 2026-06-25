"""Load local static MITRE mapping configuration."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from triage_lab.ingestion.validators import validate_local_input_path


class MitreConfigError(ValueError):
    """Raised when local MITRE mapping config is invalid or unsafe."""


DEFAULT_MITRE_MAPPING_PATH = (
    Path(__file__).resolve().parents[3] / "config" / "mitre_mapping.yaml"
)
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
class MitreMappingConfig:
    """Validated local MITRE mapping configuration."""

    name: str
    version: int
    mappings: dict[str, tuple[dict[str, Any], ...]]


def load_mitre_mapping(config_path: str | Path | None = None) -> MitreMappingConfig:
    """Load local static MITRE mapping YAML."""
    path = (
        DEFAULT_MITRE_MAPPING_PATH
        if config_path is None
        else _validate_config_path(config_path)
    )
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise MitreConfigError(f"unable to read MITRE mapping config: {exc}") from exc
    except yaml.YAMLError as exc:
        raise MitreConfigError(f"invalid MITRE mapping YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise MitreConfigError("MITRE mapping config must be a YAML mapping")
    return _parse_mapping(raw)


def _validate_config_path(config_path: str | Path) -> Path:
    try:
        path = validate_local_input_path(str(config_path))
    except ValueError as exc:
        raise MitreConfigError(str(exc)) from exc
    if path.suffix.lower() not in {".yaml", ".yml"}:
        raise MitreConfigError("MITRE mapping config must be a local YAML file")
    return path


def _parse_mapping(raw: dict[str, Any]) -> MitreMappingConfig:
    _validate_safety(raw.get("safety"))
    mappings = raw.get("mappings")
    if not isinstance(mappings, dict):
        raise MitreConfigError("mappings must be a mapping")

    normalized = {
        str(event_type): tuple(_normalize_entries(event_type, entries))
        for event_type, entries in mappings.items()
    }
    missing = REQUIRED_EVENT_TYPES - set(normalized)
    if missing:
        raise MitreConfigError(f"mappings missing event types: {sorted(missing)}")

    return MitreMappingConfig(
        name=_require_str(raw, "name"),
        version=_require_int(raw, "version"),
        mappings=normalized,
    )


def _validate_safety(value: object) -> None:
    if not isinstance(value, dict):
        raise MitreConfigError("safety must be configured")
    if (
        value.get("offline_only") is not True
        or value.get("synthetic_data_only") is not True
    ):
        raise MitreConfigError(
            "MITRE mapping config must be offline-only and synthetic-data only"
        )
    for key in (
        "network_calls",
        "external_ai",
        "external_threat_intelligence",
        "external_mitre_api",
    ):
        if value.get(key) is not False:
            raise MitreConfigError(f"MITRE mapping config must set {key}: false")


def _normalize_entries(event_type: str, entries: object) -> list[dict[str, Any]]:
    raw_entries = entries if isinstance(entries, list) else [entries]
    if not raw_entries or not all(isinstance(item, dict) for item in raw_entries):
        raise MitreConfigError(f"mappings.{event_type} must contain mapping entries")

    normalized: list[dict[str, Any]] = []
    for entry in raw_entries:
        normalized.append(
            {
                "tactic": _entry_str(entry, "tactic", event_type),
                "technique_id": _entry_optional_str(entry, "technique_id", event_type),
                "technique_name": _entry_str(entry, "technique_name", event_type),
                "confidence": _entry_str(entry, "confidence", event_type),
                "rationale": _entry_str(entry, "rationale", event_type),
            }
        )
    return normalized


def _entry_str(entry: dict[str, Any], key: str, event_type: str) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value:
        raise MitreConfigError(f"mappings.{event_type}.{key} must be a string")
    return value


def _entry_optional_str(entry: dict[str, Any], key: str, event_type: str) -> str | None:
    value = entry.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise MitreConfigError(f"mappings.{event_type}.{key} must be null or string")
    return value


def _require_str(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise MitreConfigError(f"{key} must be a non-empty string")
    return value


def _require_int(raw: dict[str, Any], key: str) -> int:
    value = raw.get(key)
    if not isinstance(value, int):
        raise MitreConfigError(f"{key} must be an integer")
    return value
