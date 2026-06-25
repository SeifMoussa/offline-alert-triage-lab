"""Load local defensive triage playbooks from YAML."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from triage_lab.ingestion.validators import validate_local_input_path


class PlaybookConfigError(ValueError):
    """Raised when local triage playbook config is invalid or unsafe."""


DEFAULT_TRIAGE_STEPS_PATH = (
    Path(__file__).resolve().parents[3] / "config" / "triage_steps.yaml"
)


@dataclass(frozen=True)
class PlaybookConfig:
    """Validated local playbook configuration."""

    name: str
    version: int
    steps: tuple[dict[str, Any], ...]


def load_playbooks(config_path: str | Path | None = None) -> PlaybookConfig:
    """Load local defensive playbook YAML."""
    path = (
        DEFAULT_TRIAGE_STEPS_PATH
        if config_path is None
        else _validate_config_path(config_path)
    )
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PlaybookConfigError(
            f"unable to read triage playbook config: {exc}"
        ) from exc
    except yaml.YAMLError as exc:
        raise PlaybookConfigError(f"invalid triage playbook YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise PlaybookConfigError("triage playbook config must be a YAML mapping")
    return _parse_playbooks(raw)


def _validate_config_path(config_path: str | Path) -> Path:
    try:
        path = validate_local_input_path(str(config_path))
    except ValueError as exc:
        raise PlaybookConfigError(str(exc)) from exc
    if path.suffix.lower() not in {".yaml", ".yml"}:
        raise PlaybookConfigError("triage playbook config must be a local YAML file")
    return path


def _parse_playbooks(raw: dict[str, Any]) -> PlaybookConfig:
    _validate_safety(raw.get("safety"))
    steps = raw.get("steps")
    if not isinstance(steps, list) or not steps:
        raise PlaybookConfigError("steps must be a non-empty list")
    normalized = tuple(_parse_step(step) for step in steps)
    return PlaybookConfig(
        name=_optional_name(raw),
        version=_require_int(raw, "version"),
        steps=normalized,
    )


def _validate_safety(value: object) -> None:
    if not isinstance(value, dict):
        raise PlaybookConfigError("safety must be configured")
    if (
        value.get("offline_only") is not True
        or value.get("synthetic_data_only") is not True
    ):
        raise PlaybookConfigError(
            "triage playbook config must be offline-only and synthetic-data only"
        )
    for key in ("network_calls", "external_ai", "external_threat_intelligence"):
        if value.get(key) is not False:
            raise PlaybookConfigError(f"triage playbook config must set {key}: false")


def _parse_step(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PlaybookConfigError("each playbook step must be a mapping")
    return {
        "id": _entry_str(value, "id"),
        "title": _entry_str(value, "title"),
        "description": _entry_str(value, "description"),
        "safety_note": _entry_str(value, "safety_note"),
        "order": _entry_int(value, "order"),
        "applies_to_event_types": _entry_str_list(value, "applies_to_event_types"),
        "applies_to_severities": _entry_str_list(value, "applies_to_severities"),
    }


def _optional_name(raw: dict[str, Any]) -> str:
    value = raw.get("name", "offline-alert-triage-local-playbooks")
    if not isinstance(value, str) or not value:
        raise PlaybookConfigError("name must be a non-empty string")
    return value


def _require_int(raw: dict[str, Any], key: str) -> int:
    value = raw.get(key)
    if not isinstance(value, int):
        raise PlaybookConfigError(f"{key} must be an integer")
    return value


def _entry_str(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise PlaybookConfigError(f"step {key} must be a non-empty string")
    return value


def _entry_int(raw: dict[str, Any], key: str) -> int:
    value = raw.get(key)
    if not isinstance(value, int):
        raise PlaybookConfigError(f"step {key} must be an integer")
    return value


def _entry_str_list(raw: dict[str, Any], key: str) -> list[str]:
    value = raw.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise PlaybookConfigError(f"step {key} must be a list of strings")
    return value
