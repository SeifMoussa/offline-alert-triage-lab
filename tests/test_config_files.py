from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONFIG_FILES = [
    ROOT / "config" / "rules.yaml",
    ROOT / "config" / "mitre_mapping.yaml",
    ROOT / "config" / "triage_steps.yaml",
    ROOT / "config" / "grouping_rules.yaml",
]
EXPECTED_EVENT_TYPES = {
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
APPROVED_MARKER_PATTERN = "SYNTHETIC_[A-Z_]+_MARKER"
BLOCKED_CONFIG_PATTERNS = (
    re.compile(r"https?://", re.IGNORECASE),
    re.compile(r"\bapi[_-]?key\b", re.IGNORECASE),
    re.compile(r"\bmetasploit\b", re.IGNORECASE),
    re.compile(r"\bnmap\b", re.IGNORECASE),
    re.compile(r"\bnessus\b", re.IGNORECASE),
)


def load_yaml(path: Path) -> dict[str, object]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_expected_config_files_exist() -> None:
    missing = [path for path in CONFIG_FILES if not path.exists()]
    assert missing == []


def test_yaml_config_files_are_parseable() -> None:
    for path in CONFIG_FILES:
        parsed = load_yaml(path)
        assert isinstance(parsed, dict)
        assert parsed["safety"]["offline_only"] is True
        assert parsed["safety"]["synthetic_data_only"] is True


def test_rules_yaml_covers_all_event_types_and_markers() -> None:
    rules = load_yaml(ROOT / "config" / "rules.yaml")
    assert set(rules["base_severity"]) == EXPECTED_EVENT_TYPES
    assert rules["severity_levels"] == ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    marker_patterns = {
        marker["pattern"] for marker in rules["synthetic_marker_patterns"]
    }
    assert marker_patterns == {APPROVED_MARKER_PATTERN}


def test_mitre_mapping_covers_all_event_types() -> None:
    mapping = load_yaml(ROOT / "config" / "mitre_mapping.yaml")
    assert set(mapping["mappings"]) == EXPECTED_EVENT_TYPES
    assert mapping["mappings"]["brute_force"][0]["technique_id"] == "T1110"
    assert mapping["mappings"]["policy_violation"][0]["technique_id"] is None
    assert mapping["mappings"]["unknown"][0]["technique_id"] is None


def test_triage_steps_cover_all_event_types() -> None:
    triage = load_yaml(ROOT / "config" / "triage_steps.yaml")
    covered = {
        event_type
        for step in triage["steps"]
        for event_type in step["applies_to_event_types"]
    }
    assert covered == EXPECTED_EVENT_TYPES


def test_config_has_no_network_or_executable_integration_patterns() -> None:
    for path in CONFIG_FILES:
        text = path.read_text(encoding="utf-8")
        for pattern in BLOCKED_CONFIG_PATTERNS:
            assert pattern.search(text) is None
