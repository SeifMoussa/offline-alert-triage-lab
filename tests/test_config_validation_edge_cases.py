from __future__ import annotations

from pathlib import Path

import pytest

from triage_lab.classification.rules import RuleConfigError, load_rules
from triage_lab.grouping.config import GroupingConfigError, load_grouping_config
from triage_lab.mitre.loader import MitreConfigError, load_mitre_mapping
from triage_lab.triage.playbooks import PlaybookConfigError, load_playbooks

UNKNOWN_MITRE_ENTRY = (
    "  unknown:\n"
    "    - tactic: Unknown\n"
    "      technique_id: null\n"
    "      technique_name: Unknown mapping placeholder\n"
    "      confidence: low\n"
    "      rationale: Unknown synthetic alerts use a local documented fallback "
    "placeholder.\n"
)


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def _replace_top_level(source: str, key: str, replacement: str) -> str:
    lines = source.splitlines()
    output: list[str] = []
    skipping = False
    inserted = False
    for line in lines:
        if line.startswith(f"{key}:"):
            output.extend(replacement.splitlines())
            skipping = True
            inserted = True
            continue
        if skipping and line and not line.startswith((" ", "-")):
            skipping = False
        if not skipping:
            output.append(line)
    if not inserted:
        raise AssertionError(f"{key} was not found in fixture config")
    return "\n".join(output) + "\n"


@pytest.mark.parametrize(
    ("filename", "loader", "error"),
    [
        ("rules.txt", load_rules, RuleConfigError),
        ("mitre.txt", load_mitre_mapping, MitreConfigError),
        ("playbooks.txt", load_playbooks, PlaybookConfigError),
        ("grouping.txt", load_grouping_config, GroupingConfigError),
    ],
)
def test_yaml_config_loaders_reject_non_yaml_suffix(
    tmp_path: Path, filename: str, loader, error
) -> None:
    path = _write(tmp_path / filename, "name: local\n")

    with pytest.raises(error, match="YAML"):
        loader(path)


@pytest.mark.parametrize(
    ("filename", "loader", "error", "message"),
    [
        ("rules.yaml", load_rules, RuleConfigError, "unable to read"),
        ("mitre.yaml", load_mitre_mapping, MitreConfigError, "unable to read"),
        ("playbooks.yaml", load_playbooks, PlaybookConfigError, "unable to read"),
        ("grouping.yaml", load_grouping_config, GroupingConfigError, "unable to read"),
    ],
)
def test_yaml_config_loaders_report_missing_files(
    tmp_path: Path, filename: str, loader, error, message: str
) -> None:
    with pytest.raises(error, match=message):
        loader(tmp_path / filename)


@pytest.mark.parametrize(
    ("filename", "loader", "error", "message"),
    [
        ("rules.yaml", load_rules, RuleConfigError, "invalid YAML"),
        ("mitre.yaml", load_mitre_mapping, MitreConfigError, "invalid MITRE"),
        ("playbooks.yaml", load_playbooks, PlaybookConfigError, "invalid triage"),
        (
            "grouping.yaml",
            load_grouping_config,
            GroupingConfigError,
            "invalid grouping",
        ),
    ],
)
def test_yaml_config_loaders_report_malformed_yaml(
    tmp_path: Path, filename: str, loader, error, message: str
) -> None:
    path = _write(tmp_path / filename, "name: [unterminated\n")

    with pytest.raises(error, match=message):
        loader(path)


@pytest.mark.parametrize(
    ("replacement", "message"),
    [
        ("safety:\n  offline_only: false", "offline-only"),
        (
            "safety:\n  offline_only: true\n  synthetic_data_only: true\n"
            "  network_calls: true",
            "network_calls",
        ),
        ("base_severity: []", "base_severity"),
        ("severity_levels: [LOW, MEDIUM]", "severity_levels"),
        ("default_severity: EMERGENCY", "default_severity"),
        ("name: ''", "name"),
        ("version: one", "version"),
        ("modifier_rules: bad", "modifier_rules"),
        ("sensitive_destination_ports: [ssh]", "sensitive_destination_ports"),
        ("privileged_usernames: [123]", "privileged_usernames"),
        ("known_synthetic_bad_ips: [123]", "known_synthetic_bad_ips"),
        ("synthetic_marker_patterns: bad", "synthetic_marker_patterns"),
        ("synthetic_marker_patterns:\n  - name: missing", "entries need pattern"),
    ],
)
def test_rules_config_validation_errors(
    tmp_path: Path, replacement: str, message: str
) -> None:
    source = Path("config/rules.yaml").read_text(encoding="utf-8")
    key = replacement.split(":", 1)[0]
    path = _write(tmp_path / "rules.yaml", _replace_top_level(source, key, replacement))

    with pytest.raises(RuleConfigError, match=message):
        load_rules(path)


def test_rules_config_requires_all_base_event_types(tmp_path: Path) -> None:
    source = Path("config/rules.yaml").read_text(encoding="utf-8")
    path = _write(
        tmp_path / "rules.yaml",
        source.replace("  unknown: MEDIUM\n", ""),
    )

    with pytest.raises(RuleConfigError, match="missing event types"):
        load_rules(path)


def test_rules_config_rejects_unsupported_base_severity(tmp_path: Path) -> None:
    source = Path("config/rules.yaml").read_text(encoding="utf-8")
    path = _write(
        tmp_path / "rules.yaml",
        source.replace("  unknown: MEDIUM", "  unknown: EMERGENCY"),
    )

    with pytest.raises(RuleConfigError, match="base_severity.unknown"):
        load_rules(path)


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("mappings: []", "mappings must be a mapping"),
        ("safety: []", "safety must be configured"),
        ("safety:\n  offline_only: false", "offline-only"),
        (
            "safety:\n  offline_only: true\n  synthetic_data_only: true\n"
            "  network_calls: true",
            "network_calls",
        ),
        ("name: ''", "name"),
        ("version: one", "version"),
    ],
)
def test_mitre_config_validation_errors(
    tmp_path: Path, body: str, message: str
) -> None:
    source = Path("config/mitre_mapping.yaml").read_text(encoding="utf-8")
    key = body.split(":", 1)[0]
    path = _write(
        tmp_path / "mitre_mapping.yaml",
        _replace_top_level(source, key, body),
    )

    with pytest.raises(MitreConfigError, match=message):
        load_mitre_mapping(path)


def test_mitre_config_rejects_missing_and_bad_mapping_entries(tmp_path: Path) -> None:
    source = Path("config/mitre_mapping.yaml").read_text(encoding="utf-8")
    missing_unknown = _write(
        tmp_path / "missing.yaml",
        source.replace(UNKNOWN_MITRE_ENTRY, ""),
    )
    with pytest.raises(MitreConfigError, match="missing event types"):
        load_mitre_mapping(missing_unknown)

    bad_entries = _write(
        tmp_path / "bad_entries.yaml",
        source.replace(UNKNOWN_MITRE_ENTRY, "  unknown: []\n"),
    )
    with pytest.raises(MitreConfigError, match="must contain mapping entries"):
        load_mitre_mapping(bad_entries)

    bad_technique = _write(
        tmp_path / "bad_technique.yaml",
        source.replace("      technique_id: T1110\n", "      technique_id: 123\n", 1),
    )
    with pytest.raises(MitreConfigError, match="null or string"):
        load_mitre_mapping(bad_technique)

    bad_entry_field = _write(
        tmp_path / "bad_entry_field.yaml",
        source.replace(
            "    - tactic: Unknown\n"
            "    tactic: Unknown\n"
            "    technique_id:\n"
            "    technique_name: No configured mapping\n"
            "    confidence: low\n"
            "    rationale: Fallback mapping for unknown synthetic event types.\n",
            "",
        ),
    )
    bad_entry_field.write_text(
        source.replace("    - tactic: Unknown\n", "    - tactic: \n", 1),
        encoding="utf-8",
    )
    with pytest.raises(MitreConfigError, match="tactic must be a string"):
        load_mitre_mapping(bad_entry_field)


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("steps: []", "steps must be a non-empty list"),
        ("safety: []", "safety must be configured"),
        ("safety:\n  offline_only: false", "offline-only"),
        (
            "safety:\n  offline_only: true\n  synthetic_data_only: true\n"
            "  network_calls: true",
            "network_calls",
        ),
        ("name: ''", "name"),
        ("version: one", "version"),
    ],
)
def test_playbook_config_validation_errors(
    tmp_path: Path, body: str, message: str
) -> None:
    source = Path("config/triage_steps.yaml").read_text(encoding="utf-8")
    key = body.split(":", 1)[0]
    path = _write(
        tmp_path / "triage_steps.yaml",
        _replace_top_level(source, key, body),
    )

    with pytest.raises(PlaybookConfigError, match=message):
        load_playbooks(path)


def test_playbook_config_rejects_bad_step_shapes(tmp_path: Path) -> None:
    base = """
name: local-playbook
version: 1
safety:
  offline_only: true
  synthetic_data_only: true
  network_calls: false
  external_ai: false
  external_threat_intelligence: false
steps:
  - id: STEP-1
    title: Review alert
    description: Review the synthetic alert.
    safety_note: Stay offline.
    order: 1
    applies_to_event_types: [unknown]
    applies_to_severities: [LOW]
"""
    for replacement, message in [
        ("  - bad", "each playbook step"),
        (
            "  - id: ''\n"
            "    title: Review\n"
            "    description: Review.\n"
            "    safety_note: Stay offline.\n"
            "    order: 1\n"
            "    applies_to_event_types: [unknown]\n"
            "    applies_to_severities: [LOW]",
            "step id",
        ),
        (
            "  - id: STEP-1\n"
            "    title: Review\n"
            "    description: Review.\n"
            "    safety_note: Stay offline.\n"
            "    order: one\n"
            "    applies_to_event_types: [unknown]\n"
            "    applies_to_severities: [LOW]",
            "step order",
        ),
        (
            "  - id: STEP-1\n"
            "    title: Review\n"
            "    description: Review.\n"
            "    safety_note: Stay offline.\n"
            "    order: 1\n"
            "    applies_to_event_types: unknown\n"
            "    applies_to_severities: [LOW]",
            "list of strings",
        ),
    ]:
        path = _write(
            tmp_path / "triage_steps.yaml",
            base.split("steps:\n", 1)[0] + "steps:\n" + replacement,
        )
        with pytest.raises(PlaybookConfigError, match=message):
            load_playbooks(path)


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("rules: []", "rules must be a non-empty list"),
        ("safety: []", "safety must be configured"),
        ("safety:\n  offline_only: false", "offline-only"),
        (
            "safety:\n  offline_only: true\n  synthetic_data_only: true\n"
            "  network_calls: true",
            "network_calls",
        ),
        ("name: ''", "name"),
        ("version: one", "version"),
    ],
)
def test_grouping_config_validation_errors(
    tmp_path: Path, body: str, message: str
) -> None:
    source = Path("config/grouping_rules.yaml").read_text(encoding="utf-8")
    key = body.split(":", 1)[0]
    path = _write(
        tmp_path / "grouping_rules.yaml",
        _replace_top_level(source, key, body),
    )

    with pytest.raises(GroupingConfigError, match=message):
        load_grouping_config(path)


def test_grouping_config_rejects_bad_rule_shapes(tmp_path: Path) -> None:
    base = """
name: local-grouping
version: 1
safety:
  offline_only: true
  synthetic_data_only: true
  network_calls: false
  external_ai: false
  external_threat_intelligence: false
rules:
  - id: rule-1
    description: Group synthetic alerts.
    enabled: true
    match_type: same_field_time_window
    field: username
    time_window_minutes: 60
    minimum_alerts: 2
"""
    for replacement, message in [
        ("  - bad", "each grouping rule"),
        (
            "  - id: ''\n"
            "    description: Group\n"
            "    enabled: true\n"
            "    match_type: same_field_time_window\n"
            "    time_window_minutes: 1\n"
            "    minimum_alerts: 2",
            "rule id",
        ),
        (
            "  - id: rule-1\n"
            "    description: Group\n"
            "    enabled: 1\n"
            "    match_type: same_field_time_window\n"
            "    time_window_minutes: 1\n"
            "    minimum_alerts: 2",
            "boolean",
        ),
        (
            "  - id: rule-1\n"
            "    description: Group\n"
            "    enabled: true\n"
            "    match_type: nope\n"
            "    time_window_minutes: 1\n"
            "    minimum_alerts: 2",
            "unsupported",
        ),
        (
            "  - id: rule-1\n"
            "    description: Group\n"
            "    enabled: true\n"
            "    match_type: same_field_time_window\n"
            "    time_window_minutes: -1\n"
            "    minimum_alerts: 2",
            "non-negative",
        ),
        (
            "  - id: rule-1\n"
            "    description: Group\n"
            "    enabled: true\n"
            "    match_type: same_field_with_severity\n"
            "    time_window_minutes: 1\n"
            "    minimum_alerts: 2\n"
            "    required_severity: BAD",
            "required_severity",
        ),
        (
            "  - id: rule-1\n"
            "    description: Group\n"
            "    enabled: true\n"
            "    match_type: same_field_time_window\n"
            "    time_window_minutes: 1\n"
            "    minimum_alerts: 2\n"
            "    field: {bad: value}",
            "invalid value",
        ),
    ]:
        path = _write(
            tmp_path / "grouping_rules.yaml",
            base.split("rules:\n", 1)[0] + "rules:\n" + replacement,
        )
        with pytest.raises(GroupingConfigError, match=message):
            load_grouping_config(path)
