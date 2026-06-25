from __future__ import annotations

from pathlib import Path

import pytest

from triage_lab.grouping.config import GroupingConfigError, load_grouping_config


def test_grouping_config_loading() -> None:
    config = load_grouping_config()

    assert config.name == "offline-alert-triage-grouping-rules"
    assert config.version == 1
    assert {rule["id"] for rule in config.rules} >= {
        "same_source_ip_within_15m",
        "same_username_within_60m",
        "same_hostname_with_critical_alert",
        "same_mitre_tactic_within_30m",
        "same_source_and_privilege_escalation_chain",
        "same_host_multi_stage_activity",
    }


def test_grouping_config_rejects_url_and_path_traversal() -> None:
    with pytest.raises(GroupingConfigError, match="network paths"):
        load_grouping_config("https://example.com/grouping.yaml")

    with pytest.raises(GroupingConfigError, match="path traversal"):
        load_grouping_config("..\\grouping_rules.yaml")


def test_invalid_grouping_config_fails_clearly(tmp_path: Path) -> None:
    config_path = tmp_path / "bad_grouping.yaml"
    config_path.write_text(
        """
name: bad
version: 1
safety:
  offline_only: false
  synthetic_data_only: true
  network_calls: false
  external_ai: false
  external_threat_intelligence: false
rules: []
""",
        encoding="utf-8",
    )

    with pytest.raises(GroupingConfigError, match="offline-only"):
        load_grouping_config(config_path)


def test_custom_local_grouping_config_works(tmp_path: Path) -> None:
    config_path = tmp_path / "grouping.yaml"
    config_path.write_text(
        """
name: custom-grouping
version: 2
safety:
  offline_only: true
  synthetic_data_only: true
  network_calls: false
  external_ai: false
  external_threat_intelligence: false
rules:
  - id: same_username_within_60m
    description: Group by username.
    enabled: true
    match_type: same_field_time_window
    field: username
    time_window_minutes: 60
    minimum_alerts: 2
""",
        encoding="utf-8",
    )

    config = load_grouping_config(config_path)

    assert config.name == "custom-grouping"
    assert config.version == 2
    assert config.rules[0]["field"] == "username"
