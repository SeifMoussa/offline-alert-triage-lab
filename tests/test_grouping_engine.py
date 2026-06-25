from __future__ import annotations

import json
from pathlib import Path

from triage_lab.grouping.engine import group_loaded_alerts, grouping_result_is_success

ROOT = Path(__file__).resolve().parents[1]


def test_group_loaded_alerts_sample_dataset() -> None:
    payload = group_loaded_alerts(ROOT / "alerts" / "sample_alerts.json")

    assert grouping_result_is_success(payload)
    assert payload["alerts_loaded"] == 22
    assert payload["incident_count"] == 1
    assert payload["grouped_alert_count"] == 22
    assert payload["ungrouped_alert_count"] == 0
    assert payload["highest_incident_severity"] == "CRITICAL"
    assert payload["incidents"][0]["incident_id"] == "INC-0001"
    assert payload["incidents"][0]["suggested_priority"] == "P1"


def test_group_loaded_alerts_with_custom_grouping_config(tmp_path: Path) -> None:
    config_path = tmp_path / "grouping.yaml"
    config_path.write_text(
        """
name: custom-grouping
version: 1
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

    payload = group_loaded_alerts(
        ROOT / "alerts" / "sample_alerts.json",
        grouping_config_path=config_path,
    )

    assert payload["errors"] == []
    assert payload["incident_count"] >= 1
    assert payload["grouped_alert_count"] > 0


def test_group_loaded_alerts_invalid_grouping_config_is_structured() -> None:
    payload = group_loaded_alerts(
        ROOT / "alerts" / "sample_alerts.json",
        grouping_config_path="https://example.com/grouping.yaml",
    )

    assert not grouping_result_is_success(payload)
    assert payload["incident_count"] == 0
    assert payload["errors"][0]["error_type"] == "grouping_config_error"


def test_group_loaded_alerts_output_is_json_serializable() -> None:
    payload = group_loaded_alerts(ROOT / "alerts" / "sample_alerts.json")

    encoded = json.dumps(payload)

    assert "raw_message" not in encoded
    assert "SYNTHETIC_TOKEN_MARKER" not in encoded
