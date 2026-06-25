from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

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

REQUIRED_ALERT_FIELDS = {
    "alert_id",
    "timestamp",
    "source_ip",
    "dest_ip",
    "event_type",
    "raw_message",
    "synthetic_marker",
}

JSON_FIXTURES = [
    ROOT / "alerts" / "sample_alerts.json",
    ROOT / "tests" / "fixtures" / "valid_alerts.json",
    ROOT / "tests" / "fixtures" / "malformed_alerts.json",
    ROOT / "tests" / "fixtures" / "edge_case_alerts.json",
    ROOT / "tests" / "fixtures" / "sensitive_marker_alerts.json",
]


def load_json(path: Path) -> list[dict[str, object]]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_expected_sample_files_exist() -> None:
    missing = [path for path in JSON_FIXTURES if not path.exists()]
    assert missing == []


def test_json_fixtures_are_parseable_lists() -> None:
    for path in JSON_FIXTURES:
        data = load_json(path)
        assert isinstance(data, list)
        assert data


def test_main_sample_alert_count_and_event_type_coverage() -> None:
    alerts = load_json(ROOT / "alerts" / "sample_alerts.json")
    assert 20 <= len(alerts) <= 30
    assert {str(alert["event_type"]) for alert in alerts} == EXPECTED_EVENT_TYPES


def test_valid_fixtures_have_required_fields_and_synthetic_marker() -> None:
    valid_paths = [
        ROOT / "alerts" / "sample_alerts.json",
        ROOT / "tests" / "fixtures" / "valid_alerts.json",
        ROOT / "tests" / "fixtures" / "edge_case_alerts.json",
        ROOT / "tests" / "fixtures" / "sensitive_marker_alerts.json",
    ]
    for path in valid_paths:
        for alert in load_json(path):
            assert set(alert) >= REQUIRED_ALERT_FIELDS
            assert alert["synthetic_marker"] is True
