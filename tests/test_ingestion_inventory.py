from __future__ import annotations

import json

from tests.test_alert_models import valid_alert_payload

from triage_lab.ingestion.inventory import build_inventory


def test_directory_loading_counts_supported_and_unsupported_files(tmp_path) -> None:
    valid = valid_alert_payload()
    second = valid_alert_payload()
    second["alert_id"] = "unit-0002"
    second["event_type"] = "brute_force"

    (tmp_path / "nested").mkdir()
    (tmp_path / "alerts.json").write_text(json.dumps([valid]), encoding="utf-8")
    (tmp_path / "nested" / "more.json").write_text(
        json.dumps([second]),
        encoding="utf-8",
    )
    (tmp_path / "notes.txt").write_text("local note", encoding="utf-8")

    result = build_inventory(tmp_path)

    assert result.files_seen == 3
    assert result.files_loaded == 2
    assert result.unsupported_files == 1
    assert result.records_seen == 2
    assert result.alerts_loaded == 2
    assert result.event_type_counts == {"brute_force": 1, "failed_login": 1}
    assert result.earliest_timestamp is not None
    assert result.latest_timestamp is not None


def test_unsupported_extension_behavior(tmp_path) -> None:
    path = tmp_path / "alerts.csv"
    path.write_text("not supported", encoding="utf-8")

    result = build_inventory(path)

    assert result.valid is False
    assert result.files_seen == 1
    assert result.unsupported_files == 1
    assert result.errors[0].error_type == "unsupported_file"


def test_missing_path_is_structured_error(tmp_path) -> None:
    result = build_inventory(tmp_path / "missing.json")

    assert result.valid is False
    assert result.files_seen == 0
    assert result.errors[0].error_type == "path_not_found"


def test_inventory_dict_shape_for_sample_alerts() -> None:
    result = build_inventory("alerts")
    payload = result.to_inventory_dict()

    assert payload["alerts_loaded"] == 22
    assert payload["records_seen"] == 22
    assert payload["event_type_counts"]["unknown"] == 2
    assert payload["earliest_timestamp"] == "2026-01-15T02:15:00Z"
    assert payload["latest_timestamp"] == "2026-01-15T09:05:00Z"


def test_validation_dict_for_empty_result(tmp_path) -> None:
    result = build_inventory(tmp_path / "missing.json")
    payload = result.to_validation_dict()

    assert payload["valid"] is False
    assert payload["files_checked"] == 0
    assert payload["error_count"] == 1
