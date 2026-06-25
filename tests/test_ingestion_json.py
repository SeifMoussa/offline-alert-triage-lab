from __future__ import annotations

import json

from tests.test_alert_models import valid_alert_payload

from triage_lab.ingestion.json_loader import load_alerts_from_path
from triage_lab.models.alert import AlertRecord


def test_json_array_loading(tmp_path) -> None:
    path = tmp_path / "alerts.json"
    path.write_text(json.dumps([valid_alert_payload()]), encoding="utf-8")

    result = load_alerts_from_path(path)

    assert result.valid is True
    assert result.records_seen == 1
    assert result.alerts_loaded == 1
    assert isinstance(result.alerts[0], AlertRecord)


def test_single_json_object_loading(tmp_path) -> None:
    path = tmp_path / "single.json"
    path.write_text(json.dumps(valid_alert_payload()), encoding="utf-8")

    result = load_alerts_from_path(path)

    assert result.valid is True
    assert result.records_seen == 1
    assert result.alerts_loaded == 1


def test_ndjson_loading(tmp_path) -> None:
    first = valid_alert_payload()
    second = valid_alert_payload()
    second["alert_id"] = "unit-0002"
    path = tmp_path / "alerts.json"
    path.write_text(
        "\n".join(json.dumps(record) for record in [first, second]),
        encoding="utf-8",
    )

    result = load_alerts_from_path(path)

    assert result.valid is True
    assert result.records_seen == 2
    assert result.alerts_loaded == 2


def test_malformed_json_handling(tmp_path) -> None:
    path = tmp_path / "broken.json"
    path.write_text("{not-json", encoding="utf-8")

    result = load_alerts_from_path(path)

    assert result.valid is False
    assert result.alerts_loaded == 0
    assert result.errors[0].error_type == "malformed_json"


def test_empty_file_handling(tmp_path) -> None:
    path = tmp_path / "empty.json"
    path.write_text("", encoding="utf-8")

    result = load_alerts_from_path(path)

    assert result.valid is False
    assert result.errors[0].error_type == "empty_file"


def test_malformed_record_is_structured_error(tmp_path) -> None:
    payload = valid_alert_payload()
    del payload["dest_ip"]
    path = tmp_path / "bad-record.json"
    path.write_text(json.dumps([payload]), encoding="utf-8")

    result = load_alerts_from_path(path)

    assert result.valid is False
    assert result.records_seen == 1
    assert result.alerts_loaded == 0
    assert result.errors[0].error_type == "validation_error"
    assert result.errors[0].record_index == 0
    assert result.errors[0].field_path == "dest_ip"


def test_non_object_record_is_structured_error(tmp_path) -> None:
    path = tmp_path / "bad-record.json"
    path.write_text(json.dumps(["not-an-object"]), encoding="utf-8")

    result = load_alerts_from_path(path)

    assert result.valid is False
    assert result.errors[0].error_type == "invalid_record_type"


def test_top_level_json_scalar_is_structured_error(tmp_path) -> None:
    path = tmp_path / "bad-shape.json"
    path.write_text("42", encoding="utf-8")

    result = load_alerts_from_path(path)

    assert result.valid is False
    assert result.errors[0].error_type == "invalid_json_shape"


def test_ndjson_ignores_blank_lines(tmp_path) -> None:
    path = tmp_path / "alerts.json"
    path.write_text(f"\n{json.dumps(valid_alert_payload())}\n", encoding="utf-8")

    result = load_alerts_from_path(path)

    assert result.valid is True
    assert result.records_seen == 1
