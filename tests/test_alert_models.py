from __future__ import annotations

import pytest
from pydantic import ValidationError

from triage_lab.models.alert import AlertRecord


def valid_alert_payload() -> dict[str, object]:
    return {
        "alert_id": "unit-0001",
        "timestamp": "2026-01-17T10:00:00Z",
        "source_ip": "10.1.1.10",
        "dest_ip": "10.1.1.20",
        "source_port": 50000,
        "dest_port": 443,
        "username": "analyst_user",
        "hostname": "workstation-01.test",
        "event_type": "failed_login",
        "raw_message": "Synthetic failed login for workstation-01.test.",
        "count": 1,
        "tags": ["synthetic"],
        "synthetic_marker": True,
    }


def assert_invalid(payload: dict[str, object], expected: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        AlertRecord.model_validate(payload)
    assert expected in str(exc_info.value)


def test_valid_alert_model_creation() -> None:
    alert = AlertRecord.model_validate(valid_alert_payload())
    assert alert.alert_id == "unit-0001"
    assert alert.tags == ["synthetic"]
    assert alert.to_safe_dict()["alert_id"] == "unit-0001"
    assert "SYNTHETIC_TOKEN_MARKER" in alert.approved_synthetic_markers()


def test_missing_required_field_is_rejected() -> None:
    payload = valid_alert_payload()
    del payload["dest_ip"]
    assert_invalid(payload, "Field required")


def test_invalid_timestamp_is_rejected() -> None:
    payload = valid_alert_payload()
    payload["timestamp"] = "not-a-timestamp"
    assert_invalid(payload, "valid datetime")


def test_invalid_ip_range_is_rejected() -> None:
    payload = valid_alert_payload()
    payload["source_ip"] = "8.8.8.8"
    assert_invalid(payload, "allowed synthetic IP range")


def test_invalid_ip_string_is_rejected() -> None:
    payload = valid_alert_payload()
    payload["source_ip"] = "not-an-ip"
    assert_invalid(payload, "valid IP address")


def test_invalid_port_is_rejected() -> None:
    payload = valid_alert_payload()
    payload["dest_port"] = 0
    assert_invalid(payload, "between 1 and 65535")


def test_invalid_count_is_rejected() -> None:
    payload = valid_alert_payload()
    payload["count"] = -1
    assert_invalid(payload, "non-negative")


def test_unsafe_hostname_is_rejected() -> None:
    payload = valid_alert_payload()
    payload["hostname"] = "production.invalid"
    assert_invalid(payload, "approved example domain")


def test_email_username_is_rejected() -> None:
    payload = valid_alert_payload()
    payload["username"] = "person@example.com"
    assert_invalid(payload, "email address")


def test_raw_credential_text_is_rejected() -> None:
    payload = valid_alert_payload()
    payload["raw_message"] = "Synthetic message password=not-real."
    assert_invalid(payload, "credential-looking")


def test_raw_unapproved_domain_is_rejected() -> None:
    payload = valid_alert_payload()
    payload["raw_message"] = "Synthetic message references unsafe.invalid."
    assert_invalid(payload, "unapproved domains")


def test_unsupported_event_type_is_rejected() -> None:
    payload = valid_alert_payload()
    payload["event_type"] = "not_supported"
    assert_invalid(payload, "unsupported event_type")


def test_empty_required_string_is_rejected() -> None:
    payload = valid_alert_payload()
    payload["alert_id"] = " "
    assert_invalid(payload, "must not be empty")


def test_synthetic_marker_must_be_true() -> None:
    payload = valid_alert_payload()
    payload["synthetic_marker"] = False
    assert_invalid(payload, "synthetic_marker must be true")
