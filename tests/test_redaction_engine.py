from __future__ import annotations

import copy
import json

from tests.test_alert_models import valid_alert_payload

from triage_lab.models.alert import AlertRecord
from triage_lab.redaction.engine import redact_payload


def test_recursive_redaction_removes_sensitive_fields_without_mutation() -> None:
    payload = {
        "alert": {
            "alert_id": "alert-1",
            "source_ip": "10.1.1.10",
            "dest_ip": "192.0.2.10",
            "username": "analyst_user",
            "hostname": "workstation-01.test",
            "raw_message": "Synthetic message SYNTHETIC_TOKEN_MARKER token=abc",
            "description": "Synthetic marker SYNTHETIC_TOKEN_MARKER token=abc",
            "notes": [
                "password=abc",
                "safe project terms: CodeQL GitHub Actions pytest Ruff MITRE ATT&CK",
            ],
        },
        "tuple_values": ("secret=abc", "T1110"),
        "set_values": {"api_key=abc", "INC-0001"},
    }
    original = copy.deepcopy(payload)

    result = redact_payload(payload)
    rendered = json.dumps(result.payload, sort_keys=True)

    assert payload == original
    assert result.safe_for_output
    assert result.summary.raw_messages_removed == 1
    assert result.summary.ip_values_redacted == 2
    assert result.summary.usernames_redacted == 1
    assert result.summary.credential_patterns_redacted == 4
    assert result.summary.markers_redacted == 1
    assert "raw_message" not in rendered
    assert "10.1.1.10" not in rendered
    assert "analyst_user" not in rendered
    assert "SYNTHETIC_TOKEN_MARKER" not in rendered
    assert "password=" not in rendered
    assert "token=" not in rendered
    assert "secret=" not in rendered
    assert "api_key=" not in rendered
    assert "workstation-01.test" in rendered
    assert "T1110" in rendered
    assert "INC-0001" in rendered
    assert "CodeQL GitHub Actions pytest Ruff MITRE ATT&CK" in rendered


def test_pydantic_model_redaction_uses_safe_serialization_then_policy() -> None:
    payload = valid_alert_payload()
    payload["raw_message"] = "Synthetic marker SYNTHETIC_SECRET_MARKER."
    alert = AlertRecord.model_validate(payload)

    result = redact_payload(alert)

    assert result.safe_for_output
    assert result.payload["alert_id"] == "unit-0001"
    assert result.payload["event_type"] == "failed_login"
    assert result.payload["source_ip"] == "[REDACTED:ip]"
    assert result.payload["dest_ip"] == "[REDACTED:ip]"
    assert result.payload["username"] == "[REDACTED:username]"
    assert "raw_message" not in result.payload


def test_summary_counts_categories_without_exposing_values() -> None:
    result = redact_payload(
        {
            "source_ip": "10.9.8.7",
            "username": "lab_user",
            "message": "private_key not-real SYNTHETIC_PASSWORD_MARKER",
        }
    )
    summary = result.summary.model_dump(mode="json")
    rendered_summary = json.dumps(summary)

    assert summary["fields_redacted"] == 2
    assert summary["ip_values_redacted"] == 1
    assert summary["usernames_redacted"] == 1
    assert summary["credential_patterns_redacted"] == 1
    assert summary["markers_redacted"] == 1
    assert "10.9.8.7" not in rendered_summary
    assert "lab_user" not in rendered_summary
    assert "SYNTHETIC_PASSWORD_MARKER" not in rendered_summary
