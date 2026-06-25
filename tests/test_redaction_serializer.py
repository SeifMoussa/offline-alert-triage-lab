from __future__ import annotations

from triage_lab.redaction.serializer import safe_payload, serialize_for_output


def test_safe_payload_returns_redacted_payload_only() -> None:
    payload = safe_payload(
        {
            "alert_id": "alert-1",
            "source_ip": "10.1.1.10",
            "username": "analyst_user",
            "safe": "pytest Ruff MITRE",
        }
    )

    assert payload == {
        "alert_id": "alert-1",
        "source_ip": "[REDACTED:ip]",
        "username": "[REDACTED:username]",
        "safe": "pytest Ruff MITRE",
    }


def test_serialize_for_output_returns_result_metadata() -> None:
    result = serialize_for_output({"dest_ip": "192.0.2.10"})

    assert result.payload["dest_ip"] == "[REDACTED:ip]"
    assert result.summary.redaction_applied
    assert result.summary.ip_values_redacted == 1
    assert result.safe_for_output
