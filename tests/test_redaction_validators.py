from __future__ import annotations

from triage_lab.redaction.validators import validate_safe_output


def test_validator_accepts_report_ready_safe_payload() -> None:
    result = validate_safe_output(
        {
            "alert_id": "alert-1",
            "event_type": "brute_force",
            "severity": "HIGH",
            "mitre_technique_id": "T1110",
            "mitre_tactic": "Credential Access",
            "hostname": "workstation-01.test",
            "source_ip": "[REDACTED:ip]",
            "username": "[REDACTED:username]",
        }
    )

    assert result.safe
    assert result.errors == []


def test_validator_fails_when_prohibited_marker_remains() -> None:
    result = validate_safe_output({"message": "SYNTHETIC_PASSWORD_MARKER"})

    assert not result.safe
    assert result.errors[0]["error_type"] == "prohibited_marker"


def test_validator_fails_when_credential_patterns_remain() -> None:
    result = validate_safe_output(
        {
            "message": "token=abc private_key abc",
            "nested": ["password=abc", "secret=abc", "api_key=abc"],
        }
    )

    error_types = {error["error_type"] for error in result.errors}
    assert {
        "token_assignment",
        "password_assignment",
        "secret_assignment",
        "api_key_assignment",
        "private_key",
    }.issubset(error_types)


def test_validator_fails_for_raw_message_ip_and_email_username() -> None:
    result = validate_safe_output(
        {
            "raw_message": "Synthetic raw text",
            "source_ip": "10.1.2.3",
            "dest_ip": "192.0.2.10",
            "username": "person@example.com",
        }
    )

    error_types = {error["error_type"] for error in result.errors}
    assert {
        "raw_message_present",
        "unredacted_ip",
        "email_username",
    }.issubset(error_types)
