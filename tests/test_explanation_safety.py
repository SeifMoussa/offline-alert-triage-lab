from __future__ import annotations

from triage_lab.explanations.engine import explain_loaded_alerts
from triage_lab.explanations.safety import (
    assert_no_unfilled_placeholders,
    sanitize_explanation_text,
)


def test_raw_message_is_not_included_by_default() -> None:
    payload = explain_loaded_alerts("alerts/sample_alerts.json")
    rendered = str(payload)

    assert "raw_message" not in rendered
    assert "Synthetic failed login for analyst_user" not in rendered


def test_sensitive_marker_constants_absent_from_output() -> None:
    payload = explain_loaded_alerts("tests/fixtures/sensitive_marker_alerts.json")
    rendered = str(payload)

    assert "SYNTHETIC_PASSWORD_MARKER" not in rendered
    assert "SYNTHETIC_TOKEN_MARKER" not in rendered
    assert "SYNTHETIC_SECRET_MARKER" not in rendered


def test_credential_like_strings_are_redacted() -> None:
    text = sanitize_explanation_text("token=SHOULD_NOT_APPEAR")

    assert "SHOULD_NOT_APPEAR" not in text
    assert "[REDACTED]" in text


def test_unfilled_placeholder_detection() -> None:
    try:
        assert_no_unfilled_placeholders("hello {missing}")
    except ValueError as exc:
        assert "unfilled" in str(exc)
    else:
        raise AssertionError("expected placeholder detection failure")
