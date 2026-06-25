from __future__ import annotations

import json

from tests.test_alert_models import valid_alert_payload

from triage_lab.ingestion.json_loader import load_alerts_from_path
from triage_lab.ingestion.validators import redact_sensitive_text


def test_path_traversal_is_rejected() -> None:
    result = load_alerts_from_path("../alerts/sample_alerts.json")

    assert result.valid is False
    assert result.errors[0].error_type == "unsafe_input_path"
    assert "path traversal" in result.errors[0].message


def test_url_input_is_rejected() -> None:
    result = load_alerts_from_path("https://example.com/alerts.json")

    assert result.valid is False
    assert result.errors[0].error_type == "unsafe_input_path"
    assert "network paths" in result.errors[0].message


def test_unc_network_path_is_rejected() -> None:
    result = load_alerts_from_path(r"\\server\share\alerts.json")

    assert result.valid is False
    assert result.errors[0].error_type == "unsafe_input_path"


def test_raw_credential_error_does_not_echo_secret_value(tmp_path) -> None:
    payload = valid_alert_payload()
    payload["raw_message"] = "Synthetic message token=SHOULD_NOT_APPEAR."
    path = tmp_path / "secretish.json"
    path.write_text(json.dumps([payload]), encoding="utf-8")

    result = load_alerts_from_path(path)
    rendered_errors = json.dumps(result.to_validation_dict())

    assert result.valid is False
    assert "SHOULD_NOT_APPEAR" not in rendered_errors
    assert "credential-looking" in rendered_errors


def test_redact_sensitive_text_masks_approved_markers() -> None:
    text = "SYNTHETIC_PASSWORD_MARKER token=abc123"

    redacted = redact_sensitive_text(text)

    assert "SYNTHETIC_PASSWORD_MARKER" not in redacted
    assert "abc123" not in redacted
    assert "[REDACTED]" in redacted
