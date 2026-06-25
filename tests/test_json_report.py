from __future__ import annotations

import json

from triage_lab.reporting.json_report import render_json_report
from triage_lab.reporting.pipeline import build_security_report


def test_json_report_is_valid_and_safe() -> None:
    report = build_security_report(
        "alerts/sample_alerts.json",
        generated_at="2026-06-25T00:00:00Z",
    )

    rendered = render_json_report(report)
    payload = json.loads(rendered)

    assert payload["metadata"]["report_type"] == "security_alert_triage"
    assert payload["summary"]["safe_for_output"] is True
    assert payload["summary"]["incident_count"] == 1
    assert "T1110" in rendered
    assert "workstation-01.test" in rendered
    assert "raw_message" not in rendered
    assert "SYNTHETIC_PASSWORD_MARKER" not in rendered
    assert "token=" not in rendered
    assert "api_key=" not in rendered
    assert "private_key" not in rendered
