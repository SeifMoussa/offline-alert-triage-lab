from __future__ import annotations

import json
from pathlib import Path

from triage_lab.grouping.engine import group_loaded_alerts

ROOT = Path(__file__).resolve().parents[1]


def test_incident_output_redacts_sources_and_usernames() -> None:
    payload = group_loaded_alerts(ROOT / "alerts" / "sample_alerts.json")
    incident = payload["incidents"][0]
    encoded = json.dumps(incident)

    assert "[REDACTED:source_ip:1]" in incident["source_ips_redacted"]
    assert "[REDACTED:username:1]" in incident["usernames_redacted"]
    assert "10.10.1.20" not in encoded
    assert "analyst_user" not in encoded


def test_safe_test_hostnames_remain_visible() -> None:
    payload = group_loaded_alerts(ROOT / "alerts" / "sample_alerts.json")

    assert "server-01.test" in payload["incidents"][0]["hostnames"]
    assert all(
        hostname.endswith(".test")
        for incident in payload["incidents"]
        for hostname in incident["hostnames"]
    )


def test_grouping_output_omits_raw_messages_and_sensitive_markers() -> None:
    payload = group_loaded_alerts(
        ROOT / "tests" / "fixtures" / "sensitive_marker_alerts.json"
    )
    encoded = json.dumps(payload)

    assert "raw_message" not in encoded
    assert "SYNTHETIC_PASSWORD_MARKER" not in encoded
    assert "SYNTHETIC_TOKEN_MARKER" not in encoded
    assert "SYNTHETIC_SECRET_MARKER" not in encoded


def test_no_external_ai_or_network_options_in_grouping_output() -> None:
    payload = group_loaded_alerts(ROOT / "alerts" / "sample_alerts.json")
    encoded = json.dumps(payload).lower()

    assert "api_key" not in encoded
    assert "external ai" not in encoded
    assert "network call" not in encoded
