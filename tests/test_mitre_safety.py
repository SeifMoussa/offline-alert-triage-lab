from __future__ import annotations

from triage_lab.mitre.mapping import map_loaded_alerts_to_mitre


def test_mitre_config_url_error_is_safe() -> None:
    payload = map_loaded_alerts_to_mitre(
        "alerts/sample_alerts.json",
        "https://example.com/mitre_mapping.yaml",
    )

    assert payload["errors"][0]["error_type"] == "mitre_config_error"
    assert "network paths" in payload["errors"][0]["message"]


def test_mitre_config_path_traversal_error_is_safe() -> None:
    payload = map_loaded_alerts_to_mitre(
        "alerts/sample_alerts.json",
        "../config/mitre_mapping.yaml",
    )

    assert payload["errors"][0]["error_type"] == "mitre_config_error"
    assert "path traversal" in payload["errors"][0]["message"]


def test_sensitive_marker_fixture_does_not_emit_raw_markers() -> None:
    payload = map_loaded_alerts_to_mitre("tests/fixtures/sensitive_marker_alerts.json")
    rendered = str(payload)

    assert not payload["errors"]
    assert "SYNTHETIC_PASSWORD_MARKER" not in rendered
    assert "SYNTHETIC_TOKEN_MARKER" not in rendered
    assert "SYNTHETIC_SECRET_MARKER" not in rendered
