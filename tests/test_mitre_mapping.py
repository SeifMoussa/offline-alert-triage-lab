from __future__ import annotations

from tests.test_alert_models import valid_alert_payload

from triage_lab.mitre.loader import load_mitre_mapping
from triage_lab.mitre.mapping import (
    map_alert_to_mitre,
    map_loaded_alerts_to_mitre,
    mitre_url_for_technique,
)
from triage_lab.models.alert import AlertRecord

EXPECTED_TECHNIQUES = {
    "failed_login": "T1110",
    "brute_force": "T1110",
    "port_scan": "T1046",
    "privilege_escalation": "T1068",
    "lateral_movement": "T1021",
    "data_exfiltration": "T1041",
    "c2_beacon": "T1071",
    "malware_detected": "T1204",
    "anomalous_login_time": "T1078",
}


def make_alert(event_type: str) -> AlertRecord:
    payload = valid_alert_payload()
    payload["event_type"] = event_type
    return AlertRecord.model_validate(payload)


def test_static_mitre_url_generation() -> None:
    assert mitre_url_for_technique("T1110") == (
        "https://attack.mitre.org/techniques/T1110/"
    )
    assert mitre_url_for_technique("T1110.001") == (
        "https://attack.mitre.org/techniques/T1110/001/"
    )
    assert mitre_url_for_technique(None) is None


def test_each_expected_event_type_maps_correctly() -> None:
    config = load_mitre_mapping()
    for event_type, technique_id in EXPECTED_TECHNIQUES.items():
        result = map_alert_to_mitre(
            make_alert(event_type),
            config,
            final_severity="HIGH",
        )
        assert result.mapping_found is True
        assert result.fallback_used is False
        assert result.techniques[0].technique_id == technique_id


def test_policy_and_unknown_use_documented_fallback_placeholders() -> None:
    config = load_mitre_mapping()

    policy = map_alert_to_mitre(make_alert("policy_violation"), config)
    unknown = map_alert_to_mitre(make_alert("unknown"), config)

    assert policy.mapping_found is False
    assert policy.fallback_used is True
    assert policy.techniques[0].technique_id is None
    assert unknown.mapping_found is False
    assert unknown.fallback_used is True


def test_unmapped_future_event_uses_unknown_fallback() -> None:
    config = load_mitre_mapping()
    alert = make_alert("unknown").model_copy(update={"event_type": "future_event"})

    result = map_alert_to_mitre(alert, config)

    assert result.mapping_found is False
    assert result.fallback_used is True
    assert result.event_type == "future_event"


def test_loaded_alerts_map_to_mitre_with_classification_severity() -> None:
    payload = map_loaded_alerts_to_mitre("alerts/sample_alerts.json")

    assert payload["alerts_loaded"] == 22
    assert payload["mapping_counts"] == {"mapped": 18, "fallback": 4}
    assert "Credential Access" in payload["tactics_observed"]
    assert "T1110" in payload["techniques_observed"]
    assert payload["mapped_alerts"][0]["final_severity"] is not None
    assert payload["errors"] == []
