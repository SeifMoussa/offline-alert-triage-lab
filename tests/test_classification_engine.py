from __future__ import annotations

from tests.test_alert_models import valid_alert_payload

from triage_lab.classification.engine import classify_alert
from triage_lab.classification.rules import load_rules
from triage_lab.models.alert import AlertRecord
from triage_lab.models.severity import Severity


def make_alert(**updates: object) -> AlertRecord:
    payload = valid_alert_payload()
    payload.update(updates)
    return AlertRecord.model_validate(payload)


def test_each_base_event_type_maps_correctly() -> None:
    ruleset = load_rules()
    for event_type, expected in ruleset.base_severity.items():
        result = classify_alert(make_alert(event_type=event_type), ruleset)
        assert result.base_severity == expected


def test_unrecognized_event_type_defaults_to_medium() -> None:
    ruleset = load_rules()
    alert = make_alert().model_copy(update={"event_type": "future_event"})

    result = classify_alert(alert, ruleset)

    assert result.base_severity == Severity.MEDIUM
    assert result.final_severity == Severity.MEDIUM


def test_count_100_raises_by_one() -> None:
    result = classify_alert(make_alert(count=100), load_rules())

    assert result.final_severity == Severity.MEDIUM
    assert [modifier.modifier_id for modifier in result.modifiers_applied] == [
        "MOD-COUNT-100"
    ]


def test_count_500_raises_by_three_total_from_two_count_rules() -> None:
    result = classify_alert(make_alert(count=500), load_rules())

    assert result.final_severity == Severity.CRITICAL
    assert [modifier.modifier_id for modifier in result.modifiers_applied][:2] == [
        "MOD-COUNT-100",
        "MOD-COUNT-500",
    ]


def test_sensitive_port_raises_severity() -> None:
    result = classify_alert(make_alert(dest_port=22), load_rules())

    assert result.final_severity == Severity.MEDIUM
    assert "MOD-SENSITIVE-DEST-PORT" in {
        modifier.modifier_id for modifier in result.modifiers_applied
    }


def test_known_synthetic_bad_ip_overrides_to_critical() -> None:
    result = classify_alert(make_alert(source_ip="198.51.100.25"), load_rules())

    assert result.final_severity == Severity.CRITICAL
    assert result.overrides_applied[0].override_id == "OVR-KNOWN-SYNTHETIC-BAD-IP"


def test_privileged_username_raises_severity() -> None:
    result = classify_alert(make_alert(username="test_admin"), load_rules())

    assert result.final_severity == Severity.MEDIUM
    assert "MOD-PRIVILEGED-USERNAME" in {
        modifier.modifier_id for modifier in result.modifiers_applied
    }


def test_internal_asset_tag_raises_severity() -> None:
    result = classify_alert(make_alert(tags=["internal_asset"]), load_rules())

    assert result.final_severity == Severity.MEDIUM


def test_honeypot_tag_raises_severity() -> None:
    result = classify_alert(make_alert(tags=["honeypot"]), load_rules())

    assert result.final_severity == Severity.MEDIUM


def test_raw_synthetic_marker_raises_and_output_is_safe() -> None:
    result = classify_alert(
        make_alert(raw_message="Synthetic marker SYNTHETIC_TOKEN_MARKER."),
        load_rules(),
    )
    rendered = str(result.to_safe_dict())

    assert result.final_severity == Severity.MEDIUM
    assert "MOD-SYNTHETIC-MARKER" in {
        modifier.modifier_id for modifier in result.modifiers_applied
    }
    assert "SYNTHETIC_TOKEN_MARKER" not in rendered


def test_modifier_stacking_is_deterministic_and_capped() -> None:
    result = classify_alert(
        make_alert(
            event_type="brute_force",
            count=500,
            dest_port=22,
            username="test_admin",
            tags=["internal_asset", "honeypot"],
        ),
        load_rules(),
    )

    assert result.final_severity == Severity.CRITICAL
    assert [modifier.modifier_id for modifier in result.modifiers_applied] == [
        "MOD-COUNT-100",
        "MOD-COUNT-500",
        "MOD-SENSITIVE-DEST-PORT",
        "MOD-PRIVILEGED-USERNAME",
        "MOD-INTERNAL-ASSET-TAG",
        "MOD-HONEYPOT-TAG",
    ]
    assert all("SYNTHETIC_" not in trace for trace in result.trace)
