from __future__ import annotations

from tests.test_alert_models import valid_alert_payload

from triage_lab.classification.engine import classify_alert
from triage_lab.classification.rules import load_rules
from triage_lab.explanations.engine import generate_explanation
from triage_lab.grouping.config import GroupingConfig
from triage_lab.grouping.correlator import AlertGroupingContext, correlate_alerts
from triage_lab.mitre.loader import load_mitre_mapping
from triage_lab.mitre.mapping import map_alert_to_mitre
from triage_lab.models.alert import AlertRecord
from triage_lab.triage.playbooks import load_playbooks


def make_alert(alert_id: str, **updates: object) -> AlertRecord:
    payload = valid_alert_payload()
    payload.update(
        {
            "alert_id": alert_id,
            "raw_message": f"Synthetic grouping alert {alert_id}.",
        }
    )
    payload.update(updates)
    return AlertRecord.model_validate(payload)


def make_context(alert: AlertRecord) -> AlertGroupingContext:
    ruleset = load_rules()
    mitre_config = load_mitre_mapping()
    playbooks = load_playbooks()
    classification = classify_alert(alert, ruleset)
    mitre_mapping = map_alert_to_mitre(
        alert,
        mitre_config,
        final_severity=classification.final_severity.value,
    )
    explanation = generate_explanation(alert, classification, mitre_mapping, playbooks)
    return AlertGroupingContext(alert, classification, mitre_mapping, explanation)


def config_for(rule: dict[str, object]) -> GroupingConfig:
    return GroupingConfig(name="test-grouping", version=1, rules=(rule,))


def same_field_rule(field: str, minutes: int = 15) -> dict[str, object]:
    return {
        "id": f"same_{field}",
        "description": f"Group by {field}.",
        "enabled": True,
        "match_type": "same_field_time_window",
        "field": field,
        "time_window_minutes": minutes,
        "minimum_alerts": 2,
    }


def test_same_source_ip_grouping_within_15_minutes() -> None:
    contexts = [
        make_context(make_alert("a1", source_ip="10.1.1.10")),
        make_context(
            make_alert(
                "a2",
                timestamp="2026-01-17T10:14:00Z",
                source_ip="10.1.1.10",
                username="demo_user",
            )
        ),
    ]

    incidents, ungrouped = correlate_alerts(
        contexts, config_for(same_field_rule("source_ip"))
    )

    assert [incident.alert_ids for incident in incidents] == [["a1", "a2"]]
    assert ungrouped == []
    assert incidents[0].correlation_reasons[0].rule_id == "same_source_ip"


def test_same_source_ip_not_grouped_outside_time_window() -> None:
    contexts = [
        make_context(make_alert("a1", source_ip="10.1.1.10")),
        make_context(
            make_alert(
                "a2",
                timestamp="2026-01-17T10:16:00Z",
                source_ip="10.1.1.10",
            )
        ),
    ]

    incidents, ungrouped = correlate_alerts(
        contexts, config_for(same_field_rule("source_ip"))
    )

    assert incidents == []
    assert ungrouped == ["a1", "a2"]


def test_same_username_grouping_within_60_minutes() -> None:
    contexts = [
        make_context(make_alert("a1", username="analyst_user")),
        make_context(
            make_alert(
                "a2",
                timestamp="2026-01-17T10:59:00Z",
                username="analyst_user",
                source_ip="10.1.1.11",
            )
        ),
    ]

    incidents, _ = correlate_alerts(
        contexts, config_for(same_field_rule("username", minutes=60))
    )

    assert incidents[0].alert_ids == ["a1", "a2"]
    assert incidents[0].usernames_redacted == ["[REDACTED:username:1]"]


def test_same_hostname_with_critical_alert_grouping() -> None:
    rule = {
        "id": "same_hostname_with_critical_alert",
        "description": "Group critical hostname.",
        "enabled": True,
        "match_type": "same_field_with_severity",
        "field": "hostname",
        "required_severity": "CRITICAL",
        "time_window_minutes": 720,
        "minimum_alerts": 2,
    }
    contexts = [
        make_context(make_alert("a1", hostname="server-01.test")),
        make_context(
            make_alert(
                "a2",
                event_type="data_exfiltration",
                hostname="server-01.test",
                source_ip="10.1.1.11",
            )
        ),
    ]

    incidents, _ = correlate_alerts(contexts, config_for(rule))

    assert incidents[0].severity.value == "CRITICAL"
    assert incidents[0].hostnames == ["server-01.test"]


def test_same_mitre_tactic_grouping_within_30_minutes() -> None:
    rule = {
        "id": "same_mitre_tactic_within_30m",
        "description": "Group by tactic.",
        "enabled": True,
        "match_type": "same_mitre_tactic_time_window",
        "time_window_minutes": 30,
        "minimum_alerts": 2,
    }
    contexts = [
        make_context(make_alert("a1", event_type="failed_login")),
        make_context(
            make_alert(
                "a2",
                event_type="brute_force",
                timestamp="2026-01-17T10:20:00Z",
                source_ip="10.1.1.11",
            )
        ),
    ]

    incidents, _ = correlate_alerts(contexts, config_for(rule))

    assert incidents[0].mitre_tactics_observed == ["Credential Access"]
    assert incidents[0].mitre_techniques_observed == ["T1110"]


def test_multistage_chain_grouping() -> None:
    rule = {
        "id": "same_source_and_privilege_escalation_chain",
        "description": "Group chain.",
        "enabled": True,
        "match_type": "event_chain",
        "precursor_event_types": ["failed_login", "brute_force"],
        "followup_event_types": ["privilege_escalation", "lateral_movement"],
        "match_fields": ["username", "hostname"],
        "time_window_minutes": 60,
        "minimum_alerts": 2,
    }
    contexts = [
        make_context(make_alert("a1", event_type="brute_force")),
        make_context(
            make_alert(
                "a2",
                event_type="privilege_escalation",
                timestamp="2026-01-17T10:30:00Z",
                source_ip="10.1.1.11",
            )
        ),
    ]

    incidents, _ = correlate_alerts(contexts, config_for(rule))

    assert incidents[0].alert_ids == ["a1", "a2"]
    assert "event_type" in incidents[0].correlation_reasons[0].matched_fields


def test_connected_groups_merge_and_sort_deterministically() -> None:
    first_rule = same_field_rule("username", minutes=60)
    second_rule = dict(same_field_rule("hostname", minutes=60))
    second_rule["id"] = "same_hostname"
    config = GroupingConfig(
        name="test",
        version=1,
        rules=(first_rule, second_rule),
    )
    contexts = [
        make_context(make_alert("a3", username="demo_user", hostname="host-a.test")),
        make_context(make_alert("a1", username="analyst_user", hostname="host-a.test")),
        make_context(make_alert("a2", username="analyst_user", hostname="host-b.test")),
    ]

    incidents, ungrouped = correlate_alerts(contexts, config)

    assert incidents[0].incident_id == "INC-0001"
    assert incidents[0].alert_ids == ["a1", "a2", "a3"]
    assert ungrouped == []


def test_unrelated_alerts_remain_ungrouped() -> None:
    contexts = [
        make_context(make_alert("a1", username="analyst_user")),
        make_context(
            make_alert(
                "a2",
                username="demo_user",
                source_ip="10.1.1.11",
                hostname="server-01.test",
            )
        ),
    ]

    incidents, ungrouped = correlate_alerts(
        contexts, config_for(same_field_rule("username", minutes=60))
    )

    assert incidents == []
    assert ungrouped == ["a1", "a2"]
