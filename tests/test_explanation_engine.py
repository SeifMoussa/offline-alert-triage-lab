from __future__ import annotations

from tests.test_alert_models import valid_alert_payload

from triage_lab.classification.engine import classify_alert
from triage_lab.classification.rules import load_rules
from triage_lab.explanations.engine import explain_loaded_alerts, generate_explanation
from triage_lab.mitre.loader import load_mitre_mapping
from triage_lab.mitre.mapping import map_alert_to_mitre
from triage_lab.models.alert import AlertRecord
from triage_lab.triage.playbooks import load_playbooks


def make_alert(**updates: object) -> AlertRecord:
    payload = valid_alert_payload()
    payload.update(updates)
    return AlertRecord.model_validate(payload)


def generate_for_alert(alert: AlertRecord):
    classification = classify_alert(alert, load_rules())
    mitre = map_alert_to_mitre(
        alert,
        load_mitre_mapping(),
        final_severity=classification.final_severity.value,
    )
    return generate_explanation(alert, classification, mitre, load_playbooks())


def test_template_selection_by_event_type_and_severity() -> None:
    explanation = generate_for_alert(make_alert(event_type="brute_force", count=100))

    assert explanation.template_id == "TPL-BRUTE-FORCE"
    assert explanation.final_severity in {"HIGH", "CRITICAL"}
    assert "authentication failures" in explanation.summary


def test_fallback_template_for_generic_event_type() -> None:
    alert = make_alert(event_type="policy_violation")
    explanation = generate_for_alert(alert)

    assert explanation.template_id == "TPL-GENERIC"
    assert "policy_violation" in explanation.summary


def test_unknown_template_and_mitre_fallback_are_safe() -> None:
    explanation = generate_for_alert(make_alert(event_type="unknown"))

    assert explanation.template_id == "TPL-UNKNOWN"
    assert "No direct MITRE ATT&CK technique mapping" in explanation.mitre_context
    assert explanation.triage.playbook_id == "TRIAGE-UNKNOWN-LOW"


def test_modifiers_are_referenced_correctly() -> None:
    explanation = generate_for_alert(
        make_alert(count=100, dest_port=22, username="test_admin")
    )

    assert "MOD-COUNT-100" in explanation.modifiers_referenced
    assert "MOD-SENSITIVE-DEST-PORT" in explanation.modifiers_referenced
    assert "MOD-PRIVILEGED-USERNAME" in explanation.modifiers_referenced


def test_no_unfilled_placeholders_in_loaded_explanations() -> None:
    payload = explain_loaded_alerts("alerts/sample_alerts.json")

    rendered = str(payload)
    assert "{event_type}" not in rendered
    assert "{severity}" not in rendered
    assert payload["alerts_loaded"] == 22
    assert len(payload["explained_alerts"]) == 22
    assert payload["errors"] == []
