from __future__ import annotations

from tests.test_alert_models import valid_alert_payload

from triage_lab.classification.engine import classify_alert
from triage_lab.classification.rules import load_rules
from triage_lab.models.alert import AlertRecord
from triage_lab.triage.playbooks import load_playbooks
from triage_lab.triage.selector import select_triage_recommendation


def make_alert(**updates: object) -> AlertRecord:
    payload = valid_alert_payload()
    payload.update(updates)
    return AlertRecord.model_validate(payload)


def test_event_type_and_severity_playbook_selected() -> None:
    alert = make_alert(event_type="brute_force", count=100)
    classification = classify_alert(alert, load_rules())

    recommendation = select_triage_recommendation(
        alert,
        classification,
        load_playbooks(),
    )

    assert recommendation.playbook_id == "TRIAGE-BRUTE-HIGH"
    assert recommendation.escalation_required is True
    assert recommendation.suggested_priority in {"urgent", "immediate"}


def test_event_fallback_playbook_selected_for_unknown() -> None:
    alert = make_alert(event_type="unknown")
    classification = classify_alert(alert, load_rules())

    recommendation = select_triage_recommendation(
        alert,
        classification,
        load_playbooks(),
    )

    assert recommendation.playbook_id == "TRIAGE-UNKNOWN-LOW"
    assert (
        recommendation.steps[0].title == "Preserve unknown synthetic alert for review"
    )


def test_global_fallback_playbook_selected_for_future_event() -> None:
    alert = make_alert(event_type="unknown").model_copy(update={"event_type": "future"})
    classification = classify_alert(alert, load_rules())

    recommendation = select_triage_recommendation(
        alert,
        classification,
        load_playbooks(),
    )

    assert recommendation.playbook_id == "TRIAGE-GLOBAL-FALLBACK"
