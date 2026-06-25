from __future__ import annotations

from triage_lab.models.explanation import AnalystExplanation
from triage_lab.models.triage_step import TriageRecommendation, TriageStep


def test_explanation_model_creation_and_safe_dict() -> None:
    step = TriageStep(
        step_id="TRIAGE-TEST",
        title="Review local context",
        description="Review synthetic local alert context.",
        safety_note="Stay offline.",
        order=1,
    )
    triage = TriageRecommendation(
        alert_id="alert-1",
        event_type="brute_force",
        severity="HIGH",
        steps=[step],
        escalation_required=True,
        suggested_priority="urgent",
        playbook_id="TRIAGE-TEST",
        playbook_source="local:v1",
    )
    mitre_context = (
        "This maps to MITRE ATT&CK technique T1110 Brute Force under Credential Access."
    )
    explanation = AnalystExplanation(
        alert_id="alert-1",
        event_type="brute_force",
        final_severity="HIGH",
        summary="Synthetic authentication failures were reviewed.",
        reasoning=mitre_context,
        evidence_points=["Final severity is HIGH."],
        mitre_context=mitre_context,
        modifiers_referenced=["MOD-COUNT-100"],
        template_id="TPL-BRUTE-FORCE",
        triage=triage,
    )

    payload = explanation.to_safe_dict()

    assert payload["generated_by"] == "deterministic_template_engine"
    assert payload["mitre_technique_id"] == "T1110"
    assert payload["mitre_tactic"] == "Credential Access"
    assert payload["playbook_id"] == "TRIAGE-TEST"
