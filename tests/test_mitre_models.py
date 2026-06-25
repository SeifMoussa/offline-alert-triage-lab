from __future__ import annotations

from triage_lab.models.mitre import MitreMappingResult, MitreTechnique


def test_mitre_mapping_result_safe_dict_flattens_first_technique() -> None:
    technique = MitreTechnique(
        tactic="Credential Access",
        technique_id="T1110",
        technique_name="Brute Force",
        mitre_url="https://attack.mitre.org/techniques/T1110/",
        mapping_source="local:v1",
        confidence="high",
    )
    result = MitreMappingResult(
        alert_id="alert-1",
        event_type="brute_force",
        final_severity="HIGH",
        techniques=[technique],
        mapping_found=True,
        fallback_used=False,
        reason="Mapped locally.",
    )

    payload = result.to_safe_dict()

    assert payload["mitre_tactic"] == "Credential Access"
    assert payload["mitre_technique_id"] == "T1110"
    assert payload["mitre_url"] == "https://attack.mitre.org/techniques/T1110/"
