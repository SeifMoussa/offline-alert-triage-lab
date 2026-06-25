from __future__ import annotations

import json
from pathlib import Path

from tests.test_alert_models import valid_alert_payload
from tests.test_classification_engine import make_alert

from triage_lab.classification.engine import (
    classify_alert,
    classify_loaded_alerts,
    classify_result_is_success,
)
from triage_lab.classification.rules import RuleSet, load_rules
from triage_lab.classification.severity import Severity as CompatSeverity
from triage_lab.classification.severity import highest_severity as compat_highest
from triage_lab.explanations.engine import (
    explain_loaded_alerts,
    explanation_result_is_success,
    generate_explanation,
)
from triage_lab.ingestion.inventory import build_inventory
from triage_lab.mitre.loader import load_mitre_mapping
from triage_lab.mitre.mapping import map_alert_to_mitre
from triage_lab.models.alert import AlertRecord
from triage_lab.models.explanation import _first_tactic, _first_technique_id
from triage_lab.models.load_result import LoadResult
from triage_lab.models.parse_error import ParseError
from triage_lab.models.severity import Severity, highest_severity
from triage_lab.models.triage_step import TriageRecommendation, TriageStep
from triage_lab.triage.playbooks import load_playbooks
from triage_lab.triage.selector import select_triage_recommendation


def test_classification_conditions_ignore_invalid_shapes_and_types() -> None:
    ruleset = RuleSet(
        name="edge-rules",
        version=1,
        default_severity=Severity.LOW,
        base_severity={"failed_login": Severity.LOW},
        sensitive_destination_ports=(),
        privileged_usernames=(),
        known_synthetic_bad_ips=(),
        synthetic_marker_patterns=({"name": "marker", "pattern": "TOKEN"},),
        modifier_rules=(
            {"id": "bad-condition", "description": "Ignored", "severity_delta": 1},
            {
                "id": "regex-non-string",
                "description": "Ignored",
                "severity_delta": 1,
                "condition": {
                    "field": "count",
                    "operator": "regex_from_config",
                    "config_key": "synthetic_marker_patterns",
                },
            },
            {
                "id": "unknown-operator",
                "description": "Ignored",
                "severity_delta": 1,
                "condition": {"field": "count", "operator": "nope", "value": 1},
            },
        ),
        override_rules=(),
    )

    result = classify_alert(make_alert(count=3), ruleset)

    assert result.final_severity == Severity.LOW
    assert result.modifiers_applied == []


def test_classification_loaded_alerts_handles_empty_success(tmp_path: Path) -> None:
    empty = tmp_path / "empty.json"
    empty.write_text("[]", encoding="utf-8")

    payload = classify_loaded_alerts(empty)

    assert classify_result_is_success(payload)
    assert payload["classified_alerts"] == []
    assert payload["highest_severity"] is None
    assert payload["severity_counts"] == {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }


def test_classification_loaded_alerts_reports_bad_config(tmp_path: Path) -> None:
    alert_file = tmp_path / "alert.json"
    alert_file.write_text(json.dumps([valid_alert_payload()]), encoding="utf-8")
    bad_config = tmp_path / "rules.yaml"
    bad_config.write_text("[]", encoding="utf-8")

    payload = classify_loaded_alerts(alert_file, bad_config)

    assert not classify_result_is_success(payload)
    assert payload["ruleset"] == {"name": None, "version": None}
    assert payload["errors"][0]["error_type"] == "rules_config_error"


def test_explanation_for_unknown_event_uses_fallbacks() -> None:
    alert = make_alert().model_copy(update={"event_type": "future_event"})
    classification = classify_alert(
        alert,
        RuleSet(
            name="edge-rules",
            version=1,
            default_severity=Severity.MEDIUM,
            base_severity={},
            sensitive_destination_ports=(),
            privileged_usernames=(),
            known_synthetic_bad_ips=(),
            synthetic_marker_patterns=(),
            modifier_rules=(),
            override_rules=(),
        ),
    )
    mitre_mapping = map_alert_to_mitre(
        alert,
        load_mitre_mapping(),
        final_severity=classification.final_severity.value,
    )

    explanation = generate_explanation(
        alert,
        classification,
        mitre_mapping,
        load_playbooks(),
    )
    rendered = json.dumps(explanation.to_safe_dict())

    assert explanation.template_id == "TPL-GENERIC"
    assert explanation.triage.playbook_id == "TRIAGE-GLOBAL-FALLBACK"
    assert "{event_type}" not in rendered
    assert "{severity}" not in rendered
    assert "SYNTHETIC_" not in rendered


def test_explain_loaded_alerts_reports_each_config_error(tmp_path: Path) -> None:
    alert_file = tmp_path / "alert.json"
    alert_file.write_text(json.dumps([valid_alert_payload()]), encoding="utf-8")
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("[]", encoding="utf-8")

    assert (
        explain_loaded_alerts(alert_file, rules_config_path=bad_yaml)["errors"][0][
            "error_type"
        ]
        == "rules_config_error"
    )
    assert (
        explain_loaded_alerts(alert_file, mitre_config_path=bad_yaml)["errors"][0][
            "error_type"
        ]
        == "mitre_config_error"
    )
    assert (
        explain_loaded_alerts(alert_file, triage_config_path=bad_yaml)["errors"][0][
            "error_type"
        ]
        == "playbook_config_error"
    )


def test_explain_loaded_alerts_success_helpers_and_empty_counts(tmp_path: Path) -> None:
    empty = tmp_path / "empty.json"
    empty.write_text("[]", encoding="utf-8")

    payload = explain_loaded_alerts(empty)

    assert explanation_result_is_success(payload)
    assert payload["severity_counts"]["CRITICAL"] == 0
    assert payload["tactics_observed"] == []


def test_load_result_empty_dates_and_validation_dict_are_safe() -> None:
    result = LoadResult(
        input_path="synthetic.json",
        files_seen=1,
        records_seen=1,
        errors=[
            ParseError(
                file_path="synthetic.json",
                record_index=0,
                field_path="raw_message",
                message="contains SYNTHETIC_TOKEN_MARKER token=abc",
                error_type="validation_error",
            )
        ],
    )

    inventory = result.to_inventory_dict()
    validation = result.to_validation_dict()
    rendered = json.dumps({"inventory": inventory, "validation": validation})

    assert inventory["earliest_timestamp"] is None
    assert inventory["latest_timestamp"] is None
    assert validation["valid"] is False
    assert "validation_error" in rendered


def test_model_optional_helpers_return_none_for_unmapped_text() -> None:
    assert _first_technique_id("No direct MITRE ATT&CK technique mapping.") is None
    assert _first_technique_id("This maps to technique abc under Test.") is None
    assert _first_tactic("No direct MITRE ATT&CK technique mapping.") is None
    assert highest_severity([]) is None
    assert (
        compat_highest([CompatSeverity.LOW, CompatSeverity.HIGH]) == CompatSeverity.HIGH
    )


def test_triage_selector_uses_event_specific_and_global_fallbacks() -> None:
    config = load_playbooks()
    classification = classify_alert(
        make_alert(event_type="policy_violation"), load_rules()
    )
    event_fallback = select_triage_recommendation(
        make_alert(event_type="policy_violation"),
        classification,
        config,
    )
    global_fallback = select_triage_recommendation(
        make_alert().model_copy(update={"event_type": "future_event"}),
        classification.model_copy(update={"event_type": "future_event"}),
        config,
    )

    assert event_fallback.playbook_id == "TRIAGE-POLICY-LOW"
    assert global_fallback.playbook_id == "TRIAGE-GLOBAL-FALLBACK"


def test_triage_recommendation_safe_dict_includes_optional_step_fields() -> None:
    recommendation = TriageRecommendation(
        alert_id="alert-1",
        event_type="unknown",
        severity="LOW",
        playbook_id="PB-1",
        playbook_source="unit:v1",
        steps=[
            TriageStep(
                step_id="STEP-1",
                title="Review synthetic alert",
                description="Review only local synthetic evidence.",
                safety_note="No network calls.",
                order=1,
            )
        ],
        suggested_priority="P4",
        escalation_required=False,
    )

    safe = recommendation.to_safe_dict()

    assert safe["steps"][0]["step_id"] == "STEP-1"
    assert safe["steps"][0]["safety_note"] == "No network calls."


def test_build_inventory_empty_directory_and_unsupported_extension(
    tmp_path: Path,
) -> None:
    (tmp_path / "notes.txt").write_text("not an alert", encoding="utf-8")

    result = build_inventory(tmp_path)

    assert result.files_seen == 1
    assert result.files_loaded == 0
    assert result.unsupported_files == 1
    assert result.valid


def test_alert_optional_fields_serialize_as_none() -> None:
    payload = valid_alert_payload()
    payload["source_port"] = None
    payload["dest_port"] = None
    payload["username"] = None
    payload["hostname"] = None
    payload["count"] = None

    alert = AlertRecord.model_validate(payload)
    safe = alert.to_safe_dict()

    assert safe["source_port"] is None
    assert safe["hostname"] is None
