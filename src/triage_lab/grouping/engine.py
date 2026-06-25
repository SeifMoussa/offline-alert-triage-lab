"""Run deterministic incident grouping over local synthetic alerts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from triage_lab.classification.engine import classify_alert
from triage_lab.classification.rules import RuleConfigError, load_rules
from triage_lab.explanations.engine import generate_explanation
from triage_lab.grouping.config import GroupingConfigError, load_grouping_config
from triage_lab.grouping.correlator import AlertGroupingContext, correlate_alerts
from triage_lab.grouping.summary import highest_incident_severity
from triage_lab.ingestion.inventory import build_inventory
from triage_lab.mitre.loader import MitreConfigError, load_mitre_mapping
from triage_lab.mitre.mapping import map_alert_to_mitre
from triage_lab.models.grouping import GroupingResult
from triage_lab.models.parse_error import ParseError
from triage_lab.triage.playbooks import PlaybookConfigError, load_playbooks


def group_loaded_alerts(
    input_path: str | Path,
    rules_config_path: str | Path | None = None,
    mitre_config_path: str | Path | None = None,
    triage_config_path: str | Path | None = None,
    grouping_config_path: str | Path | None = None,
) -> dict[str, Any]:
    """Run ingest -> classify -> MITRE -> explain -> group incidents."""
    load_result = build_inventory(input_path)
    errors = list(load_result.errors)
    incidents = []
    ungrouped_alert_ids: list[str] = []

    try:
        ruleset = load_rules(rules_config_path)
        mitre_config = load_mitre_mapping(mitre_config_path)
        playbook_config = load_playbooks(triage_config_path)
        grouping_config = load_grouping_config(grouping_config_path)
    except RuleConfigError as exc:
        errors.append(
            _config_error("config/rules.yaml", str(exc), "rules_config_error")
        )
    except MitreConfigError as exc:
        errors.append(
            _config_error(
                str(mitre_config_path or "config/mitre_mapping.yaml"),
                str(exc),
                "mitre_config_error",
            )
        )
    except PlaybookConfigError as exc:
        errors.append(
            _config_error(
                str(triage_config_path or "config/triage_steps.yaml"),
                str(exc),
                "playbook_config_error",
            )
        )
    except GroupingConfigError as exc:
        errors.append(
            _config_error(
                str(grouping_config_path or "config/grouping_rules.yaml"),
                str(exc),
                "grouping_config_error",
            )
        )
    else:
        contexts = []
        for alert in load_result.alerts:
            classification = classify_alert(alert, ruleset)
            mitre_mapping = map_alert_to_mitre(
                alert,
                mitre_config,
                final_severity=classification.final_severity.value,
            )
            explanation = generate_explanation(
                alert,
                classification,
                mitre_mapping,
                playbook_config,
            )
            contexts.append(
                AlertGroupingContext(
                    alert=alert,
                    classification=classification,
                    mitre_mapping=mitre_mapping,
                    explanation=explanation,
                )
            )
        incidents, ungrouped_alert_ids = correlate_alerts(contexts, grouping_config)

    highest = highest_incident_severity(incidents)
    result = GroupingResult(
        incidents=incidents,
        ungrouped_alert_ids=ungrouped_alert_ids,
        incident_count=len(incidents),
        grouped_alert_count=sum(incident.member_count for incident in incidents),
        ungrouped_alert_count=len(ungrouped_alert_ids),
        highest_incident_severity=highest,
        errors=[error.model_dump(mode="json") for error in errors],
    )
    payload = result.to_safe_dict()
    payload.update(
        {
            "input_path": str(input_path),
            "alerts_loaded": load_result.alerts_loaded,
            "malformed_records": load_result.malformed_records,
        }
    )
    return {
        "input_path": payload["input_path"],
        "alerts_loaded": payload["alerts_loaded"],
        "malformed_records": payload["malformed_records"],
        "incident_count": payload["incident_count"],
        "grouped_alert_count": payload["grouped_alert_count"],
        "ungrouped_alert_count": payload["ungrouped_alert_count"],
        "highest_incident_severity": payload["highest_incident_severity"],
        "incidents": payload["incidents"],
        "ungrouped_alert_ids": payload["ungrouped_alert_ids"],
        "errors": payload["errors"],
    }


def grouping_result_is_success(payload: dict[str, Any]) -> bool:
    """Return true when grouping payload has no errors."""
    return not payload["errors"]


def _config_error(file_path: str, message: str, error_type: str) -> ParseError:
    return ParseError(file_path=file_path, message=message, error_type=error_type)
