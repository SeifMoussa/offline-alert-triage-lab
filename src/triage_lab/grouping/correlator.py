"""Deterministic alert correlation rules."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from triage_lab.grouping.config import GroupingConfig
from triage_lab.models.alert import AlertRecord
from triage_lab.models.classification import ClassificationResult
from triage_lab.models.explanation import AnalystExplanation
from triage_lab.models.incident import (
    CorrelationReason,
    Incident,
    priority_for_severity,
)
from triage_lab.models.mitre import MitreMappingResult
from triage_lab.models.severity import Severity, highest_severity


@dataclass(frozen=True)
class AlertGroupingContext:
    """Alert plus deterministic pipeline outputs used for grouping."""

    alert: AlertRecord
    classification: ClassificationResult
    mitre_mapping: MitreMappingResult
    explanation: AnalystExplanation


@dataclass(frozen=True)
class CorrelationEdge:
    """One deterministic correlation edge between two alerts."""

    left_alert_id: str
    right_alert_id: str
    reason: CorrelationReason


def correlate_alerts(
    contexts: list[AlertGroupingContext],
    config: GroupingConfig,
) -> tuple[list[Incident], list[str]]:
    """Apply grouping rules and return incidents plus ungrouped alert IDs."""
    sorted_contexts = sorted(contexts, key=lambda item: item.alert.alert_id)
    edges = _build_edges(sorted_contexts, config)
    components = _connected_components(sorted_contexts, edges)
    incidents: list[Incident] = []
    ungrouped: list[str] = []

    for component_ids in components:
        if len(component_ids) < 2:
            ungrouped.extend(component_ids)
            continue
        component_contexts = [
            context
            for context in sorted_contexts
            if context.alert.alert_id in set(component_ids)
        ]
        component_reasons = _reasons_for_component(component_ids, edges)
        incidents.append(_build_incident(component_contexts, component_reasons))

    sorted_incidents = sorted(
        incidents,
        key=lambda incident: (
            -incident.severity.rank,
            incident.timeline_start,
            incident.alert_ids[0],
        ),
    )
    numbered = [
        incident.model_copy(update={"incident_id": f"INC-{index:04d}"})
        for index, incident in enumerate(sorted_incidents, start=1)
    ]
    return numbered, sorted(ungrouped)


def _build_edges(
    contexts: list[AlertGroupingContext],
    config: GroupingConfig,
) -> list[CorrelationEdge]:
    edges: list[CorrelationEdge] = []
    enabled_rules = [rule for rule in config.rules if rule["enabled"]]
    for rule in enabled_rules:
        match_type = rule["match_type"]
        if match_type == "same_field_time_window":
            edges.extend(_same_field_time_window(contexts, rule))
        elif match_type == "same_field_with_severity":
            edges.extend(_same_field_with_severity(contexts, rule))
        elif match_type == "same_mitre_tactic_time_window":
            edges.extend(_same_mitre_tactic_time_window(contexts, rule))
        elif match_type == "event_chain":
            edges.extend(_event_chain(contexts, rule))
        elif match_type == "multi_stage_same_host":
            edges.extend(_multi_stage_same_host(contexts, rule))
    return sorted(edges, key=lambda edge: (edge.left_alert_id, edge.right_alert_id))


def _same_field_time_window(
    contexts: list[AlertGroupingContext], rule: dict[str, Any]
) -> list[CorrelationEdge]:
    field = str(rule["field"])
    edges = []
    for left, right in _pairs(contexts):
        if _same_alert_field(left.alert, right.alert, field) and _within_minutes(
            left.alert.timestamp, right.alert.timestamp, rule
        ):
            edges.append(_edge(left, right, rule, [field]))
    return edges


def _same_field_with_severity(
    contexts: list[AlertGroupingContext], rule: dict[str, Any]
) -> list[CorrelationEdge]:
    field = str(rule["field"])
    required = Severity(str(rule["required_severity"]))
    edges = []
    for left, right in _pairs(contexts):
        if _same_alert_field(left.alert, right.alert, field):
            if not _within_minutes(left.alert.timestamp, right.alert.timestamp, rule):
                continue
            if (
                left.classification.final_severity.rank >= required.rank
                or right.classification.final_severity.rank >= required.rank
            ):
                edges.append(_edge(left, right, rule, [field, "final_severity"]))
    return edges


def _same_mitre_tactic_time_window(
    contexts: list[AlertGroupingContext], rule: dict[str, Any]
) -> list[CorrelationEdge]:
    edges = []
    for left, right in _pairs(contexts):
        if _shared_tactics(left, right) and _within_minutes(
            left.alert.timestamp, right.alert.timestamp, rule
        ):
            edges.append(_edge(left, right, rule, ["mitre_tactic"]))
    return edges


def _event_chain(
    contexts: list[AlertGroupingContext], rule: dict[str, Any]
) -> list[CorrelationEdge]:
    precursor_types = set(rule["precursor_event_types"])
    followup_types = set(rule["followup_event_types"])
    match_fields = list(rule["match_fields"])
    edges = []
    for left, right in _pairs(contexts):
        if _chain_matches(left, right, precursor_types, followup_types, rule):
            matched = [
                field
                for field in match_fields
                if _field_value(left.alert, field)
                and _field_value(left.alert, field) == _field_value(right.alert, field)
            ]
            if matched:
                edges.append(_edge(left, right, rule, matched + ["event_type"]))
    return edges


def _multi_stage_same_host(
    contexts: list[AlertGroupingContext], rule: dict[str, Any]
) -> list[CorrelationEdge]:
    field = str(rule["field"])
    edges = []
    for left, right in _pairs(contexts):
        if _same_alert_field(left.alert, right.alert, field):
            if left.alert.event_type == right.alert.event_type:
                continue
            if _within_minutes(left.alert.timestamp, right.alert.timestamp, rule):
                edges.append(_edge(left, right, rule, [field, "event_type"]))
    return edges


def _chain_matches(
    left: AlertGroupingContext,
    right: AlertGroupingContext,
    precursor_types: set[str],
    followup_types: set[str],
    rule: dict[str, Any],
) -> bool:
    first, second = sorted([left, right], key=lambda item: item.alert.timestamp)
    if first.alert.event_type not in precursor_types:
        return False
    if second.alert.event_type not in followup_types:
        return False
    delta_minutes = (
        second.alert.timestamp - first.alert.timestamp
    ).total_seconds() / 60
    return 0 <= delta_minutes <= int(rule["time_window_minutes"])


def _pairs(
    contexts: list[AlertGroupingContext],
) -> list[tuple[AlertGroupingContext, AlertGroupingContext]]:
    return [
        (contexts[left], contexts[right])
        for left in range(len(contexts))
        for right in range(left + 1, len(contexts))
    ]


def _edge(
    left: AlertGroupingContext,
    right: AlertGroupingContext,
    rule: dict[str, Any],
    matched_fields: list[str],
) -> CorrelationEdge:
    alert_ids = sorted([left.alert.alert_id, right.alert.alert_id])
    return CorrelationEdge(
        left_alert_id=alert_ids[0],
        right_alert_id=alert_ids[1],
        reason=CorrelationReason(
            rule_id=rule["id"],
            description=rule["description"],
            matched_fields=sorted(set(matched_fields)),
            time_window_minutes=int(rule["time_window_minutes"]),
            contributing_alert_ids=alert_ids,
        ),
    )


def _connected_components(
    contexts: list[AlertGroupingContext],
    edges: list[CorrelationEdge],
) -> list[list[str]]:
    parent = {context.alert.alert_id: context.alert.alert_id for context in contexts}

    def find(alert_id: str) -> str:
        while parent[alert_id] != alert_id:
            parent[alert_id] = parent[parent[alert_id]]
            alert_id = parent[alert_id]
        return alert_id

    def union(left: str, right: str) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root == right_root:
            return
        parent[max(left_root, right_root)] = min(left_root, right_root)

    for edge in edges:
        union(edge.left_alert_id, edge.right_alert_id)

    components: dict[str, list[str]] = {}
    for alert_id in sorted(parent):
        components.setdefault(find(alert_id), []).append(alert_id)
    return [sorted(value) for value in components.values()]


def _reasons_for_component(
    component_ids: list[str],
    edges: list[CorrelationEdge],
) -> list[CorrelationReason]:
    component = set(component_ids)
    grouped: dict[tuple[str, tuple[str, ...], int], set[str]] = {}
    descriptions: dict[tuple[str, tuple[str, ...], int], str] = {}
    for edge in edges:
        if {edge.left_alert_id, edge.right_alert_id}.issubset(component):
            key = (
                edge.reason.rule_id,
                tuple(edge.reason.matched_fields),
                edge.reason.time_window_minutes,
            )
            grouped.setdefault(key, set()).update(edge.reason.contributing_alert_ids)
            descriptions[key] = edge.reason.description
    return [
        CorrelationReason(
            rule_id=rule_id,
            description=descriptions[key],
            matched_fields=list(fields),
            time_window_minutes=window,
            contributing_alert_ids=sorted(alert_ids),
        )
        for key, alert_ids in sorted(grouped.items())
        for rule_id, fields, window in [key]
    ]


def _build_incident(
    contexts: list[AlertGroupingContext],
    reasons: list[CorrelationReason],
) -> Incident:
    ordered = sorted(
        contexts,
        key=lambda item: (item.alert.timestamp, item.alert.alert_id),
    )
    severities = [item.classification.final_severity for item in ordered]
    severity = highest_severity(severities) or Severity.LOW
    alert_ids = sorted(item.alert.alert_id for item in ordered)
    event_types = sorted({item.alert.event_type for item in ordered})
    start = min(item.alert.timestamp for item in ordered).isoformat()
    end = max(item.alert.timestamp for item in ordered).isoformat()
    tactics = sorted(
        {
            technique.tactic
            for item in ordered
            for technique in item.mitre_mapping.techniques
            if technique.technique_id is not None
        }
    )
    techniques = sorted(
        {
            technique.technique_id
            for item in ordered
            for technique in item.mitre_mapping.techniques
            if technique.technique_id is not None
        }
    )
    return Incident(
        incident_id="INC-0000",
        title=f"{severity.value} synthetic incident with {len(alert_ids)} alerts",
        severity=severity,
        suggested_priority=priority_for_severity(severity),
        alert_ids=alert_ids,
        event_types=event_types,
        timeline_start=start,
        timeline_end=end,
        source_ips_redacted=_redacted_values(
            [item.alert.source_ip for item in ordered], "source_ip"
        ),
        usernames_redacted=_redacted_values(
            [item.alert.username for item in ordered if item.alert.username],
            "username",
        ),
        hostnames=sorted(
            {item.alert.hostname for item in ordered if item.alert.hostname}
        ),
        mitre_tactics_observed=tactics,
        mitre_techniques_observed=techniques,
        correlation_reasons=reasons,
        member_count=len(alert_ids),
        summary=_summary(severity, len(alert_ids), event_types, start, end),
    )


def _summary(
    severity: Severity,
    member_count: int,
    event_types: list[str],
    start: str,
    end: str,
) -> str:
    joined_events = ", ".join(event_types)
    return (
        f"{severity.value} synthetic incident correlating {member_count} alert(s) "
        f"across event type(s): {joined_events}. Timeline runs from {start} to {end}."
    )


def _field_value(alert: AlertRecord, field: str) -> str | None:
    value = getattr(alert, field, None)
    return str(value) if value is not None else None


def _same_alert_field(left: AlertRecord, right: AlertRecord, field: str) -> bool:
    left_value = _field_value(left, field)
    return bool(left_value) and left_value == _field_value(right, field)


def _within_minutes(left: datetime, right: datetime, rule: dict[str, Any]) -> bool:
    delta = abs((right - left).total_seconds()) / 60
    return delta <= int(rule["time_window_minutes"])


def _shared_tactics(
    left: AlertGroupingContext, right: AlertGroupingContext
) -> set[str]:
    left_tactics = {
        technique.tactic
        for technique in left.mitre_mapping.techniques
        if technique.technique_id is not None
    }
    right_tactics = {
        technique.tactic
        for technique in right.mitre_mapping.techniques
        if technique.technique_id is not None
    }
    return left_tactics & right_tactics


def _redacted_values(values: list[str], label: str) -> list[str]:
    unique = sorted(set(values))
    return [f"[REDACTED:{label}:{index}]" for index, _ in enumerate(unique, start=1)]
