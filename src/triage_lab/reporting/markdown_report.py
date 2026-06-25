"""Markdown report rendering."""

from __future__ import annotations

from triage_lab.models.report import SecurityReport


def render_markdown_report(report: SecurityReport) -> str:
    """Render a deterministic analyst-readable Markdown report."""
    data = report.to_safe_dict()
    metadata = data["metadata"]
    summary = data["summary"]
    incidents = data["incidents"]
    explained_alerts = data["explained_alerts"]
    redaction = data["redaction_summary"]
    errors = data["errors"]
    lines = [
        "# Security Alert Triage Report",
        "",
        "## Safety Disclaimer",
        "",
        "This report is generated from synthetic local alert data only. The "
        "pipeline is offline-only, deterministic, rule-based, and does not use "
        "external AI APIs, LLM calls, network calls, external MITRE APIs, or "
        "external threat intelligence.",
        "",
        "## Report Metadata",
        "",
        f"- Generated at: `{metadata['generated_at']}`",
        f"- Project: {metadata['project_name']}",
        f"- Report type: `{metadata['report_type']}`",
        f"- Input path: `{metadata['input_path']}`",
        f"- Tool version: `{metadata['tool_version']}`",
        f"- Redaction policy: `{metadata['redaction_policy']}`",
        f"- Synthetic data only: `{metadata['synthetic_data_only']}`",
        f"- Offline only: `{metadata['offline_only']}`",
        f"- Deterministic AI: `{metadata['deterministic_ai']}`",
        "",
        "## Executive Summary",
        "",
        f"- Alerts loaded: {summary['alerts_loaded']}",
        f"- Malformed records: {summary['malformed_records']}",
        f"- Classified alerts: {summary['classified_alerts']}",
        f"- Explained alerts: {summary['explained_alerts']}",
        f"- Incidents: {summary['incident_count']}",
        f"- Highest alert severity: {summary['highest_alert_severity']}",
        f"- Highest incident severity: {summary['highest_incident_severity']}",
        f"- Safe for output: `{summary['safe_for_output']}`",
        "",
        "## Alert Severity Summary",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    lines.extend(
        f"| {severity} | {count} |"
        for severity, count in summary["severity_counts"].items()
    )
    lines.extend(
        [
            "",
            "## MITRE Mapping Summary",
            "",
            "- Tactics observed: "
            + (_join(summary["tactics_observed"]) or "None observed"),
            "- Techniques observed: "
            + (_join(summary["techniques_observed"]) or "None observed"),
            "",
            "## Incident Summary",
            "",
            "| Incident ID | Severity | Priority | Members | Event Types |",
            "| --- | --- | --- | ---: | --- |",
        ]
    )
    if incidents:
        for incident in incidents:
            lines.append(
                "| "
                + " | ".join(
                    [
                        incident["incident_id"],
                        incident["severity"],
                        incident["suggested_priority"],
                        str(incident["member_count"]),
                        _join(incident["event_types"]),
                    ]
                )
                + " |"
            )
    else:
        lines.append("| None | None | None | 0 | None |")
    lines.extend(["", "## Incident Details", ""])
    for incident in incidents:
        lines.extend(
            [
                f"### {incident['incident_id']}",
                "",
                f"- Title: {incident['title']}",
                f"- Timeline: `{incident['timeline_start']}` to "
                f"`{incident['timeline_end']}`",
                f"- Hostnames: {_join(incident['hostnames']) or 'None'}",
                f"- MITRE tactics: "
                f"{_join(incident['mitre_tactics_observed']) or 'None'}",
                f"- MITRE techniques: "
                f"{_join(incident['mitre_techniques_observed']) or 'None'}",
                f"- Summary: {incident['summary']}",
                "",
                "Correlation reasons:",
            ]
        )
        for reason in incident["correlation_reasons"]:
            lines.append(
                f"- `{reason['rule_id']}` matched "
                f"{_join(reason['matched_fields'])} for "
                f"{_join(reason['contributing_alert_ids'])}."
            )
        lines.append("")
    lines.extend(["## Explained Alert Summaries", ""])
    for explanation in explained_alerts:
        lines.extend(
            [
                f"### {explanation['alert_id']}",
                "",
                f"- Event type: `{explanation['event_type']}`",
                f"- Final severity: `{explanation['final_severity']}`",
                f"- MITRE technique: `{explanation['mitre_technique_id'] or 'None'}`",
                f"- MITRE tactic: `{explanation['mitre_tactic'] or 'None'}`",
                f"- Template: `{explanation['template_id']}`",
                f"- Playbook: `{explanation['playbook_id']}`",
                f"- Summary: {explanation['summary']}",
                "Triage recommendations:",
            ]
        )
        for step in explanation["triage_steps"]:
            lines.append(
                f"- `{step['step_id']}` {step['title']}: {step['description']}"
            )
        lines.append("")
    lines.extend(
        [
            "## Redaction Summary",
            "",
            f"- Fields redacted: {redaction['fields_redacted']}",
            f"- Markers redacted: {redaction['markers_redacted']}",
            f"- IP values redacted: {redaction['ip_values_redacted']}",
            f"- Usernames redacted: {redaction['usernames_redacted']}",
            "- Credential patterns redacted: "
            f"{redaction['credential_patterns_redacted']}",
            f"- Raw content removed: {redaction['raw_content_removed']}",
            f"- Redaction applied: `{redaction['redaction_applied']}`",
            f"- Redaction policy: `{redaction['redaction_policy']}`",
            "",
            "## Errors And Malformed Records",
            "",
            f"- Error count: {len(errors)}",
        ]
    )
    for error in errors:
        lines.append(
            f"- `{error.get('error_type')}` in `{error.get('file_path')}`: "
            f"{error.get('message')}"
        )
    lines.extend(
        [
            "",
            "## Limitations",
            "",
            "- This report uses synthetic lab data only.",
            "- The AI-assisted behavior is deterministic rule-based logic.",
            "- The report does not perform live scanning, enrichment, network "
            "calls, external MITRE API calls, external threat intelligence, "
            "LLM calls, or external AI API calls.",
            "- Final interpretation should stay within the offline lab scenario.",
            "",
        ]
    )
    return "\n".join(lines)


def _join(values: list[str]) -> str:
    return ", ".join(str(value) for value in values)
