"""Command-line interface for local synthetic alert validation."""

from __future__ import annotations

import argparse
import json
from typing import Any

from triage_lab import __version__
from triage_lab.classification.engine import (
    classify_loaded_alerts,
    classify_result_is_success,
)
from triage_lab.explanations.engine import (
    explain_loaded_alerts,
    explanation_result_is_success,
)
from triage_lab.grouping.engine import (
    group_loaded_alerts,
    grouping_result_is_success,
)
from triage_lab.ingestion.inventory import build_inventory
from triage_lab.mitre.mapping import (
    map_loaded_alerts_to_mitre,
    mitre_mapping_is_success,
)
from triage_lab.redaction.serializer import serialize_for_output
from triage_lab.reporting.pipeline import build_security_report
from triage_lab.reporting.writer import write_reports
from triage_lab.safety import PROJECT_DESCRIPTION, safety_summary_text


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser."""
    parser = argparse.ArgumentParser(
        prog="triage-lab",
        description=PROJECT_DESCRIPTION,
        epilog=safety_summary_text(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"triage-lab {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command")

    inventory_parser = subparsers.add_parser(
        "inventory",
        help="Inventory local synthetic JSON alert files.",
    )
    add_input_and_format_arguments(inventory_parser)

    validate_parser = subparsers.add_parser(
        "validate-alerts",
        help="Validate local synthetic JSON alert files.",
    )
    add_input_and_format_arguments(validate_parser)

    classify_parser = subparsers.add_parser(
        "classify-alerts",
        help="Classify local synthetic JSON alerts with deterministic rules.",
    )
    add_input_and_format_arguments(classify_parser)
    classify_parser.add_argument(
        "--config",
        default=None,
        help="Optional local YAML rules config. Defaults to config/rules.yaml.",
    )

    mitre_parser = subparsers.add_parser(
        "map-mitre",
        help="Map local synthetic JSON alerts to static local MITRE entries.",
    )
    add_input_and_format_arguments(mitre_parser)
    mitre_parser.add_argument(
        "--config",
        default=None,
        help=(
            "Optional local YAML MITRE mapping config. "
            "Defaults to config/mitre_mapping.yaml."
        ),
    )

    explain_parser = subparsers.add_parser(
        "explain-alerts",
        help="Generate deterministic analyst-style explanations and triage steps.",
    )
    add_input_and_format_arguments(explain_parser)
    explain_parser.add_argument(
        "--rules",
        default=None,
        help="Optional local YAML rules config. Defaults to config/rules.yaml.",
    )
    explain_parser.add_argument(
        "--mitre-config",
        default=None,
        help=(
            "Optional local YAML MITRE mapping config. "
            "Defaults to config/mitre_mapping.yaml."
        ),
    )
    explain_parser.add_argument(
        "--triage-config",
        default=None,
        help=(
            "Optional local YAML triage playbook config. "
            "Defaults to config/triage_steps.yaml."
        ),
    )

    group_parser = subparsers.add_parser(
        "group-incidents",
        help="Group local synthetic alerts into deterministic incidents.",
    )
    add_input_and_format_arguments(group_parser)
    group_parser.add_argument(
        "--rules",
        default=None,
        help="Optional local YAML rules config. Defaults to config/rules.yaml.",
    )
    group_parser.add_argument(
        "--mitre-config",
        default=None,
        help=(
            "Optional local YAML MITRE mapping config. "
            "Defaults to config/mitre_mapping.yaml."
        ),
    )
    group_parser.add_argument(
        "--triage-config",
        default=None,
        help=(
            "Optional local YAML triage playbook config. "
            "Defaults to config/triage_steps.yaml."
        ),
    )
    group_parser.add_argument(
        "--grouping-config",
        default=None,
        help=(
            "Optional local YAML grouping config. "
            "Defaults to config/grouping_rules.yaml."
        ),
    )

    redact_parser = subparsers.add_parser(
        "redact-check",
        help="Check that grouped synthetic alert output is report-safe.",
    )
    add_input_and_format_arguments(redact_parser)

    report_parser = subparsers.add_parser(
        "report",
        help="Generate deterministic redacted JSON and Markdown reports.",
    )
    report_parser.add_argument("--input", required=True, help="Local alert file.")
    report_parser.add_argument(
        "--output",
        required=True,
        help="Local output directory for report files.",
    )
    report_parser.add_argument(
        "--format",
        choices=("json", "markdown", "both"),
        default="both",
        help="Report format to write.",
    )
    report_parser.add_argument(
        "--rules",
        default=None,
        help="Optional local YAML rules config. Defaults to config/rules.yaml.",
    )
    report_parser.add_argument(
        "--mitre-config",
        default=None,
        help=(
            "Optional local YAML MITRE mapping config. "
            "Defaults to config/mitre_mapping.yaml."
        ),
    )
    report_parser.add_argument(
        "--triage-config",
        default=None,
        help=(
            "Optional local YAML triage playbook config. "
            "Defaults to config/triage_steps.yaml."
        ),
    )
    report_parser.add_argument(
        "--grouping-config",
        default=None,
        help=(
            "Optional local YAML grouping config. "
            "Defaults to config/grouping_rules.yaml."
        ),
    )

    return parser


def add_input_and_format_arguments(parser: argparse.ArgumentParser) -> None:
    """Add common local input/output arguments."""
    parser.add_argument("--input", required=True, help="Local alert file or directory.")
    parser.add_argument(
        "--format",
        choices=("json", "text"),
        default="text",
        help="Output format.",
    )


def main(argv: list[str] | None = None) -> int:
    """Run the CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "inventory":
        result = build_inventory(args.input)
        payload = result.to_inventory_dict()
        print_output(payload, args.format, title="Alert inventory")
        return 0
    if args.command == "validate-alerts":
        result = build_inventory(args.input)
        payload = result.to_validation_dict()
        print_output(payload, args.format, title="Alert validation")
        return 0 if result.valid else 1
    if args.command == "classify-alerts":
        payload = classify_loaded_alerts(args.input, args.config)
        payload = serialize_for_output(payload).payload
        print_output(payload, args.format, title="Alert classification")
        return 0 if classify_result_is_success(payload) else 1
    if args.command == "map-mitre":
        payload = map_loaded_alerts_to_mitre(args.input, args.config)
        payload = serialize_for_output(payload).payload
        print_output(payload, args.format, title="MITRE mapping")
        return 0 if mitre_mapping_is_success(payload) else 1
    if args.command == "explain-alerts":
        payload = explain_loaded_alerts(
            args.input,
            rules_config_path=args.rules,
            mitre_config_path=args.mitre_config,
            triage_config_path=args.triage_config,
        )
        payload = serialize_for_output(payload).payload
        print_output(payload, args.format, title="Alert explanations")
        return 0 if explanation_result_is_success(payload) else 1
    if args.command == "group-incidents":
        payload = group_loaded_alerts(
            args.input,
            rules_config_path=args.rules,
            mitre_config_path=args.mitre_config,
            triage_config_path=args.triage_config,
            grouping_config_path=args.grouping_config,
        )
        payload = serialize_for_output(payload).payload
        print_output(payload, args.format, title="Incident grouping")
        return 0 if grouping_result_is_success(payload) else 1
    if args.command == "redact-check":
        pipeline_payload = group_loaded_alerts(args.input)
        redaction = serialize_for_output(pipeline_payload)
        payload = {
            "input_path": str(args.input),
            "safe_for_output": redaction.safe_for_output,
            "redaction_summary": report_safe_redaction_summary(redaction.summary),
            "prohibited_values_found": sorted(
                {
                    error["error_type"]
                    for error in redaction.validation_errors
                    if error.get("error_type")
                }
            ),
            "validation_errors": redaction.validation_errors,
            "errors": redaction.payload.get("errors", [])
            if isinstance(redaction.payload, dict)
            else [],
        }
        print_output(payload, args.format, title="Redaction safety check")
        if redaction.safe_for_output and grouping_result_is_success(redaction.payload):
            return 0
        return 1
    if args.command == "report":
        try:
            report = build_security_report(
                args.input,
                rules_config_path=args.rules,
                mitre_config_path=args.mitre_config,
                triage_config_path=args.triage_config,
                grouping_config_path=args.grouping_config,
            )
            paths = write_reports(report, args.output, args.format)
        except ValueError as exc:
            payload = {
                "json_report_path": None,
                "markdown_report_path": None,
                "safe_for_output": False,
                "alerts_loaded": 0,
                "incident_count": 0,
                "errors": [
                    {
                        "file_path": str(args.output),
                        "message": str(exc),
                        "error_type": "report_output_error",
                    }
                ],
            }
            print_output(payload, "json", title="Security report")
            return 1
        payload = {
            **paths,
            "safe_for_output": report.summary.safe_for_output,
            "alerts_loaded": report.summary.alerts_loaded,
            "incident_count": report.summary.incident_count,
            "errors": report.errors,
        }
        print_output(payload, "json", title="Security report")
        return 0 if report.summary.safe_for_output and not report.errors else 1
    return 0


def report_safe_redaction_summary(summary) -> dict[str, Any]:
    """Serialize redaction summary without raw-message field names."""
    payload = summary.model_dump(mode="json")
    payload["raw_content_removed"] = payload.pop("raw_messages_removed")
    return payload


def print_output(payload: dict[str, Any], output_format: str, *, title: str) -> None:
    """Print JSON or compact text output."""
    if output_format == "json":
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    print(title)
    print("=" * len(title))
    for key, value in payload.items():
        if key == "errors":
            print(f"errors: {len(value)}")
            for error in value:
                field = (
                    f" field={error['field_path']}" if error.get("field_path") else ""
                )
                record = (
                    f" record={error['record_index']}"
                    if error.get("record_index") is not None
                    else ""
                )
                print(
                    "- "
                    f"{error['error_type']} file={error['file_path']}"
                    f"{record}{field}: {error['message']}"
                )
            continue
        print(f"{key}: {value}")
