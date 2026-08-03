"""Load a local directory of historical triage report runs for trend analysis."""

from __future__ import annotations

import json
from pathlib import Path

from triage_lab.ingestion.validators import validate_local_input_path
from triage_lab.models.parse_error import ParseError
from triage_lab.models.trend import RunSnapshot
from triage_lab.reporting.writer import JSON_REPORT_FILENAME
from triage_lab.trend_analytics.outcomes import (
    OUTCOMES_FILENAME,
    TriageOutcomeError,
    load_triage_outcomes,
)


class TrendHistoryError(ValueError):
    """Raised when a local trend history directory path is invalid."""


def load_run_history(
    history_dir: str | Path,
) -> tuple[list[RunSnapshot], list[ParseError]]:
    """Load one RunSnapshot per local run subdirectory.

    Each run subdirectory is expected to hold the JSON report written by the
    existing ``report`` command (``security_alert_triage_report.json``) and,
    optionally, a local ``triage_outcomes.json`` disposition file. Runs with
    missing or invalid report data are skipped and recorded as structured
    errors rather than failing the whole history load.
    """
    root = _validate_history_dir(history_dir)
    errors: list[ParseError] = []
    snapshots: list[RunSnapshot] = []

    if not root.is_dir():
        errors.append(
            ParseError(
                file_path=str(root),
                message="history directory does not exist",
                error_type="history_dir_missing",
            )
        )
        return snapshots, errors

    for run_dir in sorted(path for path in root.iterdir() if path.is_dir()):
        report_path = run_dir / JSON_REPORT_FILENAME
        if not report_path.is_file():
            errors.append(
                ParseError(
                    file_path=str(report_path),
                    message=(
                        "run directory is missing a "
                        f"{JSON_REPORT_FILENAME} report file"
                    ),
                    error_type="run_report_missing",
                )
            )
            continue

        try:
            report_payload = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(
                ParseError(
                    file_path=str(report_path),
                    message=f"unable to read run report: {exc}",
                    error_type="run_report_unreadable",
                )
            )
            continue

        snapshot = _build_snapshot(run_dir.name, report_payload, run_dir, errors)
        if snapshot is not None:
            snapshots.append(snapshot)

    return snapshots, errors


def _validate_history_dir(history_dir: str | Path) -> Path:
    try:
        return validate_local_input_path(str(history_dir))
    except ValueError as exc:
        raise TrendHistoryError(f"invalid history directory: {exc}") from exc


def _build_snapshot(
    run_id: str,
    report_payload: object,
    run_dir: Path,
    errors: list[ParseError],
) -> RunSnapshot | None:
    try:
        metadata = report_payload["metadata"]  # type: ignore[index]
        summary = report_payload["summary"]  # type: ignore[index]
        generated_at = str(metadata["generated_at"])
        alerts_loaded = int(summary["alerts_loaded"])
        incident_count = int(summary["incident_count"])
        severity_counts = dict(summary.get("severity_counts", {}))
        techniques_observed = list(summary.get("techniques_observed", []))
        safe_for_output = bool(summary["safe_for_output"])
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(
            ParseError(
                file_path=str(run_dir / JSON_REPORT_FILENAME),
                message=f"run report is missing required fields: {exc}",
                error_type="run_report_invalid_shape",
            )
        )
        return None

    true_positive_count = 0
    false_positive_count = 0
    unreviewed_count = 0
    outcomes_available = False

    outcomes_path = run_dir / OUTCOMES_FILENAME
    if outcomes_path.is_file():
        try:
            dispositions = load_triage_outcomes(outcomes_path)
        except TriageOutcomeError as exc:
            errors.append(
                ParseError(
                    file_path=str(outcomes_path),
                    message=str(exc),
                    error_type="triage_outcomes_invalid",
                )
            )
        else:
            outcomes_available = True
            for disposition in dispositions.values():
                if disposition == "true_positive":
                    true_positive_count += 1
                elif disposition == "false_positive":
                    false_positive_count += 1
                else:
                    unreviewed_count += 1

    reviewed = true_positive_count + false_positive_count
    false_positive_rate = false_positive_count / reviewed if reviewed > 0 else None

    return RunSnapshot(
        run_id=run_id,
        generated_at=generated_at,
        alerts_loaded=alerts_loaded,
        incident_count=incident_count,
        severity_counts=severity_counts,
        techniques_observed=techniques_observed,
        safe_for_output=safe_for_output,
        true_positive_count=true_positive_count,
        false_positive_count=false_positive_count,
        unreviewed_count=unreviewed_count,
        outcomes_available=outcomes_available,
        false_positive_rate=false_positive_rate,
    )
