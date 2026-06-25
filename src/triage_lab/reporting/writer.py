"""Write deterministic report files to local paths."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from triage_lab.ingestion.validators import validate_local_input_path
from triage_lab.models.report import SecurityReport
from triage_lab.reporting.json_report import render_json_report
from triage_lab.reporting.markdown_report import render_markdown_report

ReportFormat = Literal["json", "markdown", "both"]
JSON_REPORT_FILENAME = "security_alert_triage_report.json"
MARKDOWN_REPORT_FILENAME = "security_alert_triage_report.md"


def write_reports(
    report: SecurityReport,
    output_dir: str | Path,
    report_format: ReportFormat,
) -> dict[str, str | None]:
    """Write requested report formats to a local output directory."""
    directory = _validate_output_dir(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    json_path = directory / JSON_REPORT_FILENAME
    markdown_path = directory / MARKDOWN_REPORT_FILENAME
    written = {"json_report_path": None, "markdown_report_path": None}
    if report_format in {"json", "both"}:
        json_path.write_text(render_json_report(report), encoding="utf-8")
        written["json_report_path"] = str(json_path)
    if report_format in {"markdown", "both"}:
        markdown_path.write_text(render_markdown_report(report), encoding="utf-8")
        written["markdown_report_path"] = str(markdown_path)
    return written


def _validate_output_dir(output_dir: str | Path) -> Path:
    try:
        return validate_local_input_path(str(output_dir))
    except ValueError as exc:
        raise ValueError(f"invalid report output path: {exc}") from exc
