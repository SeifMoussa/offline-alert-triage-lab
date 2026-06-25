from __future__ import annotations

import json
from pathlib import Path

import pytest

from triage_lab.reporting.pipeline import build_security_report
from triage_lab.reporting.writer import (
    JSON_REPORT_FILENAME,
    MARKDOWN_REPORT_FILENAME,
    write_reports,
)


def test_report_writer_writes_json_markdown_and_both(tmp_path: Path) -> None:
    report = build_security_report(
        "alerts/sample_alerts.json",
        generated_at="2026-06-25T00:00:00Z",
    )

    json_only = write_reports(report, tmp_path / "json", "json")
    markdown_only = write_reports(report, tmp_path / "markdown", "markdown")
    both = write_reports(report, tmp_path / "both", "both")

    assert json_only["json_report_path"]
    assert json_only["markdown_report_path"] is None
    assert markdown_only["json_report_path"] is None
    assert markdown_only["markdown_report_path"]
    assert both["json_report_path"]
    assert both["markdown_report_path"]
    assert (tmp_path / "both" / JSON_REPORT_FILENAME).exists()
    assert (tmp_path / "both" / MARKDOWN_REPORT_FILENAME).exists()
    assert json.loads((tmp_path / "both" / JSON_REPORT_FILENAME).read_text())


def test_report_writer_rejects_unsafe_output_paths() -> None:
    report = build_security_report("alerts/sample_alerts.json")

    with pytest.raises(ValueError, match="network paths"):
        write_reports(report, "https://example.com/reports", "json")

    with pytest.raises(ValueError, match="path traversal"):
        write_reports(report, "../reports", "markdown")
