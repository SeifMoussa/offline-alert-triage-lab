"""JSON report rendering."""

from __future__ import annotations

import json

from triage_lab.models.report import SecurityReport


def render_json_report(report: SecurityReport) -> str:
    """Render a deterministic JSON report string."""
    return json.dumps(report.to_safe_dict(), indent=2, sort_keys=True) + "\n"
