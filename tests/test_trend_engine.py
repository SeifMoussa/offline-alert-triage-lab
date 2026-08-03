from __future__ import annotations

from pathlib import Path

import pytest

from triage_lab.trend_analytics.engine import (
    build_trend_report,
    trend_result_is_success,
)

ROOT = Path(__file__).resolve().parents[1]
HISTORY_DIR = ROOT / "tests" / "fixtures" / "trend_history"
ERROR_HISTORY_DIR = ROOT / "tests" / "fixtures" / "trend_history_errors"


def test_build_trend_report_orders_runs_and_tracks_alert_volume() -> None:
    payload = build_trend_report(HISTORY_DIR)

    assert payload["run_count"] == 3
    assert [point["run_id"] for point in payload["alert_volume_trend"]] == [
        "run-2026-06-01",
        "run-2026-06-08",
        "run-2026-06-15",
    ]
    assert [point["alerts_loaded"] for point in payload["alert_volume_trend"]] == [
        10,
        16,
        22,
    ]
    assert trend_result_is_success(payload) is True


def test_build_trend_report_ranks_top_mitre_techniques() -> None:
    payload = build_trend_report(HISTORY_DIR)

    top = payload["top_mitre_techniques"]
    assert top[0] == {"technique_id": "T1046", "runs_observed_in": 3}
    assert top[1] == {"technique_id": "T1110", "runs_observed_in": 3}
    assert {"technique_id": "T1041", "runs_observed_in": 2} in top
    assert {"technique_id": "T1071", "runs_observed_in": 1} in top


def test_build_trend_report_averages_false_positive_rate_over_reviewed_runs() -> None:
    payload = build_trend_report(HISTORY_DIR)

    assert payload["runs_with_outcomes_file"] == 1
    assert payload["runs_with_reviewed_alerts"] == 1
    assert payload["average_false_positive_rate"] == pytest.approx(1 / 3)


def test_build_trend_report_collects_structured_errors_without_failing() -> None:
    payload = build_trend_report(ERROR_HISTORY_DIR)

    assert trend_result_is_success(payload) is False
    assert payload["run_count"] == 1
    assert len(payload["errors"]) == 4
