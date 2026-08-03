from __future__ import annotations

from pathlib import Path

import pytest

from triage_lab.trend_analytics.history import TrendHistoryError, load_run_history

ROOT = Path(__file__).resolve().parents[1]
HISTORY_DIR = ROOT / "tests" / "fixtures" / "trend_history"
ERROR_HISTORY_DIR = ROOT / "tests" / "fixtures" / "trend_history_errors"


def test_load_run_history_loads_all_runs_in_order() -> None:
    snapshots, errors = load_run_history(HISTORY_DIR)

    assert errors == []
    assert [snapshot.run_id for snapshot in snapshots] == [
        "run-2026-06-01",
        "run-2026-06-08",
        "run-2026-06-15",
    ]


def test_load_run_history_computes_false_positive_rate_when_outcomes_present() -> None:
    snapshots, _ = load_run_history(HISTORY_DIR)
    run_with_outcomes = next(s for s in snapshots if s.run_id == "run-2026-06-08")

    assert run_with_outcomes.outcomes_available is True
    assert run_with_outcomes.true_positive_count == 2
    assert run_with_outcomes.false_positive_count == 1
    assert run_with_outcomes.unreviewed_count == 1
    assert run_with_outcomes.false_positive_rate == pytest.approx(1 / 3)


def test_load_run_history_reports_unavailable_rate_without_outcomes_file() -> None:
    snapshots, _ = load_run_history(HISTORY_DIR)
    run_without_outcomes = next(s for s in snapshots if s.run_id == "run-2026-06-01")

    assert run_without_outcomes.outcomes_available is False
    assert run_without_outcomes.false_positive_rate is None


def test_load_run_history_rejects_url_and_path_traversal() -> None:
    with pytest.raises(TrendHistoryError, match="network paths"):
        load_run_history("https://example.com/history")

    with pytest.raises(TrendHistoryError, match="path traversal"):
        load_run_history("..\\history")


def test_load_run_history_reports_missing_directory(tmp_path: Path) -> None:
    snapshots, errors = load_run_history(tmp_path / "does-not-exist")

    assert snapshots == []
    assert errors[0].error_type == "history_dir_missing"


def test_load_run_history_records_structured_errors_for_bad_runs() -> None:
    snapshots, errors = load_run_history(ERROR_HISTORY_DIR)

    error_types = {error.error_type for error in errors}
    assert error_types == {
        "run_report_missing",
        "run_report_unreadable",
        "run_report_invalid_shape",
        "triage_outcomes_invalid",
    }
    # The run with a bad outcomes file still has a valid report and loads.
    assert any(snapshot.run_id == "run-bad-outcomes" for snapshot in snapshots)
    bad_outcomes_snapshot = next(s for s in snapshots if s.run_id == "run-bad-outcomes")
    assert bad_outcomes_snapshot.outcomes_available is False
