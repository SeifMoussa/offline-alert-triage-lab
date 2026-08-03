from __future__ import annotations

from pathlib import Path

import pytest

from triage_lab.trend_analytics.outcomes import TriageOutcomeError, load_triage_outcomes


def test_load_triage_outcomes_valid(tmp_path: Path) -> None:
    path = tmp_path / "triage_outcomes.json"
    path.write_text(
        '{"alerts": {"alert-0001": "true_positive", "alert-0002": "false_positive"}}',
        encoding="utf-8",
    )

    outcomes = load_triage_outcomes(path)

    assert outcomes == {
        "alert-0001": "true_positive",
        "alert-0002": "false_positive",
    }


def test_load_triage_outcomes_rejects_invalid_disposition(tmp_path: Path) -> None:
    path = tmp_path / "triage_outcomes.json"
    path.write_text('{"alerts": {"alert-0001": "maybe"}}', encoding="utf-8")

    with pytest.raises(TriageOutcomeError, match="unsupported disposition"):
        load_triage_outcomes(path)


def test_load_triage_outcomes_rejects_malformed_json(tmp_path: Path) -> None:
    path = tmp_path / "triage_outcomes.json"
    path.write_text("{ not json", encoding="utf-8")

    with pytest.raises(TriageOutcomeError, match="invalid triage outcomes JSON"):
        load_triage_outcomes(path)


def test_load_triage_outcomes_requires_alerts_mapping(tmp_path: Path) -> None:
    path = tmp_path / "triage_outcomes.json"
    path.write_text('{"not_alerts": {}}', encoding="utf-8")

    with pytest.raises(TriageOutcomeError, match="'alerts' mapping"):
        load_triage_outcomes(path)


def test_load_triage_outcomes_rejects_empty_alert_id(tmp_path: Path) -> None:
    path = tmp_path / "triage_outcomes.json"
    path.write_text('{"alerts": {"": "true_positive"}}', encoding="utf-8")

    with pytest.raises(TriageOutcomeError, match="non-empty strings"):
        load_triage_outcomes(path)


def test_load_triage_outcomes_rejects_unreadable_file(tmp_path: Path) -> None:
    missing_path = tmp_path / "does-not-exist" / "triage_outcomes.json"

    with pytest.raises(TriageOutcomeError, match="unable to read triage outcomes"):
        load_triage_outcomes(missing_path)
