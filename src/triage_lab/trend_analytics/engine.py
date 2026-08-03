"""Aggregate deterministic multi-run trend analytics from local history data."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from triage_lab.models.trend import RunSnapshot
from triage_lab.trend_analytics.history import load_run_history

TOP_TECHNIQUE_LIMIT = 10


def build_trend_report(history_dir: str | Path) -> dict[str, Any]:
    """Load local run history and build a deterministic trend report."""
    snapshots, errors = load_run_history(history_dir)
    ordered = sorted(
        snapshots, key=lambda snapshot: (snapshot.generated_at, snapshot.run_id)
    )

    rated_runs = [
        snapshot for snapshot in ordered if snapshot.false_positive_rate is not None
    ]
    average_false_positive_rate = (
        sum(snapshot.false_positive_rate for snapshot in rated_runs) / len(rated_runs)
        if rated_runs
        else None
    )

    return {
        "history_dir": str(history_dir),
        "run_count": len(ordered),
        "runs": [snapshot.to_safe_dict() for snapshot in ordered],
        "alert_volume_trend": [
            {
                "run_id": snapshot.run_id,
                "generated_at": snapshot.generated_at,
                "alerts_loaded": snapshot.alerts_loaded,
            }
            for snapshot in ordered
        ],
        "top_mitre_techniques": _top_techniques(ordered),
        "false_positive_rate_trend": [
            {
                "run_id": snapshot.run_id,
                "generated_at": snapshot.generated_at,
                "outcomes_available": snapshot.outcomes_available,
                "false_positive_rate": snapshot.false_positive_rate,
            }
            for snapshot in ordered
        ],
        "runs_with_outcomes_file": sum(
            snapshot.outcomes_available for snapshot in ordered
        ),
        "runs_with_reviewed_alerts": len(rated_runs),
        "average_false_positive_rate": average_false_positive_rate,
        "errors": [error.model_dump(mode="json") for error in errors],
    }


def trend_result_is_success(payload: dict[str, Any]) -> bool:
    """Return true when trend analytics payload has no load errors."""
    return not payload["errors"]


def _top_techniques(snapshots: list[RunSnapshot]) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    for snapshot in snapshots:
        counts.update(set(snapshot.techniques_observed))
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [
        {"technique_id": technique_id, "runs_observed_in": count}
        for technique_id, count in ranked[:TOP_TECHNIQUE_LIMIT]
    ]
