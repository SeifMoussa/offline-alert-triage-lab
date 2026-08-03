"""Load optional local analyst-authored triage outcome dispositions."""

from __future__ import annotations

import json
from pathlib import Path

OUTCOMES_FILENAME = "triage_outcomes.json"
VALID_DISPOSITIONS = {"true_positive", "false_positive", "unreviewed"}


class TriageOutcomeError(ValueError):
    """Raised when a local triage_outcomes.json file is invalid."""


def load_triage_outcomes(path: Path) -> dict[str, str]:
    """Load and validate a local analyst-authored outcomes file.

    The file is a simple local JSON mapping of alert IDs to a reviewed
    disposition, written by hand by an analyst after triaging a run, the
    same way ``alerts/sample_alerts.json`` is a hand-authored local fixture.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise TriageOutcomeError(f"unable to read triage outcomes: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise TriageOutcomeError(f"invalid triage outcomes JSON: {exc}") from exc

    if not isinstance(raw, dict) or not isinstance(raw.get("alerts"), dict):
        raise TriageOutcomeError(
            "triage outcomes must be a JSON object with an 'alerts' mapping"
        )

    dispositions: dict[str, str] = {}
    for alert_id, disposition in raw["alerts"].items():
        if not isinstance(alert_id, str) or not alert_id:
            raise TriageOutcomeError(
                "triage outcome alert IDs must be non-empty strings"
            )
        if disposition not in VALID_DISPOSITIONS:
            raise TriageOutcomeError(
                f"unsupported disposition for {alert_id}: {disposition!r}"
            )
        dispositions[alert_id] = disposition
    return dispositions
