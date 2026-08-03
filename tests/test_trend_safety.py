from __future__ import annotations

import json
from pathlib import Path

import pytest

from triage_lab.trend_analytics.engine import build_trend_report
from triage_lab.trend_analytics.history import TrendHistoryError, load_run_history

ROOT = Path(__file__).resolve().parents[1]
HISTORY_DIR = ROOT / "tests" / "fixtures" / "trend_history"


def test_trend_report_output_has_no_raw_message_or_sensitive_markers() -> None:
    payload = build_trend_report(HISTORY_DIR)
    encoded = json.dumps(payload)

    assert "raw_message" not in encoded
    assert "SYNTHETIC_PASSWORD_MARKER" not in encoded
    assert "SYNTHETIC_TOKEN_MARKER" not in encoded
    assert "SYNTHETIC_SECRET_MARKER" not in encoded


def test_trend_report_output_has_no_external_ai_or_network_options() -> None:
    payload = build_trend_report(HISTORY_DIR)
    encoded = json.dumps(payload).lower()

    assert "api_key" not in encoded
    assert "external ai" not in encoded
    assert "network call" not in encoded


def test_history_dir_rejects_unc_path() -> None:
    with pytest.raises(TrendHistoryError, match="network paths"):
        load_run_history("\\\\example\\share\\history")
