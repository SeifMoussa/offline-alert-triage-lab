"""Inventory helpers for loaded synthetic alert records."""

from __future__ import annotations

from pathlib import Path

from triage_lab.ingestion.json_loader import load_alerts_from_path
from triage_lab.models.load_result import LoadResult


def build_inventory(input_path: str | Path) -> LoadResult:
    """Build a validation inventory for a local input path."""
    return load_alerts_from_path(input_path)
