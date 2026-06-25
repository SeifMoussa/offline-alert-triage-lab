"""Local JSON ingestion for synthetic alert validation."""

from triage_lab.ingestion.inventory import build_inventory
from triage_lab.ingestion.json_loader import load_alert_file, load_alerts_from_path

__all__ = ["build_inventory", "load_alert_file", "load_alerts_from_path"]
