"""Small helpers for deterministic grouping summaries."""

from __future__ import annotations

from collections import Counter

from triage_lab.models.incident import Incident
from triage_lab.models.severity import Severity, highest_severity


def incident_severity_counts(incidents: list[Incident]) -> dict[str, int]:
    """Count incident severities in fixed order."""
    counts = Counter(incident.severity.value for incident in incidents)
    return {
        "LOW": counts.get("LOW", 0),
        "MEDIUM": counts.get("MEDIUM", 0),
        "HIGH": counts.get("HIGH", 0),
        "CRITICAL": counts.get("CRITICAL", 0),
    }


def highest_incident_severity(incidents: list[Incident]) -> Severity | None:
    """Return the highest severity across incidents."""
    return highest_severity([incident.severity for incident in incidents])
