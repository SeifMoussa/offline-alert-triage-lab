"""Severity model and deterministic severity operations."""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    """Ordered severity values used by the deterministic classifier."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER.index(self)

    def raise_by(self, levels: int) -> Severity:
        """Raise severity by a number of levels, capped at CRITICAL."""
        target_rank = min(self.rank + max(levels, 0), Severity.CRITICAL.rank)
        return SEVERITY_ORDER[target_rank]


SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)


def highest_severity(values: list[Severity]) -> Severity | None:
    """Return the highest severity from a list."""
    if not values:
        return None
    return max(values, key=lambda severity: severity.rank)
