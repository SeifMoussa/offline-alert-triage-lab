from __future__ import annotations

from triage_lab.models.severity import Severity, highest_severity


def test_severity_enum_ordering() -> None:
    assert Severity.LOW.rank < Severity.MEDIUM.rank
    assert Severity.MEDIUM.rank < Severity.HIGH.rank
    assert Severity.HIGH.rank < Severity.CRITICAL.rank


def test_raise_by_caps_at_critical() -> None:
    assert Severity.LOW.raise_by(1) == Severity.MEDIUM
    assert Severity.LOW.raise_by(2) == Severity.HIGH
    assert Severity.HIGH.raise_by(99) == Severity.CRITICAL
    assert Severity.CRITICAL.raise_by(1) == Severity.CRITICAL


def test_highest_severity() -> None:
    assert highest_severity([Severity.LOW, Severity.CRITICAL]) == Severity.CRITICAL
    assert highest_severity([]) is None
