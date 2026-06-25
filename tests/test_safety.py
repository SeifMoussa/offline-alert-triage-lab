from __future__ import annotations

from triage_lab.safety import (
    ALLOWED_SAFE_DOMAINS,
    ALLOWED_SYNTHETIC_IP_RANGES,
    FORBIDDEN_CAPABILITY_KEYWORDS,
    PROJECT_SAFETY_DISCLAIMER,
    safety_summary_text,
)


def test_safety_summary_includes_required_boundaries() -> None:
    summary = safety_summary_text()
    assert "Offline-only" in summary
    assert "No network calls" in summary
    assert "No external AI API" in summary
    assert "Synthetic/local alert data only" in summary


def test_safety_constants_include_allowed_ranges_and_domains() -> None:
    expected_ranges = {"10.0.0.0/8", "192.0.2.0/24"}
    expected_domains = {"example.com", ".test"}
    assert expected_ranges.issubset(set(ALLOWED_SYNTHETIC_IP_RANGES))
    assert expected_domains.issubset(set(ALLOWED_SAFE_DOMAINS))


def test_forbidden_capability_keywords_are_declared() -> None:
    assert "network call" in FORBIDDEN_CAPABILITY_KEYWORDS
    assert "external ai api" in FORBIDDEN_CAPABILITY_KEYWORDS
    assert "live scanning" in FORBIDDEN_CAPABILITY_KEYWORDS


def test_project_disclaimer_mentions_core_safety_model() -> None:
    assert "offline-only" in PROJECT_SAFETY_DISCLAIMER
    assert "synthetic/local" in PROJECT_SAFETY_DISCLAIMER
    assert "no network calls" in PROJECT_SAFETY_DISCLAIMER
