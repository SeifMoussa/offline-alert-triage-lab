"""Safety constants for the offline alert triage lab."""

from __future__ import annotations

PROJECT_DESCRIPTION = "offline-only deterministic security alert triage lab"

PROJECT_SAFETY_DISCLAIMER = (
    "This project is defensive, offline-only, and limited to synthetic/local "
    "alert data. It performs no network calls, no live scanning, no exploit "
    "code, and no external AI API usage."
)

ALLOWED_SYNTHETIC_IP_RANGES: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "192.0.2.0/24",
    "198.51.100.0/24",
    "203.0.113.0/24",
)

ALLOWED_SAFE_DOMAINS: tuple[str, ...] = (
    "example.com",
    "example.org",
    "example.net",
    ".test",
)

APPROVED_SYNTHETIC_SECRET_MARKERS: tuple[str, ...] = (
    "SYNTHETIC_PASSWORD_MARKER",
    "SYNTHETIC_TOKEN_MARKER",
    "SYNTHETIC_SECRET_MARKER",
)

FORBIDDEN_CAPABILITY_KEYWORDS: tuple[str, ...] = (
    "external ai api",
    "llm api",
    "api key integration",
    "network call",
    "live scanning",
    "exploit code",
    "attack automation",
    "malware behavior",
    "external threat intelligence",
    "metasploit",
    "nmap execution",
    "nessus integration",
    "target real systems",
)


def safety_summary_text() -> str:
    """Return the project safety summary used by CLI and documentation checks."""
    return "\n".join(
        (
            "Safety model:",
            "- Defensive only.",
            "- Offline-only and local-file based.",
            "- Synthetic/local alert data only.",
            "- No network calls.",
            "- No live scanning.",
            "- No exploit code.",
            "- No external AI API.",
            "- No external threat intelligence APIs.",
        )
    )
