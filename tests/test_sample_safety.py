from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

from triage_lab.safety import (
    ALLOWED_SAFE_DOMAINS,
    ALLOWED_SYNTHETIC_IP_RANGES,
    APPROVED_SYNTHETIC_SECRET_MARKERS,
)

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_NETWORKS = tuple(
    ipaddress.ip_network(cidr) for cidr in ALLOWED_SYNTHETIC_IP_RANGES
)
APPROVED_USERS = {
    "analyst_user",
    "test_admin",
    "demo_user",
    "service_account_test",
    "lab_user",
}
DOMAIN_PATTERN = re.compile(r"\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+\b")
REAL_SECRET_PATTERNS = (
    re.compile(r"password\s*[:=]", re.IGNORECASE),
    re.compile(r"token\s*[:=]", re.IGNORECASE),
    re.compile(r"secret\s*[:=]", re.IGNORECASE),
    re.compile(r"api[_-]?key\s*[:=]", re.IGNORECASE),
)


def load_alerts(path: Path) -> list[dict[str, object]]:
    return json.loads(path.read_text(encoding="utf-8"))


def all_alert_fixture_paths() -> list[Path]:
    return [
        ROOT / "alerts" / "sample_alerts.json",
        ROOT / "tests" / "fixtures" / "valid_alerts.json",
        ROOT / "tests" / "fixtures" / "edge_case_alerts.json",
        ROOT / "tests" / "fixtures" / "sensitive_marker_alerts.json",
    ]


def is_allowed_ip(value: object) -> bool:
    ip = ipaddress.ip_address(str(value))
    return any(ip in network for network in ALLOWED_NETWORKS)


def is_allowed_domain(value: str) -> bool:
    return value in ALLOWED_SAFE_DOMAINS or value.endswith(".test")


def test_all_fixture_ips_are_allowed_synthetic_ranges() -> None:
    for path in all_alert_fixture_paths():
        for alert in load_alerts(path):
            assert is_allowed_ip(alert["source_ip"])
            assert is_allowed_ip(alert["dest_ip"])


def test_usernames_are_approved_synthetic_values() -> None:
    for path in all_alert_fixture_paths():
        for alert in load_alerts(path):
            username = alert.get("username")
            if username is not None:
                assert username in APPROVED_USERS


def test_hostnames_and_message_domains_are_safe() -> None:
    for path in all_alert_fixture_paths():
        for alert in load_alerts(path):
            hostname = alert.get("hostname")
            if hostname is not None:
                assert is_allowed_domain(str(hostname))

            message = str(alert.get("raw_message", ""))
            for domain in DOMAIN_PATTERN.findall(message.lower()):
                assert is_allowed_domain(domain)


def test_no_real_looking_credentials_are_present() -> None:
    for path in all_alert_fixture_paths():
        text = path.read_text(encoding="utf-8")
        for pattern in REAL_SECRET_PATTERNS:
            assert pattern.search(text) is None


def test_sensitive_fixture_contains_only_approved_fake_markers() -> None:
    path = ROOT / "tests" / "fixtures" / "sensitive_marker_alerts.json"
    text = path.read_text(encoding="utf-8")
    seen_markers = set(re.findall(r"SYNTHETIC_[A-Z_]+_MARKER", text))
    assert seen_markers == set(APPROVED_SYNTHETIC_SECRET_MARKERS)
