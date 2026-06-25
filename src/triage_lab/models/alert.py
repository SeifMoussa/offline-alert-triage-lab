"""Pydantic model for synthetic alert records."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from triage_lab.safety import (
    ALLOWED_SAFE_DOMAINS,
    ALLOWED_SYNTHETIC_IP_RANGES,
    APPROVED_SYNTHETIC_SECRET_MARKERS,
)


class AlertRecord(BaseModel):
    """Validated synthetic alert record for Phase 3 ingestion."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    SUPPORTED_EVENT_TYPES: ClassVar[set[str]] = {
        "failed_login",
        "brute_force",
        "port_scan",
        "privilege_escalation",
        "data_exfiltration",
        "lateral_movement",
        "malware_detected",
        "c2_beacon",
        "policy_violation",
        "anomalous_login_time",
        "unknown",
    }
    ALLOWED_NETWORKS: ClassVar[tuple[ipaddress._BaseNetwork, ...]] = tuple(
        ipaddress.ip_network(cidr) for cidr in ALLOWED_SYNTHETIC_IP_RANGES
    )
    EMAIL_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    DOMAIN_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+\b",
        re.IGNORECASE,
    )
    SECRET_PATTERNS: ClassVar[tuple[re.Pattern[str], ...]] = (
        re.compile(r"\bpassword\s*[:=]", re.IGNORECASE),
        re.compile(r"\btoken\s*[:=]", re.IGNORECASE),
        re.compile(r"\bsecret\s*[:=]", re.IGNORECASE),
        re.compile(r"\bapi[_-]?key\s*[:=]", re.IGNORECASE),
        re.compile(r"\bbearer\s+[a-z0-9._~-]+", re.IGNORECASE),
    )

    alert_id: str
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: int | None = None
    dest_port: int | None = None
    username: str | None = None
    hostname: str | None = None
    event_type: str
    raw_message: str
    count: int | None = None
    tags: list[str] = Field(default_factory=list)
    synthetic_marker: bool

    @field_validator("alert_id", "event_type", "raw_message")
    @classmethod
    def non_empty_string(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

    @field_validator("source_ip", "dest_ip")
    @classmethod
    def allowed_synthetic_ip(cls, value: str) -> str:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("must be a valid IP address") from exc
        if not any(ip in network for network in cls.ALLOWED_NETWORKS):
            raise ValueError("must be inside an allowed synthetic IP range")
        return value

    @field_validator("source_port", "dest_port")
    @classmethod
    def valid_port(cls, value: int | None) -> int | None:
        if value is not None and not 1 <= value <= 65535:
            raise ValueError("must be between 1 and 65535")
        return value

    @field_validator("count")
    @classmethod
    def valid_count(cls, value: int | None) -> int | None:
        if value is not None and value < 0:
            raise ValueError("must be non-negative")
        return value

    @field_validator("username")
    @classmethod
    def safe_username(cls, value: str | None) -> str | None:
        if value is not None and cls.EMAIL_PATTERN.match(value):
            raise ValueError("must not be an email address")
        return value

    @field_validator("hostname")
    @classmethod
    def safe_hostname(cls, value: str | None) -> str | None:
        if value is not None and not cls._is_allowed_domain(value.lower()):
            raise ValueError("must use .test or an approved example domain")
        return value

    @field_validator("event_type")
    @classmethod
    def supported_event_type(cls, value: str) -> str:
        if value not in cls.SUPPORTED_EVENT_TYPES:
            raise ValueError("unsupported event_type")
        return value

    @field_validator("raw_message")
    @classmethod
    def safe_raw_message(cls, value: str) -> str:
        for pattern in cls.SECRET_PATTERNS:
            if pattern.search(value):
                raise ValueError("must not contain credential-looking text")
        for domain in cls.DOMAIN_PATTERN.findall(value):
            lowered = domain.lower()
            if not cls._is_allowed_domain(lowered):
                raise ValueError("must not contain unapproved domains")
        return value

    @field_validator("tags")
    @classmethod
    def safe_tags(cls, value: list[str]) -> list[str]:
        if not all(isinstance(tag, str) for tag in value):
            raise ValueError("tags must contain only strings")
        return value

    @model_validator(mode="after")
    def validate_synthetic_marker(self) -> AlertRecord:
        if self.synthetic_marker is not True:
            raise ValueError("synthetic_marker must be true")
        return self

    @classmethod
    def _is_allowed_domain(cls, value: str) -> bool:
        return value in ALLOWED_SAFE_DOMAINS or value.endswith(".test")

    @classmethod
    def approved_synthetic_markers(cls) -> tuple[str, ...]:
        """Expose approved fake markers for validators and tests."""
        return APPROVED_SYNTHETIC_SECRET_MARKERS

    def to_safe_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation of the alert."""
        return self.model_dump(mode="json")
