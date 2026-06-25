"""Deterministic redaction policy definitions."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RedactionPolicy:
    """Configuration for report-ready safe serialization."""

    name: str = "default-report-safe-v1"
    remove_raw_messages: bool = True
    redact_ip_fields: bool = True
    redact_username_fields: bool = True
    redact_credential_patterns: bool = True
    redact_approved_markers: bool = True

    raw_message_fields: tuple[str, ...] = ("raw_message",)
    source_ip_fields: tuple[str, ...] = ("source_ip", "dest_ip")
    username_fields: tuple[str, ...] = ("username",)


DEFAULT_REDACTION_POLICY = RedactionPolicy()
