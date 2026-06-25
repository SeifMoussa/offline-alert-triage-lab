"""Recursive deterministic redaction engine."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from triage_lab.models.redaction import RedactionResult, RedactionSummary
from triage_lab.redaction.policies import DEFAULT_REDACTION_POLICY, RedactionPolicy
from triage_lab.redaction.validators import validate_safe_output
from triage_lab.safety import APPROVED_SYNTHETIC_SECRET_MARKERS

IP_PLACEHOLDER = "[REDACTED:ip]"
USERNAME_PLACEHOLDER = "[REDACTED:username]"
RAW_MESSAGE_PLACEHOLDER = "[REDACTED:raw_message]"
MARKER_PLACEHOLDER = "[REDACTED:marker]"
CREDENTIAL_PLACEHOLDER = "[REDACTED:credential]"

CREDENTIAL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(password\s*[:=]\s*)\S+", re.IGNORECASE),
    re.compile(r"\b(token\s*[:=]\s*)\S+", re.IGNORECASE),
    re.compile(r"\b(secret\s*[:=]\s*)\S+", re.IGNORECASE),
    re.compile(r"\b(api[_-]?key\s*[:=]\s*)\S+", re.IGNORECASE),
    re.compile(r"\b(private_key\s*[:=]?\s*)\S*", re.IGNORECASE),
)


@dataclass
class _Counters:
    fields_redacted: int = 0
    markers_redacted: int = 0
    ip_values_redacted: int = 0
    usernames_redacted: int = 0
    credential_patterns_redacted: int = 0
    raw_messages_removed: int = 0

    def summary(self, policy: RedactionPolicy) -> RedactionSummary:
        total = (
            self.fields_redacted
            + self.markers_redacted
            + self.ip_values_redacted
            + self.usernames_redacted
            + self.credential_patterns_redacted
            + self.raw_messages_removed
        )
        return RedactionSummary(
            fields_redacted=self.fields_redacted,
            markers_redacted=self.markers_redacted,
            ip_values_redacted=self.ip_values_redacted,
            usernames_redacted=self.usernames_redacted,
            credential_patterns_redacted=self.credential_patterns_redacted,
            raw_messages_removed=self.raw_messages_removed,
            redaction_applied=total > 0,
            redaction_policy=policy.name,
        )


def redact_payload(
    payload: Any,
    policy: RedactionPolicy = DEFAULT_REDACTION_POLICY,
) -> RedactionResult:
    """Redact a payload and validate that the result is output-safe."""
    counters = _Counters()
    redacted = _redact_value(payload, policy, counters)
    summary = counters.summary(policy)
    validation = validate_safe_output(redacted, policy)
    return RedactionResult(
        payload=redacted,
        summary=summary,
        safe_for_output=validation.safe,
        validation_errors=validation.errors,
    )


def _redact_value(value: Any, policy: RedactionPolicy, counters: _Counters) -> Any:
    if hasattr(value, "to_safe_dict") and callable(value.to_safe_dict):
        return _redact_value(value.to_safe_dict(), policy, counters)
    if isinstance(value, BaseModel):
        return _redact_value(value.model_dump(mode="json"), policy, counters)
    if isinstance(value, Mapping):
        return _redact_mapping(value, policy, counters)
    if isinstance(value, list):
        return [_redact_value(item, policy, counters) for item in value]
    if isinstance(value, tuple):
        return [_redact_value(item, policy, counters) for item in value]
    if isinstance(value, set):
        return [
            _redact_value(item, policy, counters) for item in sorted(value, key=repr)
        ]
    if isinstance(value, str):
        return _redact_string(value, policy, counters)
    return value


def _redact_mapping(
    value: Mapping[Any, Any],
    policy: RedactionPolicy,
    counters: _Counters,
) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for raw_key, raw_value in value.items():
        key = str(raw_key)
        if policy.remove_raw_messages and key in policy.raw_message_fields:
            counters.raw_messages_removed += 1
            counters.fields_redacted += 1
            continue
        if policy.redact_ip_fields and key in policy.source_ip_fields:
            redacted[key] = IP_PLACEHOLDER if raw_value is not None else None
            if raw_value is not None:
                counters.ip_values_redacted += 1
                counters.fields_redacted += 1
            continue
        if policy.redact_username_fields and key in policy.username_fields:
            redacted[key] = USERNAME_PLACEHOLDER if raw_value is not None else None
            if raw_value is not None:
                counters.usernames_redacted += 1
                counters.fields_redacted += 1
            continue
        redacted[key] = _redact_value(raw_value, policy, counters)
    return redacted


def _redact_string(
    value: str,
    policy: RedactionPolicy,
    counters: _Counters,
) -> str:
    redacted = value
    if policy.redact_approved_markers:
        for marker in APPROVED_SYNTHETIC_SECRET_MARKERS:
            count = redacted.count(marker)
            if count:
                counters.markers_redacted += count
                redacted = redacted.replace(marker, MARKER_PLACEHOLDER)
    if policy.redact_credential_patterns:
        for pattern in CREDENTIAL_PATTERNS:
            redacted, count = pattern.subn(
                CREDENTIAL_PLACEHOLDER,
                redacted,
            )
            counters.credential_patterns_redacted += count
    return redacted
