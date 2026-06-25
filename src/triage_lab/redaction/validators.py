"""Safety validators for report-ready serialized payloads."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any

from triage_lab.redaction.policies import DEFAULT_REDACTION_POLICY, RedactionPolicy
from triage_lab.safety import APPROVED_SYNTHETIC_SECRET_MARKERS

PROHIBITED_TEXT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("password_assignment", re.compile(r"\bpassword\s*=", re.IGNORECASE)),
    ("token_assignment", re.compile(r"\btoken\s*=", re.IGNORECASE)),
    ("secret_assignment", re.compile(r"\bsecret\s*=", re.IGNORECASE)),
    ("api_key_assignment", re.compile(r"\bapi[_-]?key\s*=", re.IGNORECASE)),
    ("private_key", re.compile(r"\bprivate_key\b", re.IGNORECASE)),
)
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@dataclass(frozen=True)
class OutputValidationResult:
    """Structured validation result for redacted output."""

    safe: bool
    errors: list[dict[str, Any]]


def validate_safe_output(
    payload: Any,
    policy: RedactionPolicy = DEFAULT_REDACTION_POLICY,
) -> OutputValidationResult:
    """Return structured errors if a payload is unsafe for CLI/report output."""
    errors: list[dict[str, Any]] = []
    _validate_value(payload, "$", policy, errors)
    rendered = json.dumps(payload, sort_keys=True, default=str)
    for marker in APPROVED_SYNTHETIC_SECRET_MARKERS:
        if marker in rendered:
            errors.append(
                {
                    "path": "$",
                    "error_type": "prohibited_marker",
                    "message": "approved synthetic marker remained in output",
                }
            )
    for error_type, pattern in PROHIBITED_TEXT_PATTERNS:
        if pattern.search(rendered):
            errors.append(
                {
                    "path": "$",
                    "error_type": error_type,
                    "message": "credential-looking text remained in output",
                }
            )
    return OutputValidationResult(safe=not errors, errors=errors)


def _validate_value(
    value: Any,
    path: str,
    policy: RedactionPolicy,
    errors: list[dict[str, Any]],
) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            key_path = f"{path}.{key}"
            if policy.remove_raw_messages and key in policy.raw_message_fields:
                errors.append(
                    {
                        "path": key_path,
                        "error_type": "raw_message_present",
                        "message": "raw_message is not allowed in report-ready output",
                    }
                )
            if (
                policy.redact_ip_fields
                and key in policy.source_ip_fields
                and isinstance(item, str)
                and _is_raw_ip(item)
            ):
                errors.append(
                    {
                        "path": key_path,
                        "error_type": "unredacted_ip",
                        "message": "IP field contains an unredacted IP address",
                    }
                )
            if (
                policy.redact_username_fields
                and key in policy.username_fields
                and isinstance(item, str)
                and EMAIL_PATTERN.match(item)
            ):
                errors.append(
                    {
                        "path": key_path,
                        "error_type": "email_username",
                        "message": "username contains an email-like value",
                    }
                )
            _validate_value(item, key_path, policy, errors)
        return
    if isinstance(value, list | tuple | set):
        for index, item in enumerate(value):
            _validate_value(item, f"{path}[{index}]", policy, errors)


def _is_raw_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
