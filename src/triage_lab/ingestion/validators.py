"""Local path and safe display validators for ingestion."""

from __future__ import annotations

import re
from pathlib import Path

from triage_lab.safety import APPROVED_SYNTHETIC_SECRET_MARKERS

URL_PATTERN = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
SECRET_VALUE_PATTERNS = (
    re.compile(r"(password\s*[:=]\s*)\S+", re.IGNORECASE),
    re.compile(r"(token\s*[:=]\s*)\S+", re.IGNORECASE),
    re.compile(r"(secret\s*[:=]\s*)\S+", re.IGNORECASE),
    re.compile(r"(api[_-]?key\s*[:=]\s*)\S+", re.IGNORECASE),
    re.compile(r"(bearer\s+)\S+", re.IGNORECASE),
)


def is_network_path(value: str) -> bool:
    """Return true when a path string is URL-like or a UNC path."""
    return bool(URL_PATTERN.match(value)) or value.startswith(("\\\\", "//"))


def has_path_traversal(value: str) -> bool:
    """Return true when a path contains parent-directory traversal segments."""
    return any(part == ".." for part in Path(value).parts)


def validate_local_input_path(value: str) -> Path:
    """Validate and return a local input path without resolving network targets."""
    if is_network_path(value):
        raise ValueError("network paths and URLs are not accepted")
    if has_path_traversal(value):
        raise ValueError("path traversal is not accepted")
    return Path(value)


def redact_sensitive_text(value: str) -> str:
    """Mask sensitive-looking values and approved marker constants for CLI output."""
    redacted = value
    for marker in APPROVED_SYNTHETIC_SECRET_MARKERS:
        redacted = redacted.replace(marker, "[REDACTED]")
    for pattern in SECRET_VALUE_PATTERNS:
        redacted = pattern.sub(r"\1[REDACTED]", redacted)
    return redacted
