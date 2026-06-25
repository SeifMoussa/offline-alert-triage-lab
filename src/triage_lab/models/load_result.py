"""Load result models for local alert ingestion."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from triage_lab.models.alert import AlertRecord
from triage_lab.models.parse_error import ParseError


class LoadResult(BaseModel):
    """Result of loading one input path."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    input_path: str
    files_seen: int = 0
    files_loaded: int = 0
    unsupported_files: int = 0
    records_seen: int = 0
    alerts: list[AlertRecord] = Field(default_factory=list)
    errors: list[ParseError] = Field(default_factory=list)

    @property
    def alerts_loaded(self) -> int:
        return len(self.alerts)

    @property
    def malformed_records(self) -> int:
        return sum(error.record_index is not None for error in self.errors)

    @property
    def error_count(self) -> int:
        return len(self.errors)

    @property
    def valid(self) -> bool:
        return self.error_count == 0

    @property
    def event_type_counts(self) -> dict[str, int]:
        return dict(sorted(Counter(alert.event_type for alert in self.alerts).items()))

    @property
    def earliest_timestamp(self) -> datetime | None:
        if not self.alerts:
            return None
        return min(alert.timestamp for alert in self.alerts)

    @property
    def latest_timestamp(self) -> datetime | None:
        if not self.alerts:
            return None
        return max(alert.timestamp for alert in self.alerts)

    def to_inventory_dict(self) -> dict[str, Any]:
        return {
            "input_path": self.input_path,
            "files_seen": self.files_seen,
            "files_loaded": self.files_loaded,
            "unsupported_files": self.unsupported_files,
            "records_seen": self.records_seen,
            "alerts_loaded": self.alerts_loaded,
            "malformed_records": self.malformed_records,
            "event_type_counts": self.event_type_counts,
            "earliest_timestamp": _format_datetime(self.earliest_timestamp),
            "latest_timestamp": _format_datetime(self.latest_timestamp),
            "errors": [error.model_dump(mode="json") for error in self.errors],
        }

    def to_validation_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "files_checked": self.files_seen,
            "records_seen": self.records_seen,
            "alerts_loaded": self.alerts_loaded,
            "malformed_records": self.malformed_records,
            "error_count": self.error_count,
            "errors": [error.model_dump(mode="json") for error in self.errors],
        }


def _format_datetime(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat().replace("+00:00", "Z")
