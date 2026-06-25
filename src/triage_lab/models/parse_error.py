"""Structured parse and validation errors for local alert loading."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ParseError(BaseModel):
    """A safe, structured error for one file or record."""

    model_config = ConfigDict(frozen=True)

    file_path: str
    message: str
    error_type: str
    record_index: int | None = None
    field_path: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)
