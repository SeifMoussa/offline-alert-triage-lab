"""JSON alert loading for local Phase 3 validation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from triage_lab.ingestion.common import discover_input_files, make_error
from triage_lab.ingestion.validators import validate_local_input_path
from triage_lab.models.alert import AlertRecord
from triage_lab.models.load_result import LoadResult
from triage_lab.models.parse_error import ParseError


def load_alerts_from_path(input_path: str | Path) -> LoadResult:
    """Load local JSON alert records from a file or directory."""
    raw_input = str(input_path)
    try:
        path = validate_local_input_path(raw_input)
    except ValueError as exc:
        return LoadResult(
            input_path=raw_input,
            errors=[
                make_error(
                    file_path=raw_input,
                    message=str(exc),
                    error_type="unsafe_input_path",
                )
            ],
        )

    json_files, files_seen, unsupported_files, path_errors = discover_input_files(path)
    result = LoadResult(
        input_path=raw_input,
        files_seen=files_seen,
        unsupported_files=unsupported_files,
        errors=path_errors,
    )

    for json_file in json_files:
        file_alerts, records_seen, errors = load_alert_file(json_file)
        result.files_loaded += 1
        result.records_seen += records_seen
        result.alerts.extend(file_alerts)
        result.errors.extend(errors)

    return result


def load_alert_file(path: Path) -> tuple[list[AlertRecord], int, list[ParseError]]:
    """Load one local JSON, JSON object, JSON array, or NDJSON file."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return (
            [],
            0,
            [
                make_error(
                    file_path=path,
                    message=f"unable to read file: {exc}",
                    error_type="read_error",
                )
            ],
        )

    if not text.strip():
        return (
            [],
            0,
            [
                make_error(
                    file_path=path,
                    message="input file is empty",
                    error_type="empty_file",
                )
            ],
        )

    records, parse_errors = parse_json_records(path, text)
    alerts: list[AlertRecord] = []
    errors = list(parse_errors)

    for index, record in enumerate(records):
        if not isinstance(record, dict):
            errors.append(
                make_error(
                    file_path=path,
                    message="record must be a JSON object",
                    error_type="invalid_record_type",
                    record_index=index,
                )
            )
            continue
        try:
            alerts.append(AlertRecord.model_validate(record))
        except ValidationError as exc:
            errors.extend(validation_errors_to_parse_errors(path, index, exc))

    return alerts, len(records), errors


def parse_json_records(path: Path, text: str) -> tuple[list[Any], list[ParseError]]:
    """Parse JSON array, JSON object, or NDJSON records."""
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return parse_ndjson_records(path, text)

    if isinstance(parsed, list):
        return parsed, []
    if isinstance(parsed, dict):
        return [parsed], []
    return [], [
        make_error(
            file_path=path,
            message="top-level JSON must be an alert object or alert array",
            error_type="invalid_json_shape",
        )
    ]


def parse_ndjson_records(path: Path, text: str) -> tuple[list[Any], list[ParseError]]:
    """Parse newline-delimited JSON records when each non-empty line is JSON."""
    records: list[Any] = []
    errors: list[ParseError] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            errors.append(
                make_error(
                    file_path=path,
                    message=f"malformed JSON at line {line_number}: {exc.msg}",
                    error_type="malformed_json",
                    record_index=line_number - 1,
                )
            )
    if errors:
        return [], errors
    return records, []


def validation_errors_to_parse_errors(
    path: Path, record_index: int, exc: ValidationError
) -> list[ParseError]:
    """Convert Pydantic validation errors to safe parse errors."""
    errors: list[ParseError] = []
    for error in exc.errors():
        field_path = ".".join(str(part) for part in error["loc"]) or None
        errors.append(
            make_error(
                file_path=path,
                message=str(error["msg"]),
                error_type="validation_error",
                record_index=record_index,
                field_path=field_path,
            )
        )
    return errors
