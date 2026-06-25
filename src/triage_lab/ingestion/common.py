"""Common ingestion helpers."""

from __future__ import annotations

from pathlib import Path

from triage_lab.ingestion.validators import redact_sensitive_text
from triage_lab.models.parse_error import ParseError


def make_error(
    *,
    file_path: Path | str,
    message: str,
    error_type: str,
    record_index: int | None = None,
    field_path: str | None = None,
) -> ParseError:
    """Create a safe structured parse error."""
    return ParseError(
        file_path=str(file_path),
        message=redact_sensitive_text(message),
        error_type=error_type,
        record_index=record_index,
        field_path=field_path,
    )


def discover_input_files(path: Path) -> tuple[list[Path], int, int, list[ParseError]]:
    """Discover local JSON files and count unsupported local files."""
    if not path.exists():
        return (
            [],
            0,
            0,
            [
                make_error(
                    file_path=path,
                    message="input path does not exist",
                    error_type="path_not_found",
                )
            ],
        )

    if path.is_file():
        if path.suffix.lower() == ".json":
            return [path], 1, 0, []
        return (
            [],
            1,
            1,
            [
                make_error(
                    file_path=path,
                    message=f"unsupported file extension: {path.suffix or '<none>'}",
                    error_type="unsupported_file",
                )
            ],
        )

    if path.is_dir():
        files = sorted(item for item in path.rglob("*") if item.is_file())
        json_files = [item for item in files if item.suffix.lower() == ".json"]
        unsupported = len(files) - len(json_files)
        return json_files, len(files), unsupported, []

    return (
        [],
        1,
        0,
        [
            make_error(
                file_path=path,
                message="input path is not a regular file or directory",
                error_type="unsupported_path",
            )
        ],
    )
