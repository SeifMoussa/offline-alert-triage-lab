from __future__ import annotations

from triage_lab.models.redaction import RedactionResult, RedactionSummary


def test_redaction_summary_defaults_are_safe() -> None:
    summary = RedactionSummary()

    assert summary.fields_redacted == 0
    assert summary.redaction_applied is False
    assert summary.redaction_policy == "default-report-safe-v1"


def test_redaction_result_records_validation_errors() -> None:
    result = RedactionResult(
        payload={"safe": False},
        summary=RedactionSummary(markers_redacted=1, redaction_applied=True),
        safe_for_output=False,
        validation_errors=[
            {
                "path": "$",
                "error_type": "prohibited_marker",
                "message": "marker remained",
            }
        ],
    )

    assert result.summary.markers_redacted == 1
    assert result.safe_for_output is False
    assert result.validation_errors[0]["error_type"] == "prohibited_marker"
