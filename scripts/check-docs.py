"""Validate documentation and generated report safety claims."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

IMPORTANT_DOCS = (
    "README.md",
    "SECURITY.md",
    "TESTING_REPORT.md",
    "PROJECT_COMPLETION_CHECKLIST.md",
    "CHANGELOG.md",
    "docs/phase-0-plan.md",
    "docs/testing-guide.md",
    "docs/release-checklist.md",
    "docs/reporting.md",
    "docs/redaction-policy.md",
    "docs/report-schema.md",
    "docs/safety-model.md",
)
EXAMPLE_REPORTS = (
    "reports/examples/security_alert_triage_report.json",
    "reports/examples/security_alert_triage_report.md",
)
REPORT_FORBIDDEN = (
    "SYNTHETIC_PASSWORD_MARKER",
    "SYNTHETIC_TOKEN_MARKER",
    "SYNTHETIC_SECRET_MARKER",
    "password=",
    "token=",
    "secret=",
    "api_key=",
    "private_key",
    "raw_message",
)
README_REQUIRED = (
    "offline-only",
    "synthetic",
    "deterministic",
)
SAFETY_REQUIRED = (
    "no llm",
    "no external ai api",
    "no network calls",
)
REPORT_REQUIRED = (
    "Safety Disclaimer",
    "Redaction Summary",
    "deterministic rule-based",
)
CLI_EXAMPLES = (
    "python -m triage_lab report --input alerts/sample_alerts.json "
    "--output reports/examples --format both",
    "python -m triage_lab redact-check --input alerts/sample_alerts.json --format json",
)
UNVERIFIED_CLAIMS = (
    "hosted ci passed",
    "github actions passed",
    "codeql passed on github",
    "hosted codeql passed",
    "repository is published",
    "package is published",
    "release has been created",
    "release is created",
)
UNSAFE_IMPLEMENTED_CLAIMS = (
    "llm integration is implemented",
    "external ai api is implemented",
    "network enrichment is implemented",
    "live scanning is implemented",
    "external mitre api is implemented",
    "external threat intelligence is implemented",
)


def main() -> int:
    errors: list[str] = []
    _check_files_exist(IMPORTANT_DOCS, errors)
    _check_files_exist(EXAMPLE_REPORTS, errors)
    has_errors = bool(errors)
    if has_errors:
        _print_errors(errors)
        return 1

    readme = _read("README.md")
    docs_text = "\n".join(_read(path) for path in IMPORTANT_DOCS)
    reports_text = "\n".join(_read(path) for path in EXAMPLE_REPORTS)
    lowered_docs = docs_text.lower()

    _require_all("README.md", readme.lower(), README_REQUIRED, errors)
    _require_all("documentation", lowered_docs, SAFETY_REQUIRED, errors)
    _require_all("generated reports", reports_text, REPORT_REQUIRED, errors)
    _require_all("README.md", readme, CLI_EXAMPLES, errors)
    _reject_any("documentation", lowered_docs, UNVERIFIED_CLAIMS, errors)
    _reject_any("documentation", lowered_docs, UNSAFE_IMPLEMENTED_CLAIMS, errors)
    _reject_any("generated reports", reports_text, REPORT_FORBIDDEN, errors)

    if errors:
        _print_errors(errors)
        return 1
    print("Documentation safety checks passed.")
    return 0


def _check_files_exist(paths: tuple[str, ...], errors: list[str]) -> None:
    for path in paths:
        if not (ROOT / path).is_file():
            errors.append(f"missing required file: {path}")


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _require_all(
    label: str,
    text: str,
    required: tuple[str, ...],
    errors: list[str],
) -> None:
    for needle in required:
        if needle not in text:
            errors.append(f"{label} missing required text: {needle}")


def _reject_any(
    label: str,
    text: str,
    forbidden: tuple[str, ...],
    errors: list[str],
) -> None:
    for needle in forbidden:
        if needle in text:
            errors.append(f"{label} contains forbidden claim or output: {needle}")


def _print_errors(errors: list[str]) -> None:
    print("Documentation safety checks failed:")
    for error in errors:
        print(f"- {error}")


if __name__ == "__main__":
    raise SystemExit(main())
