# Release Checklist

Release automation is not active. Local GitHub Actions workflow files, CodeQL
workflow files, Dependabot, and documentation safety checks are configured.
Hosted GitHub CI and CodeQL have not been verified yet. Branch protection, tags,
publishing, releases, and release workflow setup require explicit approval in a
later phase.

Before publishing or creating any release:

- Confirm the project remains offline-only.
- Confirm no network calls, live scanning, exploit code, external AI API, or
  external threat intelligence behavior exists.
- Confirm fixtures and examples are synthetic only.
- Run `python -m pytest`.
- Run `python -m pytest --cov=triage_lab --cov-report=term-missing --cov-fail-under=97`.
- Run `python -m ruff check .`.
- Run `python -m ruff format --check .`.
- Run `python scripts/check-docs.py`.
- Run `python -m py_compile scripts/check-docs.py`.
- Run the full CLI smoke command set through report generation.
- Scan generated reports and relevant CLI outputs for forbidden raw markers,
  credential-looking assignments, private-key markers, and `raw_message`.
- Confirm coverage is at least 97%.
- Regenerate example reports from synthetic data.
- Update `CHANGELOG.md`.
- Update `TESTING_REPORT.md`.
- Complete `PROJECT_COMPLETION_CHECKLIST.md`.

Do not mark these items complete before the relevant hosted or publishing action
actually occurs:

- Git initialized.
- Repository pushed to GitHub.
- Hosted GitHub Actions result verified.
- Hosted CodeQL result verified.
- Code scanning alerts reviewed.
- Secret scanning alerts reviewed.
- Dependabot PRs reviewed or merged.
- v0.1.0 tag created.
- GitHub Release created.
- Branch protection configured.

Publishing, tags, and release artifacts require explicit approval in a later
phase.
