# Testing Report

Current verified status: the full local pipeline (ingestion, classification, MITRE
mapping, explanations, triage playbooks, incident grouping, redaction, and
JSON/Markdown reporting), the CLI, and local CI/CodeQL/Dependabot configuration are
implemented and tested. See [docs/testing-guide.md](docs/testing-guide.md) for a
breakdown of what each area of the test suite covers.

## Commands

```bash
python -m pytest
python -m pytest --cov=triage_lab --cov-report=term-missing --cov-fail-under=97
python -m ruff check .
python -m ruff format --check .
python -m triage_lab --help
python -m triage_lab --version
python -m triage_lab report --input alerts/sample_alerts.json --output reports/examples --format both
python scripts/check-docs.py
python -m py_compile scripts/check-docs.py
```

## Verified Results

- `python -m pytest`: 256 passed, 97.29% total coverage from the configured test
  run.
- `python -m pytest --cov=triage_lab --cov-report=term-missing --cov-fail-under=97`:
  256 passed, 97.29% total coverage, and the 97% coverage gate passed.
- `python -m ruff check .`: all checks passed.
- `python -m ruff format --check .`: all files already formatted.
- `python scripts/check-docs.py`: documentation safety checks passed.
- `python -m py_compile scripts/check-docs.py`: passed.
- `python -m triage_lab --help` / `--version`: CLI help and version behave as
  documented in the README.
- CLI smoke through report generation passed locally, and the generated CLI/report
  output scan found no forbidden marker, credential, private-key, or raw-message
  patterns.
- Local CI is configured with three jobs: Tests (with the 97% coverage gate), Docs
  Safety Checks, and CLI Smoke. CodeQL is configured for Python with
  security-and-quality queries. Dependabot covers pip and GitHub Actions on a
  weekly schedule.

Hosted GitHub Actions and hosted CodeQL results have not been verified yet because
the repository has not been published.

## Pending Coverage

Future tests will cover hosted CI verification, branch protection, release
workflow behavior, tags, publishing, and release automation only after explicit
approval.

The project remains offline-only and uses synthetic/local alert data only.
