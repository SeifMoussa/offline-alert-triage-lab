# Testing Report

Current phase: Phase 11 documentation polish, release preparation, portfolio
materials, and final local QA before publishing.

The current tests verify package importability, version metadata, minimal CLI
help/version behavior, safety summary wording, expected file inventory, JSON
fixture parseability, YAML config parseability, required synthetic alert fields,
event-type coverage, approved IP and hostname usage, approved sensitive marker
constants, absence of network/API-key/offensive integration config, Pydantic
alert validation, local JSON/NDJSON loading, structured parse errors, directory
inventory, safe CLI validation output, severity rules loading, deterministic
modifier logic, classification safety, `classify-alerts` output, local MITRE
mapping config loading, static MITRE URL generation, fallback mappings,
`map-mitre` output, deterministic explanation generation, local triage playbook
selection, safe `explain-alerts` output, explanation/playbook safety, local
grouping config loading, deterministic incident correlation, redacted incident
entity output, safe `group-incidents` output, and Phase 7.5 edge-case coverage
for config validation, classifier fallback behavior, ingestion serialization,
MITRE/playbook fallbacks, and model helper branches. Phase 8 tests verify the
final deterministic redaction models, recursive redaction engine, safe
serializer, output validator, CLI integration, and `redact-check` command.
Phase 9 tests verify report models, the full reporting pipeline, JSON and
Markdown renderers, local report writing, report CLI behavior, generated report
safety, and continued existing CLI compatibility. Phase 10 tests verify local
workflow configuration, CodeQL configuration, Dependabot configuration,
documentation consistency, and the docs safety script.

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

## Phase 1 Verification

- `python -m pytest`: 10 passed, 100% coverage.
- `python -m ruff check .`: all checks passed.
- `python -m ruff format --check .`: 16 files already formatted.
- `python -m triage_lab --help`: displayed Phase 1 CLI help and safety model.
- `python -m triage_lab --version`: displayed `triage-lab 0.1.0`.

## Phase 2 Verification

- `python -m pytest`: 25 passed, 100% coverage.
- `python -m ruff check .`: all checks passed.
- `python -m ruff format --check .`: 19 files already formatted.
- `python -m triage_lab --help`: displayed CLI help and safety model.
- `python -m triage_lab --version`: displayed `triage-lab 0.1.0`.

## Phase 3 Verification

- `python -m pytest`: 66 passed, 96.74% total coverage.
- `python -m ruff check .`: all checks passed.
- `python -m ruff format --check .`: 31 files already formatted.
- `python -m triage_lab --help`: displayed CLI help with `inventory` and
  `validate-alerts`.
- `python -m triage_lab --version`: displayed `triage-lab 0.1.0`.
- `python -m triage_lab inventory --input alerts --format json`: loaded 22
  alerts from 1 JSON file, counted 1 unsupported local README file, and found no
  validation errors.
- `python -m triage_lab validate-alerts --input alerts/sample_alerts.json
  --format json`: returned `valid: true`, 22 records seen, 22 alerts loaded,
  and 0 errors.
- `python -m triage_lab validate-alerts --input alerts/sample_alerts.json
  --format text`: returned the same successful validation summary as text.

## Phase 4 Verification

- `python -m pytest`: 93 passed, 92.46% total coverage.
- `python -m ruff check .`: all checks passed.
- `python -m ruff format --check .`: 41 files already formatted.
- `python -m triage_lab --help`: displayed CLI help with `inventory`,
  `validate-alerts`, and `classify-alerts`.
- `python -m triage_lab --version`: displayed `triage-lab 0.1.0`.
- `python -m triage_lab inventory --input alerts --format json`: loaded 22
  alerts from 1 JSON file, counted 1 unsupported local README file, and found no
  validation errors.
- `python -m triage_lab validate-alerts --input alerts/sample_alerts.json
  --format json`: returned `valid: true`, 22 records seen, 22 alerts loaded,
  and 0 errors.
- `python -m triage_lab classify-alerts --input alerts/sample_alerts.json
  --format json`: classified 22 alerts, highest severity `CRITICAL`, severity
  counts `LOW: 4`, `MEDIUM: 2`, `HIGH: 2`, `CRITICAL: 14`, and 0 errors.
- `python -m triage_lab classify-alerts --input alerts/sample_alerts.json
  --format text`: returned the same successful classification summary as text.

## Phase 5 Verification

- `python -m pytest`: 112 passed, 91.28% total coverage.
- `python -m ruff check .`: all checks passed.
- `python -m ruff format --check .`: 49 files already formatted.
- `python -m triage_lab --help`: displayed CLI help with `inventory`,
  `validate-alerts`, `classify-alerts`, and `map-mitre`.
- `python -m triage_lab --version`: displayed `triage-lab 0.1.0`.
- `python -m triage_lab inventory --input alerts --format json`: loaded 22
  alerts from 1 JSON file, counted 1 unsupported local README file, and found no
  validation errors.
- `python -m triage_lab validate-alerts --input alerts/sample_alerts.json
  --format json`: returned `valid: true`, 22 records seen, 22 alerts loaded,
  and 0 errors.
- `python -m triage_lab classify-alerts --input alerts/sample_alerts.json
  --format json`: classified 22 alerts, highest severity `CRITICAL`, severity
  counts `LOW: 4`, `MEDIUM: 2`, `HIGH: 2`, `CRITICAL: 14`, and 0 errors.
- `python -m triage_lab classify-alerts --input alerts/sample_alerts.json
  --format text`: returned the same successful classification summary as text.
- `python -m triage_lab map-mitre --input alerts/sample_alerts.json
  --format json`: mapped 22 alerts, mapping counts `mapped: 18`,
  `fallback: 4`, observed 8 technique IDs, and found 0 errors.
- `python -m triage_lab map-mitre --input alerts/sample_alerts.json
  --format text`: returned the same successful MITRE mapping summary as text.

## Phase 6 Verification

- `python -m pytest`: 135 passed, 90.63% total coverage from the configured
  test run.
- `python -m pytest --cov=triage_lab --cov-report=term-missing`: 135 passed,
  90.63% total coverage.
- `python -m ruff check .`: all checks passed.
- `python -m ruff format --check .`: 62 files already formatted.
- `python -m triage_lab --help`: displayed CLI help with `inventory`,
  `validate-alerts`, `classify-alerts`, `map-mitre`, and `explain-alerts`.
- `python -m triage_lab --version`: displayed `triage-lab 0.1.0`.
- `python -m triage_lab inventory --input alerts --format json`: loaded 22
  alerts from 1 JSON file, counted 1 unsupported local README file, and found no
  validation errors.
- `python -m triage_lab validate-alerts --input alerts/sample_alerts.json
  --format json`: returned `valid: true`, 22 records seen, 22 alerts loaded,
  and 0 errors.
- `python -m triage_lab classify-alerts --input alerts/sample_alerts.json
  --format json`: classified 22 alerts, highest severity `CRITICAL`, severity
  counts `LOW: 4`, `MEDIUM: 2`, `HIGH: 2`, `CRITICAL: 14`, and 0 errors.
- `python -m triage_lab map-mitre --input alerts/sample_alerts.json
  --format json`: mapped 22 alerts, mapping counts `mapped: 18`,
  `fallback: 4`, observed 8 technique IDs, and found 0 errors.
- `python -m triage_lab explain-alerts --input alerts/sample_alerts.json
  --format json`: explained 22 alerts, severity counts `LOW: 4`, `MEDIUM: 2`,
  `HIGH: 2`, `CRITICAL: 14`, observed 8 MITRE tactics, and found 0 errors.
- `python -m triage_lab explain-alerts --input alerts/sample_alerts.json
  --format text`: returned the same successful explanation summary as text.

## Phase 7 Verification

- `python -m pytest`: 161 passed, 91.00% total coverage from the configured
  test run.
- `python -m pytest --cov=triage_lab --cov-report=term-missing`: 161 passed,
  91.00% total coverage.
- `python -m ruff check .`: all checks passed.
- `python -m ruff format --check .`: 74 files already formatted.
- `python -m triage_lab --help`: displayed CLI help with `inventory`,
  `validate-alerts`, `classify-alerts`, `map-mitre`, `explain-alerts`, and
  `group-incidents`.
- `python -m triage_lab --version`: displayed `triage-lab 0.1.0`.
- `python -m triage_lab inventory --input alerts --format json`: loaded 22
  alerts from 1 JSON file, counted 1 unsupported local README file, and found no
  validation errors.
- `python -m triage_lab validate-alerts --input alerts/sample_alerts.json
  --format json`: returned `valid: true`, 22 records seen, 22 alerts loaded,
  and 0 errors.
- `python -m triage_lab classify-alerts --input alerts/sample_alerts.json
  --format json`: classified 22 alerts, highest severity `CRITICAL`, severity
  counts `LOW: 4`, `MEDIUM: 2`, `HIGH: 2`, `CRITICAL: 14`, and 0 errors.
- `python -m triage_lab map-mitre --input alerts/sample_alerts.json
  --format json`: mapped 22 alerts, mapping counts `mapped: 18`,
  `fallback: 4`, observed 8 technique IDs, and found 0 errors.
- `python -m triage_lab explain-alerts --input alerts/sample_alerts.json
  --format json`: explained 22 alerts, severity counts `LOW: 4`, `MEDIUM: 2`,
  `HIGH: 2`, `CRITICAL: 14`, observed 8 MITRE tactics, and found 0 errors.
- `python -m triage_lab group-incidents --input alerts/sample_alerts.json
  --format json`: grouped 22 alerts into 1 incident, left 0 ungrouped alerts,
  highest incident severity `CRITICAL`, and found 0 errors.
- `python -m triage_lab group-incidents --input alerts/sample_alerts.json
  --format text`: returned the same successful incident grouping summary as
  text.

## Phase 7.5 Verification

- `python -m pytest --cov=triage_lab --cov-report=term-missing`: 221 passed,
  98.60% total coverage.
- Added focused coverage-hardening tests for local config loader error paths,
  classification fallback/condition branches, explanation and triage fallback
  behavior, ingestion edge cases, safe serialization, and enum/helper branches.
- No Phase 8 functionality was added.
- No final redaction engine, final Markdown/JSON reports, workflows, tags,
  release artifacts, or publishing steps were added.

## Phase 8 Verification

- `python -m pytest --cov=triage_lab --cov-report=term-missing`: 235 passed,
  97.99% total coverage during implementation verification.
- Added deterministic redaction models, policy, recursive redaction engine,
  safe serializer, and structured output validator tests.
- Added CLI integration tests for `classify-alerts`, `map-mitre`,
  `explain-alerts`, `group-incidents`, and `redact-check`.
- Verified redaction removes or masks `raw_message`, source IPs, destination
  IPs, usernames, approved fake marker constants, and credential-looking
  patterns while preserving safe IDs, MITRE metadata, severities, timestamps,
  and `.test` hostnames.
- No final Markdown/JSON reports, workflows, tags, release artifacts, or
  publishing steps were added.

## Phase 9 Verification

- `python -m pytest --cov=triage_lab --cov-report=term-missing`: 249 passed,
  97.29% total coverage during implementation verification.
- Added report models, deterministic report pipeline, JSON renderer, Markdown
  renderer, local report writer, and report CLI tests.
- Generated stable example reports:
  `reports/examples/security_alert_triage_report.json` and
  `reports/examples/security_alert_triage_report.md`.
- Verified reports include safety disclaimer, deterministic rule-based AI
  wording, synthetic-data scope, incident summary, MITRE summary, triage
  recommendations, redaction summary, limitations, and errors/malformed-record
  summary.
- Verified generated reports do not include raw messages, raw source IPs, raw
  destination IPs, raw usernames, approved fake marker constants,
  credential-looking assignments, or private-key markers.
- No CI, CodeQL, Dependabot, workflows, tags, release artifacts, publishing
  steps, or releases were added.

## Phase 10 Verification

- `python -m pytest`: 256 passed, 97.29% total coverage from the configured
  test run.
- `python -m pytest --cov=triage_lab --cov-report=term-missing
  --cov-fail-under=97`: 256 passed, 97.29% total coverage, and the 97%
  coverage gate passed.
- `python -m ruff check .`: all checks passed.
- `python -m ruff format --check .`: 103 files already formatted.
- `python scripts/check-docs.py`: documentation safety checks passed.
- `python -m py_compile scripts/check-docs.py`: passed.
- CLI smoke through report generation passed locally, and the generated
  CLI/report output scan found no forbidden marker, credential, private-key, or
  raw-message patterns.
- Local CI configuration added with stable jobs: Tests, Docs Safety Checks, and
  CLI Smoke.
- CI coverage gate configured at 97% with
  `python -m pytest --cov=triage_lab --cov-report=term-missing
  --cov-report=xml --cov-fail-under=97`.
- Ruff lint and format checks configured in CI.
- Documentation safety checks configured with `python scripts/check-docs.py`.
- CLI smoke configured for the full local command set through report
  generation.
- CodeQL workflow configured for Python with security-and-quality queries.
- Dependabot configured for pip and GitHub Actions weekly updates.
- Hosted GitHub CI and CodeQL have not been verified yet.
- No git initialization, branch protection, publishing, tags, releases, or
  release workflow setup were added.

## Phase 11 Verification

- README polished for recruiter-facing project review.
- Documentation polished for implemented features and pending hosted checks.
- `RELEASE.md` added with release preparation notes, publishing commands,
  checklists, portfolio copy, LinkedIn draft, and CV bullets.
- Example reports reviewed for required sections and public safety.
- `python -m pytest`: 256 passed, 97.29% total coverage from the configured
  test run.
- `python -m pytest --cov=triage_lab --cov-report=term-missing
  --cov-fail-under=97`: 256 passed, 97.29% total coverage, and the 97%
  coverage gate passed.
- `python -m ruff check .`: all checks passed.
- `python -m ruff format --check .`: 103 files already formatted.
- `python scripts/check-docs.py`: documentation safety checks passed.
- `python -m py_compile scripts/check-docs.py`: passed.
- CLI smoke through report generation passed locally.
- Generated report and relevant CLI output scans found no forbidden marker,
  credential, private-key, or raw-message patterns.
- Hygiene cleanup removed generated cache, coverage, and bytecode artifacts
  after validation.
- No git initialization, publishing, tags, releases, branch protection, or
  hosted-status claims were added.

The project remains offline-only and uses synthetic/local alert data only.
Future tests will cover hosted CI verification, branch protection, release
workflow behavior, tags, publishing, and release automation only after explicit
approval.
