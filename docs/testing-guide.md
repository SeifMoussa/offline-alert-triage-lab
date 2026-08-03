# Testing Guide

The test suite must preserve the project's defensive, offline-only,
synthetic-data safety model.

## Core Quality Commands

```bash
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m triage_lab --help
python -m triage_lab --version
```

## Current Coverage

Scaffold tests verify:

- Package importability.
- Version metadata.
- CLI help and version behavior.
- Safety summary wording.
- Presence of config and documentation placeholders.

Dataset and configuration tests verify:

- Expected JSON fixture and YAML config files exist.
- JSON fixtures are parseable.
- YAML config files are parseable.
- Valid alerts include required fields and `synthetic_marker: true`.
- All required event types are represented.
- Fixture IP addresses stay inside approved synthetic ranges.
- Hostnames and domains use `.test` or approved example domains.
- Sensitive marker fixtures contain only approved fake marker constants.
- Config files do not define network behavior, API-key placeholders, or
  executable offensive-tool integrations.

Ingestion tests verify:

- Pydantic alert model validation.
- Missing required fields.
- Invalid timestamps, IP ranges, ports, counts, hostnames, usernames, event
  types, and raw-message content.
- JSON array loading.
- Single JSON object loading.
- Simple NDJSON loading.
- Malformed JSON handling.
- Empty file handling.
- Directory inventory loading.
- Unsupported extension behavior.
- Path traversal, URL, and UNC path rejection.
- CLI `inventory` and `validate-alerts` JSON/text output.
- Redaction of sensitive-looking CLI error output.

Classification tests verify:

- Severity enum ordering and capped severity raising.
- Base event-type severity mappings from local YAML.
- Safe default severity for unrecognized event types.
- Count, sensitive port, privileged username, internal asset, honeypot, and
  synthetic marker modifiers.
- Known synthetic bad IP override to `CRITICAL`.
- Deterministic modifier order and `CRITICAL` cap.
- Rules config loading, invalid config errors, and custom local config support.
- Config URL and path-traversal rejection.
- `classify-alerts` JSON/text CLI output.
- No raw sensitive marker constants in classification output.

MITRE mapping tests verify:

- MITRE model serialization.
- Local MITRE mapping config loading.
- Invalid MITRE config errors.
- Custom local MITRE config support.
- Config URL and path-traversal rejection.
- Static MITRE URL generation for techniques and sub-techniques.
- Expected event-type to technique mappings.
- Policy and unknown fallback mappings.
- `map-mitre` JSON/text CLI output.
- Existing inventory, validation, classification, help, and version commands.
- No raw sensitive marker constants in MITRE output.

Explanation and triage tests verify:

- Explanation model serialization and safe output shape.
- Deterministic template selection by event type and severity.
- Safe fallback explanation behavior for unknown or unmapped events.
- Modifier references and MITRE context in generated explanations.
- No unfilled template placeholders.
- Omission of `raw_message` by default.
- Redaction or absence of raw fake sensitive marker constants.
- Local triage playbook loading, invalid config errors, and custom local config
  support.
- Triage config URL and path-traversal rejection.
- Event-type plus severity playbook selection, event fallback selection, and
  documented global fallback selection.
- `explain-alerts` JSON/text CLI output.
- Existing inventory, validation, classification, MITRE mapping, help, and
  version commands.
- No network calls, external AI/API behavior, or unsafe output.

Incident grouping tests verify:

- Incident and grouping model serialization.
- Priority mapping from severity to `P1` through `P4`.
- Local grouping config loading and invalid config errors.
- Custom local grouping config support.
- Grouping config URL and path-traversal rejection.
- Same source IP, username, hostname, MITRE tactic, event-chain, and multi-stage
  host correlation rules.
- Deterministic merging of connected alert groups.
- Stable incident IDs and deterministic incident sorting.
- Highest-severity incident rollups.
- Redaction of source IPs and usernames in incident output.
- Preservation of safe `.test` hostnames.
- Omission of `raw_message` and fake sensitive marker constants.
- `group-incidents` JSON/text CLI output.
- Existing inventory, validation, classification, MITRE mapping, explanation,
  help, and version commands.
- No network calls, external AI/API behavior, or unsafe output.

Coverage-hardening tests verify:

- Config loader error paths.
- Classification condition and fallback branches.
- MITRE, explanation, triage, grouping, ingestion, and model edge cases.
- Coverage above 97% without removing code or weakening safety checks.

Redaction tests verify:

- Redaction models and summary serialization.
- Recursive dict, list, tuple, and set redaction.
- Pydantic model redaction through safe serialization.
- Source IP, destination IP, username, raw-message, marker, and
  credential-looking pattern redaction.
- Original input objects are not mutated.
- Safe `.test` hostnames, MITRE IDs, alert IDs, incident IDs, severities, and
  safe project terms are preserved.
- Redaction summaries count categories without exposing raw values.
- Safe-output validation fails when prohibited markers, credential-looking
  assignments, raw IP fields, email-like usernames, or `raw_message` remain.
- CLI integration for `classify-alerts`, `map-mitre`, `explain-alerts`, and
  `group-incidents`.
- The `redact-check` command reports redaction summary and validation status.
- Help/version still work.
- No network calls, external AI/API behavior, or unsafe output.

Reporting tests verify:

- Report model creation and summary counts.
- Full reporting pipeline output.
- JSON report validity and safety.
- Markdown report sections, incident IDs, MITRE summary, triage
  recommendations, redaction summary, safety disclaimer, and deterministic AI
  wording.
- Report writer behavior for JSON, Markdown, and both formats.
- Output URL, network path, and path traversal rejection.
- Report CLI JSON, Markdown, and both modes.
- Existing CLI commands continue to work.
- Generated reports do not expose raw messages, raw entity values, approved
  marker constants, credential-looking assignments, or private-key markers.
- No network calls, external AI/API behavior, or unsafe output.

Trend analytics tests verify:

- Local `triage_outcomes.json` loading, disposition validation, and malformed
  JSON handling.
- Local run-history loading, deterministic run ordering, and history
  directory URL/path-traversal rejection.
- Structured errors for a missing report file, unreadable/malformed report
  JSON, a report missing required summary fields, and an invalid outcomes
  file, without failing the rest of the trend report.
- Alert-volume trend ordering, top-MITRE-technique ranking, and
  false-positive-rate averaging over only the runs with reviewed outcomes.
- `trend-report` JSON/text CLI output and exit codes.
- No `raw_message`, sensitive marker constants, or network/API-key mentions in
  trend analytics output.

Automation configuration tests verify:

- `.github/workflows/ci.yml` exists.
- `.github/workflows/codeql.yml` exists.
- `.github/dependabot.yml` exists.
- CI has stable job names: Tests, Docs Safety Checks, and CLI Smoke.
- CI uses a 97% coverage gate.
- CI runs pytest, Ruff, docs safety checks, and representative CLI smoke.
- CodeQL targets Python and uses security-and-quality queries.
- Dependabot covers pip and GitHub Actions only.
- `scripts/check-docs.py` exists, imports, compiles, and executes.
- Documentation does not claim hosted CI or CodeQL has passed yet.
- Documentation does not claim publishing or releases have happened.
- README and example reports remain consistent.

## Local Quality Commands

```bash
python -m pytest
python -m pytest --cov=triage_lab --cov-report=term-missing --cov-fail-under=97
python -m ruff check .
python -m ruff format --check .
python scripts/check-docs.py
python -m py_compile scripts/check-docs.py
```

The local CI coverage gate is 97%. Hosted GitHub CI and hosted CodeQL have not
been verified yet.

## Pending Coverage

Future tests will cover hosted CI verification, branch protection, release
workflow behavior, tags, publishing, and release automation only after explicit
approval.

Fixtures must use synthetic/local alert data only.
