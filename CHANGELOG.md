# Changelog

All notable changes will be documented in this file.

## 0.1.0 - Unreleased

- Created Phase 1 scaffold for an offline-only deterministic security alert
  triage lab.
- Added minimal CLI help/version support.
- Added safety constants, documentation placeholders, config placeholders, and
  scaffold tests.
- Added Phase 2 synthetic alert datasets, local YAML configuration, schema and
  configuration docs, and fixture/config safety tests.
- Added Phase 3 Pydantic alert models, local JSON/NDJSON ingestion, structured
  parse-error handling, safe inventory and validation CLI commands, and
  ingestion safety tests.
- Added Phase 4 deterministic severity classification from local YAML rules,
  traceable modifiers and overrides, safe `classify-alerts` CLI output, and
  classification tests.
- Added Phase 5 local static MITRE ATT&CK mapping from YAML, static MITRE URL
  generation, safe `map-mitre` CLI output, and MITRE mapping tests.
- Added Phase 6 deterministic analyst-style explanations, local defensive
  triage playbook selection, safe `explain-alerts` CLI output, and explanation
  and playbook tests.
- Added Phase 7 deterministic incident grouping, local grouping rules, safe
  `group-incidents` CLI output, redacted incident entity fields, and grouping
  tests.
- Added Phase 7.5 coverage hardening tests for real edge cases across config
  loading, ingestion, classification, MITRE mapping, explanations, triage,
  grouping, and model serialization, raising total coverage to 98.60% with 221
  tests and no Phase 8 functionality.
- Added Phase 8 deterministic redaction models, redaction policy, recursive
  redaction engine, safe serializer, structured output validator, CLI
  integration for report-ready payload safety, and `redact-check` command
  without adding final Markdown/JSON reports.
- Added Phase 9 deterministic JSON and Markdown reporting, report models,
  report pipeline, renderers, local report writer, safe `report` CLI command,
  and stable redacted example reports without adding CI, CodeQL, publishing,
  tags, or releases.
- Added Phase 10 local CI workflow configuration, CodeQL workflow
  configuration, Dependabot configuration, documentation safety checks, and
  workflow/config tests without initializing git, publishing, creating tags, or
  creating a release.
- Added Phase 11 documentation polish, recruiter-ready README updates,
  `RELEASE.md`, portfolio materials, release preparation checklists, example
  report review, and final local QA preparation without initializing git,
  publishing, creating tags, creating a release, or configuring branch
  protection.

No release has been published.
