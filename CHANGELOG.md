# Changelog

All notable changes will be documented in this file.

## 0.1.0 - Unreleased

- Added the core offline alert triage pipeline: local JSON/NDJSON ingestion with
  Pydantic validation and structured parse errors, deterministic severity
  classification from local YAML rules with traceable modifiers, local MITRE
  ATT&CK mapping from static YAML tables, deterministic analyst-style
  explanations, and local defensive triage playbook selection.
- Added deterministic incident grouping from local correlation rules, with
  severity rollups and redacted incident entity output.
- Added a centralized redaction engine and safe serializer that strip raw
  messages, source/destination IPs, usernames, and credential-looking values
  before any CLI or report output, plus a `redact-check` command for validating
  output safety directly.
- Added deterministic JSON and Markdown reporting built from a single safe
  `SecurityReport` model, a local report writer, and stable example reports
  under `reports/examples`.
- Added the full CLI: `inventory`, `validate-alerts`, `classify-alerts`,
  `map-mitre`, `explain-alerts`, `group-incidents`, `redact-check`, and
  `report`.
- Added local GitHub Actions CI (tests with a 97% coverage gate, documentation
  safety checks, and CLI smoke), a CodeQL workflow for Python, Dependabot
  configuration for pip and GitHub Actions, and a documentation safety script.
  Hosted CI and CodeQL have not been verified yet since the repository has not
  been published.
- Added the full documentation set (schema, configuration, safety model,
  redaction policy, reporting, testing guide, design decisions, release
  checklist) and coverage-hardening tests across config loading, ingestion,
  classification, MITRE mapping, explanations, triage, and grouping, reaching
  97.30% total coverage across 256 tests.

No release has been published.
