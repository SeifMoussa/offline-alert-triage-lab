# Design Decisions

This project treats "AI-assisted" as deterministic expert-system behavior, not
as external AI or stochastic generation.

## Current Decisions

- Use a `src` layout with import package `triage_lab`.
- Use `argparse` for the CLI to keep dependencies minimal.
- Use `pydantic` for validation and `PyYAML` for local YAML loading.
- Keep YAML files as data-only configuration.
- Keep all examples offline-only and synthetic.
- Use JSON-parseable malformed fixtures to represent schema problems without
  implementing the ingestion engine early.
- Use static local MITRE mapping data and no external MITRE or threat
  intelligence calls.
- Use fake marker constants only for sensitive-data test coverage.
- Implement loading for JSON arrays, single JSON objects, and simple
  NDJSON while deferring CSV.
- Reject URLs, network paths, and parent-directory traversal before reading
  input paths.
- Return structured parse errors instead of raising uncaught CLI exceptions for
  malformed or invalid alert input.
- Load severity behavior from local YAML instead of hardcoding the
  ruleset in Python.
- Keep classification output safe by omitting `raw_message` and exposing only
  rule IDs, severity transitions, and sanitized reasons.
- Apply modifiers in YAML order so results are deterministic and testable.
- Load MITRE behavior from local YAML and generate MITRE URLs as static
  strings from technique IDs.
- Treat policy and unknown events as local fallback mappings rather than forcing
  an ATT&CK technique where no direct mapping is configured.
- Generate analyst-style explanations with deterministic local
  templates, never LLM calls or stochastic text generation.
- Select triage recommendations from local YAML playbooks using
  event-type, severity, event fallback, and documented global fallback matching.
- Omit `raw_message` from explanation CLI output by default and sanitize fake
  sensitive marker constants in generated text.
- Implement incident grouping as deterministic graph correlation:
  grouping rules create alert edges, connected components become incidents, and
  incident IDs are assigned after stable sorting.
- Redact source IPs and usernames in incident output while allowing safe `.test`
  hostnames to remain visible.
- Implement redaction as a centralized deterministic safe serialization
  layer rather than scattered output checks.
- Remove `raw_message` fields by default for report-ready serialization.
- Redact `source_ip`, `dest_ip`, `username`, approved fake marker constants, and
  credential-looking patterns before CLI output and reports.
- Preserve safe metadata needed by analysts and reports, including alert IDs,
  event types, severities, MITRE metadata, template IDs, playbook IDs, incident
  IDs, correlation rule IDs, timestamps, and safe `.test` hostnames.
- Add `redact-check` as a narrow validation command for redacted grouped output;
  it does not generate reports.
- Implement reports as renderers over one safe `SecurityReport` model
  instead of separate JSON and Markdown data paths.
- Use a deterministic default report timestamp for stable tests and example
  reports.
- Route report payloads through the redaction/safe serialization layer
  before rendering.
- Reject unsafe report output paths with the existing local path validator.
- Configure GitHub workflows, CodeQL, and Dependabot locally only; defer hosted
  verification, tags, releases, branch protection, and publishing.
- Build trend analytics as a read-only aggregator over local report history
  instead of adding a database or long-running service. Each run is its own
  local directory holding the existing redacted `report` JSON output, so no
  new persistence mechanism is introduced.
- Compute false-positive rate only from an optional local
  `triage_outcomes.json` file that an analyst hand-authors per run, and report
  it as unavailable rather than assumed zero when that file is missing, since
  nothing else in the pipeline tracks ground-truth disposition.

## Pending Decisions

Publishing, hosted CI verification, hosted CodeQL verification, branch
protection, tags, releases, and release automation require explicit approval
before they happen.

No pending decision should introduce network calls, live scanning, exploit code,
or external AI API behavior.
