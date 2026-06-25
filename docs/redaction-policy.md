# Redaction Policy

Phase 8 implements deterministic redaction and safe serialization for CLI output
and report-ready payloads. Phase 9 reports consume this layer before JSON and
Markdown rendering.

The redaction layer is local, rule-based, auditable, reproducible, and fully
testable. It does not use LLM calls, external AI APIs, API keys, stochastic
generation, network calls, external MITRE APIs, or external threat intelligence.

## Default Policy

The default policy is `default-report-safe-v1`.

It performs these actions before output is considered report-ready:

- Removes `raw_message` fields by default.
- Replaces `source_ip` and `dest_ip` values with `[REDACTED:ip]`.
- Replaces `username` values with `[REDACTED:username]`.
- Replaces approved synthetic marker constants with `[REDACTED:marker]`.
- Replaces credential-looking text with `[REDACTED:credential]`.

Approved fake marker constants are:

- `SYNTHETIC_PASSWORD_MARKER`
- `SYNTHETIC_TOKEN_MARKER`
- `SYNTHETIC_SECRET_MARKER`

These markers may appear in fixtures and tests only. They are not allowed in CLI
or report-ready output.

Credential-looking patterns include:

- `password=...`
- `token=...`
- `secret=...`
- `api_key=...`
- `private_key...`

## Preserved Safe Metadata

The serializer preserves useful non-sensitive context, including:

- `alert_id`
- `event_type`
- severity values
- MITRE technique IDs and names
- MITRE tactics
- `template_id`
- `playbook_id`
- `incident_id`
- correlation rule IDs
- timestamps
- safe `.test` hostnames

Safe project terms such as CodeQL, GitHub Actions, pytest, Ruff, MITRE, and
ATT&CK are not redacted.

## Validation

The validator returns structured errors instead of crashing when output remains
unsafe. It fails payloads containing raw approved marker constants,
credential-looking assignments, `private_key`, unredacted IP fields,
email-looking usernames, or `raw_message` fields under the default policy.

## Scope Boundary

Phase 9 JSON and Markdown reports use this safe serialization layer. Reports
must not contain raw marker constants, raw messages, raw IP values, raw
usernames, or credential-looking assignments.

Documentation safety checks verify generated reports for these forbidden output
patterns. Hosted GitHub CI and CodeQL have not been verified yet.
