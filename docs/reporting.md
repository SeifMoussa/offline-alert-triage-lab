# Reporting

Phase 9 implements final deterministic JSON and Markdown report generation.

Reports are generated from local synthetic alert files only. The reporting
pipeline runs the existing local stages:

```text
ingest -> classify -> map MITRE -> explain -> group incidents -> redact -> report
```

The reports are deterministic, redacted, auditable, reproducible, and fully
testable. They use the Phase 8 safe serializer and redaction layer before report
rendering.

## CLI Usage

```bash
python -m triage_lab report --input alerts/sample_alerts.json --output reports/examples --format both
python -m triage_lab report --input alerts/sample_alerts.json --output reports/examples --format json
python -m triage_lab report --input alerts/sample_alerts.json --output reports/examples --format markdown
```

The report command writes stable filenames:

- `security_alert_triage_report.json`
- `security_alert_triage_report.md`

Output paths must be local directories. URLs, network paths, and parent-directory
traversal are rejected.

## Report Contents

Reports include:

- Safety disclaimer.
- Deterministic rule-based AI statement.
- Synthetic-data and offline-only scope.
- Executive summary.
- Severity summary.
- MITRE tactic and technique summary.
- Incident summary and details.
- Explained alert summaries.
- Triage recommendations.
- Redaction summary.
- Errors and malformed-record summary.
- Limitations.

Reports do not include `raw_message`, raw source IP values, raw destination IP
values, raw usernames, approved synthetic marker constants, or
credential-looking assignments such as `password=`, `token=`, `secret=`,
`api_key=`, or `private_key`.

Safe `.test` hostnames, alert IDs, event types, severity values, MITRE IDs,
incident IDs, template IDs, playbook IDs, correlation rule IDs, and timestamps
may remain visible.

## Safety Boundaries

Reporting makes no network calls, no external MITRE API calls, no external
threat intelligence calls, no LLM calls, and no external AI API calls.

CI, CodeQL, Dependabot, and docs safety checks are configured locally. Hosted
GitHub CI and CodeQL have not been verified yet. Publishing, tags, branch
protection, releases, and release workflow setup remain pending.
