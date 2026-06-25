# Report Schema

Phase 9 implements deterministic JSON and Markdown report generation.

Reports are generated from synthetic local alert data only and consume the Phase
8 deterministic redaction and safe serialization layer.

## JSON Sections

- Report metadata.
- Alert validation summary.
- Classified alert summaries.
- Local MITRE mappings.
- Template-driven explanations.
- Local triage steps.
- Incident grouping summaries.
- Redaction metadata.
- Tool version.

## Markdown Sections

- Executive summary.
- Severity distribution.
- Incident summary.
- Alert details.
- MITRE mapping table.
- Triage recommendations.
- Redaction summary.
- Deterministic trace notes.

Reports must never require network calls or external enrichment. They must not
include real customer data, real credentials, real tokens, or private
information.

Report-ready payloads must not include `raw_message`, raw source IP values, raw
destination IP values, raw usernames, approved fake marker constants, or
credential-looking assignments such as `password=`, `token=`, `secret=`,
`api_key=`, or `private_key`.

Safe report fields may include alert IDs, event types, severity values, MITRE
technique IDs/names, tactics, template IDs, playbook IDs, incident IDs,
correlation rule IDs, timestamps, and safe `.test` hostnames.

The `report` CLI writes stable example filenames:

- `reports/examples/security_alert_triage_report.json`
- `reports/examples/security_alert_triage_report.md`

CI, CodeQL, and Dependabot are configured locally. Hosted verification,
publishing, tags, branch protection, and releases remain pending.
