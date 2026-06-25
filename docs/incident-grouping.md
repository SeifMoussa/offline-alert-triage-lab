# Incident Grouping

Phase 7 implements deterministic incident grouping for local synthetic alerts.
The grouping engine is rule-based, explainable, reproducible, and offline-only.
It does not use LLM calls, external AI APIs, API keys, network calls, external
MITRE APIs, threat intelligence services, scanning, exploit code, or response
automation.

## Pipeline

The `group-incidents` command runs:

```text
ingest -> classify -> map MITRE -> explain -> group incidents
```

The grouping stage does not mutate original alert models and does not print
`raw_message` by default.

## Rules

Rules are loaded from `config/grouping_rules.yaml` as local YAML data only.
Supported Phase 7 rule types include:

- Same source IP within a time window.
- Same username within a time window.
- Same hostname when a related alert is critical.
- Same local MITRE tactic within a time window.
- Authentication followed by privilege escalation or lateral movement.
- Multi-stage activity on the same safe lab hostname.

When alerts match multiple rules, the engine merges connected groups into one
incident. Incident IDs are assigned after deterministic sorting, such as
`INC-0001`.

## Safe Output

Incident output includes stable alert IDs, event types, time bounds, severity,
priority, local MITRE tactics and techniques, correlation reasons, and summary
text.

Source IPs and usernames are redacted as placeholders. Safe `.test` hostnames may
remain visible. Raw sensitive marker constants, credentials, tokens, and raw
messages are not included in incident output.

Phase 8 routes `group-incidents` CLI output through the final deterministic
redaction serializer. The serializer validates that report-ready output has no
raw approved marker constants, credential-looking assignments, unredacted
`source_ip` or `dest_ip` values, email-like usernames, or `raw_message` fields.

Phase 9 reports include incident summaries and incident details generated from
the redacted grouping output. Reports preserve incident IDs, event types,
timestamps, correlation rule IDs, safe `.test` hostnames, and MITRE context
without exposing raw source IPs, raw destination IPs, usernames, raw messages,
or marker constants.
