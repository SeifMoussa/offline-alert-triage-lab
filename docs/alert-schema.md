# Alert Schema

The project uses Pydantic validation for synthetic local alert datasets.

All alert data must be synthetic, local, and offline-only. The project makes no
network calls, uses no external AI API, and performs no live threat intelligence
lookups.

## Required Fields

- `alert_id`: stable synthetic string identifier.
- `timestamp`: ISO-8601 timestamp string.
- `source_ip`: source IP from an approved private or documentation range.
- `dest_ip`: destination IP from an approved private or documentation range.
- `event_type`: supported event type string.
- `raw_message`: synthetic analyst-readable message.
- `synthetic_marker`: must be `true` for valid synthetic datasets.

## Optional Fields

- `source_port`: integer source port.
- `dest_port`: integer destination port.
- `username`: synthetic username.
- `hostname`: synthetic hostname.
- `count`: integer observation count.
- `tags`: list of strings.

## Supported Event Types

- `failed_login`
- `brute_force`
- `port_scan`
- `privilege_escalation`
- `data_exfiltration`
- `lateral_movement`
- `malware_detected`
- `c2_beacon`
- `policy_violation`
- `anomalous_login_time`
- `unknown`

## Approved Synthetic Values

Approved username examples:

- `analyst_user`
- `test_admin`
- `demo_user`
- `service_account_test`
- `lab_user`

Approved hostname examples:

- `workstation-01.test`
- `server-01.test`
- `domain-controller.test`
- `web-gateway.test`
- `file-server.test`

Approved sensitive marker constants for tests only:

- `SYNTHETIC_PASSWORD_MARKER`
- `SYNTHETIC_TOKEN_MARKER`
- `SYNTHETIC_SECRET_MARKER`

These marker constants are fake test markers, not credentials, tokens, or
secrets.

## Safety Constraints

IP addresses must stay within approved private or documentation ranges. Domains
and hostnames must use `example.com`, `example.org`, `example.net`, or `.test`.
Datasets must not contain real usernames, emails, passwords, tokens, hostnames,
company names, customer data, or private information.

## Validation Behavior

The `AlertRecord` model validates:

- Required fields are present.
- `timestamp` parses as an ISO-8601 datetime.
- `source_ip` and `dest_ip` are inside approved synthetic ranges.
- Optional ports are between `1` and `65535`.
- Optional `count` is non-negative.
- Optional `username` is not an email address.
- Optional `hostname` uses `.test` or an approved example domain.
- `event_type` is one of the supported values.
- `raw_message` does not contain credential-looking strings or unapproved
  domains.
- `tags` contains strings.
- `synthetic_marker` is `true`.

Validation errors are returned as structured parse errors by the ingestion
layer.

After validation, the local pipeline classifies severity, maps events to static
MITRE examples, generates deterministic explanations, selects defensive triage
steps, groups related alerts into incidents, applies redaction, and writes JSON
and Markdown reports.

The mapper and reporting pipeline do not print `raw_message` content in CLI or
report output. Report-ready serialization removes `raw_message` by default,
redacts `source_ip`, `dest_ip`, and `username` values, and redacts approved fake
marker constants and credential-looking patterns. Safe alert IDs, event types,
severity values, MITRE metadata, incident IDs, timestamps, and `.test` hostnames
may remain visible.
