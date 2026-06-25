# Safety Model

The AI-Assisted Security Alert Triage Lab is defensive, offline-only, and limited
to synthetic/local alert data.

## Non-Negotiable Boundaries

- No network calls.
- No live scanning.
- No exploit code.
- No attack automation.
- No malware behavior.
- No external AI API, LLM, or API-key integration.
- No external threat intelligence API calls.
- No real customer data.
- No real credentials, tokens, or private information.

## Approved Example Data

Examples may use private lab ranges and reserved documentation ranges:

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`
- `192.0.2.0/24`
- `198.51.100.0/24`
- `203.0.113.0/24`

Examples may use `example.com`, `example.org`, `example.net`, and `.test`
domains only.

## Safety Enforcement

The package provides constants and summary text in `triage_lab.safety`. The
pipeline enforces these boundaries during path validation, alert validation,
redaction, report generation, and documentation safety checks.

## Phase 2 Dataset and Config Safety

Phase 2 adds synthetic JSON fixtures and local YAML configuration. These files
must remain offline-only and synthetic. They must not contain real usernames,
emails, passwords, tokens, hostnames, company names, customer data, public
production IP addresses, external enrichment URLs, or executable integrations.

The approved fake sensitive marker constants are:

- `SYNTHETIC_PASSWORD_MARKER`
- `SYNTHETIC_TOKEN_MARKER`
- `SYNTHETIC_SECRET_MARKER`

These are documentation and test markers only. They are not secrets.

## Phase 3 Ingestion Safety

Phase 3 reads local JSON files only. It accepts JSON arrays, single JSON alert
objects, and simple newline-delimited JSON records. It rejects URLs, network
paths, and parent-directory traversal before reading input.

The CLI prints structured summaries and validation errors. It does not contact
external services, perform enrichment, scan hosts, execute tooling, or use
external AI. Sensitive-looking values and approved fake marker constants are
masked in CLI error output.

## Phase 4 Classification Safety

Phase 4 classification is local, rule-based, deterministic, and explainable. It
loads `config/rules.yaml` from disk, validates the config safety flags, and
rejects URL, network, or path-traversal config paths.

The classifier does not make network calls, perform live scanning, use external
AI APIs, request API keys, or call threat intelligence services. CLI
classification output does not include full `raw_message` content or raw
sensitive marker constants.

## Phase 5 MITRE Mapping Safety

Phase 5 MITRE mapping is local, static, deterministic, and auditable. It loads
`config/mitre_mapping.yaml` from disk and rejects URL, network, or
path-traversal config paths.

Generated MITRE URLs are inert reference strings built from configured technique
IDs. The mapper does not call the MITRE website, external MITRE APIs, external
threat intelligence services, or external AI APIs. CLI mapping output does not
include full `raw_message` content or raw sensitive marker constants.

## Phase 6 Explanation and Triage Safety

Phase 6 explanations are deterministic, template-driven, reproducible, and
auditable. They are generated from local validation, classification, MITRE
mapping, and playbook data only.

The explanation engine does not use LLM calls, external AI APIs, API keys,
network calls, threat intelligence lookups, live scanning, or stochastic output.
It omits full `raw_message` content by default and sanitizes approved fake
sensitive marker constants before returning CLI output.

Phase 6 triage recommendations are defensive playbook suggestions loaded from
local YAML. They focus on verifying alert source, reviewing local logs, checking
affected synthetic accounts and hosts, preserving evidence, documenting
findings, and escalating high or critical synthetic alerts. They do not instruct
the user to run offensive tools, contact live systems, test credentials, or
perform destructive actions.

## Phase 7 Incident Grouping Safety

Phase 7 incident grouping is local, rule-based, deterministic, reproducible, and
auditable. It loads `config/grouping_rules.yaml` from disk and rejects URL,
network, or path-traversal config paths.

The grouping engine creates local correlation edges between already validated
synthetic alerts and merges connected groups into incidents. It does not make
network calls, perform live enrichment, query external MITRE services, use LLM
calls, use external AI APIs, run scans, or execute response automation.

Incident output omits full `raw_message` content. Source IPs and usernames are
represented as redacted placeholders, while safe `.test` hostnames may remain
visible. Correlation reasons include rule IDs, matched field names, time-window
settings, and contributing synthetic alert IDs only.

## Phase 8 Redaction Safety

Phase 8 added the deterministic redaction engine and safe serialization layer
for CLI output and report-ready payloads. It remains offline-only, local,
rule-based, reproducible, and auditable.

The redaction layer does not use LLM calls, external AI APIs, API keys,
stochastic generation, network calls, external MITRE APIs, threat intelligence
services, live scanning, exploit code, attack automation, or malware behavior.

By default, report-ready serialization removes `raw_message`, redacts source IP
values, destination IP values, and usernames, redacts approved fake marker
constants, and redacts credential-looking patterns such as `password=`,
`token=`, `secret=`, `api_key=`, and `private_key`.

The validator fails structured payloads when prohibited marker values,
credential-looking assignments, raw IP fields, email-looking usernames, or
`raw_message` fields remain. Safe `.test` hostnames, alert IDs, incident IDs,
MITRE IDs/names, tactics, template IDs, playbook IDs, correlation rule IDs, and
timestamps may remain visible.

## Phase 9 Reporting Safety

Phase 9 adds deterministic JSON and Markdown reports. Reports are generated from
synthetic local alert data only and pass through the Phase 8 safe serializer and
redaction layer before rendering.

Reports do not include `raw_message`, raw source IP values, raw destination IP
values, raw usernames, approved fake marker constants, or credential-looking
assignments such as `password=`, `token=`, `secret=`, `api_key=`, or
`private_key`.

Reports include a safety disclaimer, synthetic-data statement, deterministic
rule-based AI statement, incident summary, MITRE summary, triage recommendations,
redaction summary, and limitations. Reporting makes no network calls, no LLM
calls, no external AI API calls, no external MITRE API calls, and no external
threat intelligence calls.

CI, CodeQL, and Dependabot are configured locally. Hosted verification,
publishing, tags, branch protection, and releases remain pending.
