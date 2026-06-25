# Reports

This directory contains generated example reports from the local synthetic alert
dataset.

Current examples:

- `reports/examples/security_alert_triage_report.json`
- `reports/examples/security_alert_triage_report.md`

Reports must be generated only from synthetic/local alert data and must preserve
the offline-only safety model. Report output must not contain raw messages, raw
entity values, credential-looking assignments, real customer data, real
credentials, real tokens, or private information.
