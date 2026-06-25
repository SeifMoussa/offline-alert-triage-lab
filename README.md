# AI-Assisted Security Alert Triage Lab

Defensive offline alert triage lab for synthetic security alerts, deterministic
classification, MITRE ATT&CK mapping, incident grouping, redaction, and
Markdown/JSON reporting.

## Safety Disclaimer

This project is defensive only. It processes local files containing synthetic
alert data and performs no network calls, no live scanning, no exploit code, no
attack automation, no malware behavior, and no external threat-intelligence
lookups.

The "AI-assisted" label is intentionally narrow and honest:

- Deterministic rule-based engine.
- No LLMs.
- No external AI APIs.
- No API keys.
- No stochastic output.
- Every decision is traceable through local rules, mappings, and templates.

## Project Goal

The lab demonstrates how a junior security automation or blue-team workflow can
turn raw synthetic alerts into analyst-ready triage output while preserving
strict safety boundaries. It is designed for portfolio review, local learning,
and repeatable quality checks.

Target roles:

- SOC Analyst.
- Cybersecurity Analyst.
- Blue Team Analyst.
- Detection Engineering trainee.
- Incident Response trainee.
- Security Automation junior role.

## What This Demonstrates

- Safe local security tooling design.
- Schema validation and structured error handling.
- Deterministic severity classification with transparent rule traces.
- Local MITRE ATT&CK mapping without external lookups.
- Analyst-style explanation generation without LLMs.
- Defensive triage playbook selection.
- Incident grouping and severity rollups.
- Report-safe redaction and output validation.
- JSON and Markdown report generation.
- Python packaging, pytest, coverage gates, Ruff, GitHub Actions, CodeQL, and
  Dependabot configuration.

## Pipeline Overview

```text
local synthetic alerts
  -> alert ingestion
  -> validation
  -> severity classification
  -> MITRE ATT&CK mapping
  -> analyst-style explanations
  -> triage playbooks
  -> incident grouping
  -> redaction
  -> Markdown/JSON reports
```

Implemented stages:

- Alert ingestion from local JSON arrays, single JSON objects, and simple NDJSON.
- Pydantic validation and structured parse-error output.
- Deterministic severity classification from local YAML rules.
- MITRE ATT&CK mapping from local static YAML tables.
- Analyst-style explanations from deterministic templates.
- Defensive triage recommendations from local playbooks.
- Incident grouping from local deterministic correlation rules.
- Redaction of raw messages, IPs, usernames, sensitive markers, and
  credential-looking patterns before report output.
- Markdown and JSON reports under `reports/examples`.

## Safety Model

Allowed data is limited to synthetic local alerts. Examples use private lab
ranges, reserved documentation IP ranges, `example.com`, `example.org`,
`example.net`, and `.test` domains.

The application rejects URL inputs, network paths, and parent-directory
traversal for CLI file paths. It does not provide options for API keys, external
enrichment, live scanning, or SIEM integration.

Reports do not include `raw_message`, raw source IP values, raw destination IP
values, raw usernames, approved fake marker constants, or credential-looking
assignments.

## Tech Stack

- Python 3.11+.
- Pydantic.
- PyYAML.
- argparse CLI.
- pytest and pytest-cov.
- Ruff linting and formatting.
- GitHub Actions workflow files configured locally.
- CodeQL workflow configured locally.
- Dependabot configured locally.

## CLI Examples

Run from the repository root. With an editable install, `triage-lab` is also
available as the console script; the examples below use `python -m triage_lab`
for direct local execution.

```bash
python -m triage_lab --help
python -m triage_lab --version
python -m triage_lab inventory --input alerts --format json
python -m triage_lab validate-alerts --input alerts/sample_alerts.json --format json
python -m triage_lab validate-alerts --input alerts/sample_alerts.json --format text
python -m triage_lab classify-alerts --input alerts/sample_alerts.json --format json
python -m triage_lab classify-alerts --input alerts/sample_alerts.json --format text
python -m triage_lab map-mitre --input alerts/sample_alerts.json --format json
python -m triage_lab map-mitre --input alerts/sample_alerts.json --format text
python -m triage_lab explain-alerts --input alerts/sample_alerts.json --format json
python -m triage_lab explain-alerts --input alerts/sample_alerts.json --format text
python -m triage_lab group-incidents --input alerts/sample_alerts.json --format json
python -m triage_lab group-incidents --input alerts/sample_alerts.json --format text
python -m triage_lab redact-check --input alerts/sample_alerts.json --format json
python -m triage_lab report --input alerts/sample_alerts.json --output reports/examples --format both
python -m triage_lab report --input alerts/sample_alerts.json --output reports/examples --format json
python -m triage_lab report --input alerts/sample_alerts.json --output reports/examples --format markdown
```

## Example Reports

- [JSON example report](reports/examples/security_alert_triage_report.json)
- [Markdown example report](reports/examples/security_alert_triage_report.md)

Both reports are generated from `alerts/sample_alerts.json`, use synthetic local
data only, include the offline-only safety disclaimer, and pass the report safety
scan.

## Testing And Quality Status

Current verified local status:

- 256 tests passed.
- 97.29% coverage.
- 97% coverage gate passed.
- Ruff check passed.
- Ruff format check passed.
- Docs safety check passed.
- CLI smoke passed.
- Generated report and relevant CLI output scan passed.

Quality commands:

```bash
python -m pytest
python -m pytest --cov=triage_lab --cov-report=term-missing --cov-fail-under=97
python -m ruff check .
python -m ruff format --check .
python scripts/check-docs.py
python -m py_compile scripts/check-docs.py
```

CI, CodeQL, and Dependabot are configured locally. Hosted GitHub CI and CodeQL have not been verified yet because the repository has not been published.

## Project Structure

```text
alerts/                  synthetic alert fixtures
config/                  local YAML rules, MITRE mappings, playbooks, grouping rules
docs/                    schema, safety, reporting, testing, and release docs
reports/examples/        generated redacted JSON and Markdown reports
scripts/check-docs.py    documentation and report safety checks
src/triage_lab/          application package
tests/                   pytest suite
```

Key package areas:

- `ingestion`: local JSON loading, inventory, and path safety.
- `classification`: severity rules, modifiers, overrides, and traces.
- `mitre`: local static ATT&CK mappings.
- `explanations`: deterministic analyst-style text.
- `triage`: defensive playbook selection.
- `grouping`: deterministic incident correlation.
- `redaction`: report-safe serialization and validation.
- `reporting`: report models, pipeline, renderers, and writer.

## Limitations

- Educational lab only; not a production SOC platform.
- Synthetic alert data only.
- JSON-focused ingestion; CSV ingestion is intentionally out of scope for
  v0.1.0.
- Local static MITRE examples are not a live ATT&CK data sync.
- No SIEM, EDR, cloud, ticketing, LLM, or external threat-intelligence
  integrations.
- Hosted CI, hosted CodeQL, branch protection, tags, and release verification
  remain pending until publishing.

## Roadmap

- Publish repository after explicit approval.
- Verify hosted GitHub Actions and hosted CodeQL after publishing.
- Review code scanning, secret scanning, and Dependabot results.
- Configure branch protection after hosted checks exist.
- Create the v0.1.0 tag and GitHub Release after final approval.
- Consider additional synthetic fixtures and report screenshots for portfolio
  presentation.

## License

MIT License. See [LICENSE](LICENSE).
