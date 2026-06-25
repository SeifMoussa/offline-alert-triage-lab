# Release Preparation

## Project Summary

AI-Assisted Security Alert Triage Lab is a defensive offline lab for synthetic
security alert triage. It uses deterministic rule-based classification, local
MITRE ATT&CK mappings, analyst-style explanations, incident grouping,
redaction, and Markdown/JSON reports.

Target repository:
`https://github.com/SeifMoussa/offline-alert-triage-lab`

## Safety Scope

- Defensive only.
- Offline/local files only.
- Synthetic alert data only.
- No real customer data, credentials, tokens, or private information.
- No network calls from the application.
- No live scanning, exploit code, attack automation, or malware behavior.
- No external MITRE API, external threat-intelligence API, LLM, external AI API,
  or API-key integration.

## What v0.1.0 Includes

- Local alert ingestion and validation.
- Deterministic severity classification.
- Static local MITRE ATT&CK mapping.
- Deterministic analyst-style explanations.
- Defensive triage playbook recommendations.
- Deterministic incident grouping.
- Redaction and report-safe serialization.
- JSON and Markdown reports.
- CLI commands for inventory, validation, classification, MITRE mapping,
  explanations, incident grouping, redaction checks, and reporting.
- pytest suite, 97% coverage gate, Ruff, docs safety check, CLI smoke workflow,
  CodeQL workflow, and Dependabot configuration files.

## Verified Local Quality Results

- `python -m pytest`: 256 passed.
- `python -m pytest --cov=triage_lab --cov-report=term-missing --cov-fail-under=97`:
  256 passed, 97.29% coverage, 97% gate passed.
- `python -m ruff check .`: passed.
- `python -m ruff format --check .`: passed.
- `python scripts/check-docs.py`: passed.
- `python -m py_compile scripts/check-docs.py`: passed.
- CLI smoke through report generation: passed locally.
- Generated report and CLI output safety scan: passed locally.

## Pending Post-Push Checks

- Hosted GitHub Actions verification.
- Hosted CodeQL verification.
- Code scanning alert review.
- Secret scanning alert review.
- Dependabot PR review and merge decisions.
- Branch protection configuration.
- v0.1.0 tag creation.
- GitHub Release creation.

## Manual Git Publishing Commands

Run only after explicit approval to start publishing:

```bash
git init
git add .
git commit -m "Prepare offline alert triage lab v0.1.0"
git branch -M main
git remote add origin https://github.com/SeifMoussa/offline-alert-triage-lab.git
git push -u origin main
```

Tagging after hosted verification and final approval:

```bash
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

## GitHub CLI Publishing Commands

Run only after explicit approval:

```bash
gh repo create SeifMoussa/offline-alert-triage-lab --public --source . --remote origin --push
gh repo edit SeifMoussa/offline-alert-triage-lab --description "Defensive offline AI-assisted security alert triage lab using deterministic rule-based classification, MITRE ATT&CK mapping, analyst-style explanations, incident grouping, redaction, and Markdown/JSON reports with Python, pytest, Ruff, GitHub Actions, and CodeQL."
```

Suggested topics:

```bash
gh repo edit SeifMoussa/offline-alert-triage-lab --add-topic cybersecurity --add-topic soc --add-topic blue-team --add-topic alert-triage --add-topic incident-response --add-topic detection-engineering --add-topic security-automation --add-topic mitre-attack --add-topic python --add-topic pytest --add-topic ruff --add-topic codeql --add-topic github-actions --add-topic dependabot --add-topic portfolio
```

## Repository Description

Defensive offline AI-assisted security alert triage lab using deterministic
rule-based classification, MITRE ATT&CK mapping, analyst-style explanations,
incident grouping, redaction, and Markdown/JSON reports with Python, pytest,
Ruff, GitHub Actions, and CodeQL.

## Suggested GitHub Topics

cybersecurity, soc, blue-team, alert-triage, incident-response,
detection-engineering, security-automation, mitre-attack, python, pytest, ruff,
codeql, github-actions, dependabot, portfolio

## v0.1.0 Release Title

v0.1.0 - Offline Security Alert Triage Lab

## v0.1.0 Release Notes Draft

Initial portfolio release of the AI-Assisted Security Alert Triage Lab.

Includes a complete defensive offline pipeline for synthetic alerts:
ingestion, validation, severity classification, local MITRE ATT&CK mapping,
deterministic analyst-style explanations, defensive triage recommendations,
incident grouping, redaction, and JSON/Markdown reports.

Safety scope:

- Synthetic local data only.
- Deterministic rule-based logic only.
- No LLMs, external AI APIs, API keys, network calls, live scanning, exploit
  code, or external threat-intelligence lookups.

Local quality status before publishing:

- 256 tests passed.
- 97.29% coverage with a 97% gate.
- Ruff lint and format checks passed.
- Docs safety check passed.
- CLI smoke and generated report safety scan passed.

Hosted GitHub Actions and hosted CodeQL should be verified after pushing.

## Post-Push Verification Checklist

- [ ] Confirm repository visibility and README rendering.
- [ ] Confirm example report links render correctly.
- [ ] Confirm GitHub Actions workflow starts.
- [ ] Confirm hosted test workflow result.
- [ ] Confirm hosted docs safety and CLI smoke results.
- [ ] Confirm hosted CodeQL workflow result.
- [ ] Review repository settings.

## Code Scanning Checklist

- [ ] Confirm CodeQL workflow is enabled.
- [ ] Wait for first hosted CodeQL run.
- [ ] Review code scanning alerts.
- [ ] Fix or document any actionable finding.
- [ ] Confirm no unresolved critical/high findings before release.

## Secret Scanning Checklist

- [ ] Confirm secret scanning availability for the repository.
- [ ] Review secret scanning alerts after push.
- [ ] Confirm no real credentials, tokens, API keys, or private values are
  present.
- [ ] Keep `.env` files out of the repository.

## Dependabot Checklist

- [ ] Confirm Dependabot configuration is visible.
- [ ] Review pip ecosystem updates.
- [ ] Review GitHub Actions ecosystem updates.
- [ ] Merge only updates that pass hosted checks.

## Branch Protection Checklist

- [ ] Configure after hosted CI and CodeQL checks exist.
- [ ] Require pull request review before merge.
- [ ] Require status checks.
- [ ] Require the test workflow.
- [ ] Require CodeQL/code scanning where available.
- [ ] Disallow force pushes to `main`.

## Screenshot And Report-Excerpt Plan

- Capture the README first viewport.
- Capture the CLI `--help` output.
- Capture the Markdown report executive summary and severity summary.
- Capture the incident summary section.
- Capture the redaction summary section.
- Avoid screenshots containing raw synthetic marker constants or unsafe sample
  values.

## LinkedIn Post Draft

I built an offline AI-assisted Security Alert Triage Lab as a defensive
cybersecurity portfolio project.

The project processes synthetic local alerts through validation, deterministic
severity classification, local MITRE ATT&CK mapping, analyst-style
explanations, defensive triage recommendations, incident grouping, redaction,
and JSON/Markdown reporting.

Important scope note: "AI-assisted" here means deterministic rule-based logic.
There are no LLMs, external AI APIs, API keys, network calls, live scanning, or
real customer data.

Local quality status before publishing: 256 tests passed, 97.29% coverage with
a 97% gate, Ruff passed, docs safety checks passed, CLI smoke passed, and report
safety scans passed.

## LinkedIn Projects Section Draft

AI-Assisted Security Alert Triage Lab

Built a defensive offline Python lab that turns synthetic security alerts into
analyst-ready triage reports. Implemented local alert ingestion, validation,
deterministic severity classification, local MITRE ATT&CK mapping,
analyst-style explanations, defensive triage playbooks, incident grouping,
redaction, and JSON/Markdown reports. Added pytest coverage, Ruff checks,
GitHub Actions, CodeQL, and Dependabot configuration. The project uses no LLMs,
external AI APIs, network calls, live scanning, or real customer data.

## CV Bullets

- Built a defensive offline security alert triage lab in Python with synthetic
  alert ingestion, validation, deterministic severity classification, MITRE
  ATT&CK mapping, incident grouping, redaction, and JSON/Markdown reporting.
- Implemented analyst-style explanations and triage recommendations using
  deterministic local templates and playbooks, with no LLMs, external APIs, or
  network calls.
- Added 256 pytest tests with 97.29% coverage, a 97% coverage gate, Ruff
  lint/format checks, documentation safety checks, CLI smoke validation, and
  local GitHub Actions/CodeQL/Dependabot configuration.

## Recruiter-Facing Summary

This project shows practical blue-team automation skills: validating alert
data, applying transparent triage logic, mapping to MITRE ATT&CK, explaining
decisions for analysts, grouping related alerts, protecting sensitive output,
and proving quality with tests and CI-ready tooling. It is intentionally
offline, deterministic, and safe for public portfolio review.
