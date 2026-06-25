# Phase 0 Implementation Plan: AI-Assisted Security Alert Triage Lab

Project name: AI-Assisted Security Alert Triage Lab  
Repository name: offline-alert-triage-lab  
Package name: triage_lab

Phase 11 note: this document is the original implementation plan. Phases 1
through 10 have implemented the local pipeline, redaction, reporting, local CI
configuration, CodeQL configuration, Dependabot configuration, and documentation
safety checks. Hosted GitHub CI, hosted CodeQL, publishing, tags, releases, and
branch protection remain pending until explicit approval.

## 1. Final Project Scope

Build a defensive, offline-only security alert triage lab that processes synthetic alerts from local files and produces deterministic analyst-style triage outputs.

The project will support:

- JSON alert ingestion.
- Pydantic validation and structured parse-error reporting.
- Deterministic severity classification.
- YAML-configured base severity rules, thresholds, modifiers, MITRE mappings, and triage steps.
- Transparent rule-based inference with traceable decision output.
- Local MITRE ATT&CK mapping from static YAML tables.
- Template-driven explanations.
- Local triage step recommendations.
- Incident grouping and correlation for related alerts.
- Redaction of sensitive fields before report output.
- Markdown and JSON reports.
- CLI operation for local files.
- Tests with a coverage target of at least 90%.
- Ruff formatting and linting.
- GitHub Actions CI, CodeQL, Dependabot, and release workflow in later phases only.

Out of scope:

- External AI, LLM, or API integrations.
- External threat intelligence.
- Network calls of any kind.
- Live scanning.
- Offensive tooling.
- Real customer, production, credential, or private data.
- Real-world alert collection.
- SIEM integrations.
- Web UI.
- Long-running daemon behavior.
- Database storage.

The "AI-assisted" behavior will be implemented as deterministic expert-system style logic: rule matching, scoring, local mappings, modifier application, correlation rules, and explanation templates.

## 2. Final Safety Boundaries

The project must remain defensive, local, deterministic, and synthetic.

Hard safety constraints:

- Defensive only.
- Offline/local files only.
- Synthetic alert data only.
- No real customer data.
- No real credentials.
- No real tokens.
- No real private information.
- No live scanning.
- No exploit code.
- No attack automation.
- No malware behavior.
- No network calls.
- No external threat intelligence API calls.
- No LLM/API key integration.
- No Metasploit, Nmap execution, Nessus integration, or offensive tooling.
- No code that targets real systems.
- No real IPs except reserved documentation ranges and private lab ranges.
- Use only `example.com`, `example.org`, `example.net`, and `.test` domains in examples.

Allowed synthetic IP ranges:

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`
- `192.0.2.0/24`
- `198.51.100.0/24`
- `203.0.113.0/24`

Safety enforcement should be implemented in two layers:

- Validation-time safety checks for input alerts and config content.
- Test fixtures that intentionally reject unsafe examples.

The code should never attempt to contact, scan, enrich, or verify any host, domain, or external service.

## 3. Phase-by-Phase Development Roadmap

### Phase 0: Planning

Deliverables:

- `docs/phase-0-plan.md`

No source code, workflows, git initialization, tags, releases, or publishing.

### Phase 1: Project Scaffold and Safety Foundation

Goal: Create the package structure, baseline metadata, static config placeholders, synthetic fixture data, and basic safety model.

Deliverables:

- Python package skeleton under `src/triage_lab`.
- `pyproject.toml` with package metadata and development tools.
- Static config files with initial rule, MITRE, and triage-step schemas.
- Synthetic sample alerts using only allowed IP and domain values.
- Initial Pydantic models.
- Safety helper module for local/synthetic constraints.
- Initial CLI entrypoint stub.
- README and project governance docs.
- Focused tests for schema validation and safety boundaries.

No GitHub workflows yet.

### Phase 2: Ingestion and Validation

Goal: Load JSON alerts from local files and report structured validation errors.

Deliverables:

- JSON ingestion module.
- Validation pipeline.
- Parse error model.
- CLI command for validating alert files.
- Tests for valid alerts, malformed JSON, missing fields, bad types, unsupported event types, unsafe IPs/domains, and redaction-sensitive fields.

CSV ingestion remains deferred unless it is safe and simple.

### Phase 3: Severity Classification Engine

Goal: Implement deterministic severity scoring and rule trace output.

Deliverables:

- Rule loader for local YAML.
- Base severity rules by event type.
- Threshold-based severity conversion.
- Modifier rules.
- Trace model that records matched rules, scores, modifiers, and final severity.
- CLI command for classification.
- Tests for each event type, thresholds, modifiers, rule ordering, and edge cases.

### Phase 4: MITRE Mapping and Explanations

Goal: Add local MITRE mapping and deterministic analyst explanations.

Deliverables:

- MITRE mapping loader from `config/mitre_mapping.yaml`.
- Mapping model for tactic, technique ID, technique name, confidence, and rationale.
- Template-driven explanation engine.
- Explanation trace showing which templates and facts were used.
- Tests for event-to-MITRE mappings and stable explanation output.

### Phase 5: Triage Playbooks

Goal: Suggest analyst triage steps from local YAML playbooks.

Deliverables:

- Playbook loader.
- Mapping from event type, severity, and MITRE technique to triage steps.
- Step ordering and deduplication.
- Tests for playbook selection and deterministic ordering.

### Phase 6: Incident Grouping and Correlation

Goal: Group related alerts into incidents using deterministic rules.

Deliverables:

- Correlation keys such as source IP, destination IP, user, host, event type, time window, and MITRE technique.
- Incident model.
- Grouping trace explaining why alerts were grouped.
- Tests for grouping by shared entity, time-window boundaries, unrelated alerts, and mixed severity rollups.

### Phase 7: Redaction and Reporting

Goal: Redact sensitive fields and produce Markdown/JSON reports.

Deliverables:

- Redaction engine.
- JSON report writer.
- Markdown report writer.
- Report model for alerts, classifications, MITRE mappings, explanations, triage steps, incidents, redaction metadata, and tool version.
- Tests for redaction coverage, report schema, deterministic output, and Markdown content.

### Phase 8: CLI Completion and Documentation

Goal: Provide a complete local CLI workflow and user documentation.

Deliverables:

- CLI commands for `validate`, `classify`, `triage`, and `report`.
- CLI help text.
- Example reports under `reports/examples`.
- README usage walkthrough.
- Testing report.
- Completion checklist.

### Phase 9: CI, CodeQL, Dependabot, and Release Workflow

Goal: Add repository automation after the local project is stable.

Deliverables:

- GitHub Actions test workflow.
- Ruff workflow.
- CodeQL workflow.
- Dependabot configuration.
- Release workflow.
- Release checklist.

No release should be created until the project is complete, tested, and explicitly approved.

## 4. Data Model Design

Core models:

- `Alert`: validated input alert.
- `AlertMetadata`: optional contextual fields such as environment, sensor, product, and tags.
- `ValidationErrorDetail`: structured validation or parse error.
- `ClassificationResult`: base score, modifiers, final score, severity, and trace.
- `RuleMatch`: rule ID, description, matched fields, score impact, and rationale.
- `MitreMapping`: tactic, technique ID, technique name, confidence, and rationale.
- `Explanation`: analyst-style explanation plus supporting facts.
- `TriageStep`: ordered action suggestion from local playbook.
- `Incident`: grouped alert IDs, correlation keys, severity rollup, timeframe, and summary.
- `RedactionResult`: redacted object plus list of redacted field paths.
- `Report`: final normalized output for JSON and Markdown writers.

Design principles:

- Use Pydantic models for validation and serialization.
- Keep raw input separated from normalized alert objects.
- Preserve rule traces for every classification decision.
- Keep deterministic ordering for output lists.
- Use enums for event type and severity.
- Avoid hidden global state.

## 5. Alert Schema

Required fields:

- `alert_id`: stable synthetic identifier.
- `timestamp`: ISO 8601 timestamp.
- `event_type`: one of the supported event types.
- `source_ip`: allowed private or documentation-range IP.
- `destination_ip`: allowed private or documentation-range IP.
- `host`: synthetic hostname using `.test` or an obvious lab naming pattern.
- `user`: synthetic user identifier.
- `message`: short synthetic alert message.

Optional fields:

- `source_port`
- `destination_port`
- `protocol`
- `domain`
- `process_name`
- `file_path`
- `command_line`
- `authentication_result`
- `country`
- `asset_criticality`
- `confidence`
- `count`
- `tags`
- `metadata`

Supported event types:

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

Schema safety checks:

- IP addresses must be within allowed ranges.
- Domains must be `example.com`, `example.org`, `example.net`, or `.test`.
- Fields that look like real credentials or tokens must fail validation or be redacted, depending on context.
- Alert IDs must be synthetic and stable.
- Timestamps must parse as timezone-aware or be normalized consistently.

## 6. Severity Classification Design

Severity levels:

- `informational`
- `low`
- `medium`
- `high`
- `critical`

Classification should use a transparent numeric score:

- Base score from event type.
- Adjustments from alert attributes.
- Adjustments from modifier rules.
- Final severity from thresholds.

Example base scoring concept:

- `unknown`: low base score.
- `policy_violation`: low to medium.
- `failed_login`: low unless repeated or privileged.
- `brute_force`: medium to high.
- `port_scan`: medium.
- `anomalous_login_time`: medium.
- `malware_detected`: high.
- `privilege_escalation`: high.
- `lateral_movement`: high.
- `data_exfiltration`: high to critical.
- `c2_beacon`: high to critical.

Every result must include:

- Base rule ID.
- Base score.
- Matched modifiers.
- Final score.
- Final severity.
- Human-readable rationale.

## 7. Modifier Rule Design

Modifier rules should be configured in `config/rules.yaml`.

Modifier examples:

- Increase severity when `asset_criticality` is `high`.
- Increase severity when `user` appears privileged, using synthetic patterns such as `admin.test` or `svc-admin`.
- Increase severity when `count` crosses configured thresholds.
- Increase severity for repeated failures over a time window.
- Increase severity when destination port is associated with sensitive administrative services in a lab context.
- Decrease severity when confidence is low.
- Decrease severity for known benign policy test events.

Modifier rule fields:

- `id`
- `description`
- `conditions`
- `score_delta`
- `rationale`
- `applies_to_event_types`

Condition handling must be deterministic and limited to simple comparisons:

- Equals.
- In list.
- Greater than or equal.
- Less than or equal.
- Field exists.
- Contains safe literal substring.

No arbitrary code execution should be possible from YAML.

## 8. MITRE Mapping Design

MITRE mapping should come only from `config/mitre_mapping.yaml`.

Mapping fields:

- `event_type`
- `tactic`
- `technique_id`
- `technique_name`
- `confidence`
- `rationale`

Example mapping categories:

- `brute_force`: Credential Access, Brute Force.
- `privilege_escalation`: Privilege Escalation.
- `lateral_movement`: Lateral Movement.
- `data_exfiltration`: Exfiltration.
- `c2_beacon`: Command and Control.
- `malware_detected`: Execution or Defense Evasion depending on local mapping.
- `anomalous_login_time`: Initial Access or Valid Accounts depending on event context.

The project should not fetch MITRE data from the internet. Technique names and IDs should be static local educational examples and reviewed manually.

## 9. Explanation Engine Design

The explanation engine should generate analyst-style prose using local templates.

Inputs:

- Alert fields.
- Classification result.
- Matched rules.
- MITRE mappings.
- Triage playbook selections.
- Incident grouping context, if available.

Outputs:

- Short summary.
- Severity rationale.
- MITRE rationale.
- Recommended next-step summary.
- Trace details.

Template principles:

- Deterministic text.
- No stochastic generation.
- No external AI.
- No hidden inference.
- Stable output for stable input.
- Explicit references to matched rule IDs and key alert facts.

Template format can be Python string templates or YAML templates, as long as missing variables are handled safely and tested.

## 10. Triage Playbook Design

Triage steps should be stored in `config/triage_steps.yaml`.

Step fields:

- `id`
- `title`
- `description`
- `applies_to_event_types`
- `applies_to_severities`
- `applies_to_mitre_techniques`
- `order`
- `safety_note`

Steps must remain defensive and offline. They may suggest:

- Review local synthetic alert context.
- Compare related synthetic alerts.
- Check local lab logs or provided fixtures.
- Verify whether the synthetic user or host appears in related alerts.
- Preserve report output.
- Escalate within the fictional lab scenario.

Steps must not suggest:

- Scanning real systems.
- Running offensive tools.
- Contacting external services.
- Looking up live threat intelligence.
- Executing malware samples.
- Testing credentials.

## 11. Incident Grouping Design

Incident grouping should correlate alerts using local deterministic rules.

Possible grouping keys:

- Same `source_ip` within a time window.
- Same `destination_ip` within a time window.
- Same `host` within a time window.
- Same `user` within a time window.
- Same `event_type` sequence pattern.
- Same MITRE tactic or technique.

Incident fields:

- `incident_id`
- `alert_ids`
- `start_time`
- `end_time`
- `severity`
- `entities`
- `correlation_reasons`
- `summary`

Severity rollup:

- Use highest alert severity as the baseline.
- Optionally increase one level when multiple high-confidence related alerts occur in the same incident.
- Never exceed `critical`.
- Record the rollup rule in the trace.

The grouping engine should avoid complex graph or ML behavior until there is a clear need. Simple deterministic correlation is enough for this lab.

## 12. Redaction Design

The redaction engine should remove or mask sensitive values before report output.

Fields to redact or inspect:

- Credentials.
- Tokens.
- API keys.
- Email-like values if they are not clearly synthetic.
- Long secret-like strings.
- Command-line arguments that look like secrets.
- Unapproved public IPs.
- Unapproved domains.

Redaction behavior:

- Replace sensitive values with stable placeholders such as `[REDACTED:token]`.
- Record redacted field paths.
- Preserve enough context for the report to remain useful.
- Do not mutate the original alert model in place unless explicitly intended.

The redaction engine should be tested with intentionally unsafe fixture values.

## 13. Reporting Design

Report formats:

- JSON for machine-readable output.
- Markdown for analyst-readable output.

JSON report should include:

- Report metadata.
- Input file path or display name.
- Alert count.
- Validation summary.
- Classified alerts.
- MITRE mappings.
- Explanations.
- Triage steps.
- Incidents.
- Redaction metadata.
- Tool version.

Markdown report should include:

- Executive summary.
- Severity distribution.
- Incident summary.
- Alert details.
- MITRE mapping table.
- Triage recommendations.
- Redaction summary.
- Deterministic trace notes.

Report output must be deterministic:

- Stable ordering.
- Stable timestamps where generated metadata is either supplied or clearly marked.
- Stable formatting.

## 14. CLI Command Design

Proposed CLI entrypoint:

```text
triage-lab
```

Commands:

```text
triage-lab validate --input alerts/sample_alerts.json
triage-lab classify --input alerts/sample_alerts.json --config config/rules.yaml
triage-lab triage --input alerts/sample_alerts.json --config-dir config
triage-lab report --input alerts/sample_alerts.json --config-dir config --format markdown --output reports/examples/sample_report.md
triage-lab report --input alerts/sample_alerts.json --config-dir config --format json --output reports/examples/sample_report.json
```

CLI principles:

- Only local file paths.
- No network options.
- No API-key options.
- Clear validation failures.
- Nonzero exit codes for malformed input, validation failure, and unsafe content.
- Deterministic output.
- Helpful `--help` text.

Potential implementation library:

- `typer` for CLI ergonomics, if dependency footprint is acceptable.
- `argparse` if minimal dependencies are preferred.

Recommended initial choice: `typer`, unless Phase 1 decides to keep dependencies minimal.

## 15. Test Strategy

Coverage target:

- At least 90%.

Test categories:

- Unit tests for models.
- Unit tests for safety validation.
- Unit tests for rule loading.
- Unit tests for severity classification.
- Unit tests for modifiers.
- Unit tests for MITRE mapping.
- Unit tests for explanation templates.
- Unit tests for triage step selection.
- Unit tests for incident grouping.
- Unit tests for redaction.
- Unit tests for JSON and Markdown report generation.
- CLI tests for validate/classify/triage/report commands.
- Snapshot-style tests for deterministic outputs where useful.

Fixture strategy:

- Keep all fixtures synthetic.
- Use only allowed IP ranges.
- Use only allowed domains.
- Include unsafe negative fixtures for validation and redaction tests.
- Keep fixtures small and easy to inspect.

Quality gates:

- `pytest`
- `pytest --cov=triage_lab --cov-report=term-missing`
- `ruff check`
- `ruff format --check`

## 16. Documentation Strategy

Required documentation:

- `README.md`: project overview, safety boundaries, installation, CLI usage, examples.
- `SECURITY.md`: safety model, supported data boundaries, vulnerability reporting guidance.
- `TESTING_REPORT.md`: test commands, coverage summary, known gaps.
- `PROJECT_COMPLETION_CHECKLIST.md`: phase completion checklist.
- `CHANGELOG.md`: release notes once releases begin.
- `docs/phase-0-plan.md`: this plan.

Documentation must consistently state:

- The project is offline-only.
- The project uses synthetic data only.
- The AI-assisted component is deterministic and rule-based.
- No external APIs, LLMs, scanning, or offensive tooling are used.

## 17. CI, CodeQL, and Release Strategy for Later Phases

CI should be added only after core local functionality exists.

Later GitHub Actions workflows:

- Test workflow for Python versions supported by the project.
- Ruff lint/format workflow.
- Coverage reporting in workflow logs.
- CodeQL workflow for Python.

Dependabot later:

- Python package ecosystem.
- GitHub Actions ecosystem.
- Conservative schedule, such as weekly.

Release workflow later:

- Manual workflow dispatch or tag-triggered release.
- Build source distribution and wheel.
- Run full tests before release artifact creation.
- Generate release notes from changelog.
- Do not publish automatically unless explicitly approved.

Release readiness requirements:

- Tests passing.
- Coverage target met.
- Safety fixtures passing.
- Example reports regenerated.
- Documentation updated.
- Completion checklist finished.

## 18. Risks and Scope-Creep Controls

Risk: The phrase "AI-assisted" could imply LLM behavior.  
Control: Explicitly document that the system is deterministic, rule-based, and traceable.

Risk: Alert triage could drift into live detection or scanning.  
Control: Only accept local files and never add network-capable commands.

Risk: MITRE mapping could require external data refreshes.  
Control: Use local educational mapping YAML only.

Risk: Incident grouping could become overly complex.  
Control: Start with simple deterministic keys and time windows.

Risk: Redaction could become a full DLP engine.  
Control: Implement targeted safety checks for lab data and report output.

Risk: CSV ingestion could introduce messy parsing and injection concerns.  
Control: Defer CSV until JSON pipeline is stable; only add it if simple and safe.

Risk: Reports could become a large analytics system.  
Control: Limit reports to concise Markdown and JSON outputs.

Risk: CI/release work could distract from core behavior.  
Control: Defer workflows and release automation until later phases.

## 19. Exact Recommended Phase 1 Scaffold

Phase 1 should create these directories:

```text
.github/
src/
src/triage_lab/
src/triage_lab/ingestion/
src/triage_lab/classification/
src/triage_lab/mitre/
src/triage_lab/explanations/
src/triage_lab/triage/
src/triage_lab/grouping/
src/triage_lab/redaction/
src/triage_lab/reporting/
src/triage_lab/models/
config/
alerts/
reports/
reports/examples/
tests/
tests/fixtures/
docs/
```

Phase 1 should create these files:

```text
src/triage_lab/__init__.py
src/triage_lab/__main__.py
src/triage_lab/cli.py
src/triage_lab/safety.py
src/triage_lab/models/__init__.py
src/triage_lab/models/alerts.py
src/triage_lab/models/results.py
src/triage_lab/ingestion/__init__.py
src/triage_lab/classification/__init__.py
src/triage_lab/mitre/__init__.py
src/triage_lab/explanations/__init__.py
src/triage_lab/triage/__init__.py
src/triage_lab/grouping/__init__.py
src/triage_lab/redaction/__init__.py
src/triage_lab/reporting/__init__.py
config/rules.yaml
config/mitre_mapping.yaml
config/triage_steps.yaml
alerts/sample_alerts.json
tests/test_alert_models.py
tests/test_safety.py
tests/fixtures/valid_alerts.json
tests/fixtures/unsafe_alerts.json
pyproject.toml
README.md
LICENSE
CHANGELOG.md
SECURITY.md
TESTING_REPORT.md
PROJECT_COMPLETION_CHECKLIST.md
```

Phase 1 should not create:

```text
.github/workflows/*
.github/dependabot.yml
git tags
release artifacts
published packages
```

The `.github/` directory may be created as an empty placeholder only if needed for the intended final structure, but workflows and automation should wait until later.

## Proposed Architecture

The architecture should use a clean local pipeline:

```text
Local JSON alerts
  -> ingestion
  -> Pydantic validation and safety checks
  -> deterministic severity classification
  -> MITRE mapping from local YAML
  -> template-driven explanations
  -> local triage playbook selection
  -> incident grouping
  -> redaction
  -> JSON and Markdown reports
```

Each stage should expose structured result objects and trace metadata. This keeps behavior inspectable, testable, and suitable for an educational security lab.

## Proposed Phases

Recommended phase order:

1. Phase 1: Scaffold and safety foundation.
2. Phase 2: Ingestion and validation.
3. Phase 3: Severity classification.
4. Phase 4: MITRE mapping and explanations.
5. Phase 5: Triage playbooks.
6. Phase 6: Incident grouping.
7. Phase 7: Redaction and reporting.
8. Phase 8: CLI completion and documentation.
9. Phase 9: CI, CodeQL, Dependabot, and release workflow.

## Files and Directories Phase 1 Should Create

Phase 1 should create the scaffold listed in section 19, with emphasis on:

- `pyproject.toml`
- `src/triage_lab/`
- `config/*.yaml`
- `alerts/sample_alerts.json`
- `tests/`
- top-level documentation files

Phase 1 should keep implementations minimal and focused on package importability, basic validation, safety constants, and initial testability.

## Risks and Design Decisions

Key design decisions:

- Use deterministic rules instead of external AI.
- Use YAML only as data, never as executable logic.
- Keep CLI local-file only.
- Use Pydantic for strict validation.
- Keep report generation deterministic.
- Defer workflows and release automation.

Key risks:

- Scope creep into live security tooling.
- Overcomplicated correlation.
- Unsafe example data.
- Ambiguous "AI-assisted" positioning.
- Adding external integrations too early.

The controls in this plan are sufficient to keep Phase 1 bounded.

## Phase 1 Readiness

Phase 1 is ready to start.

The recommended next action is to create the scaffold and minimal safety/model foundation only, without implementing the full triage pipeline and without adding GitHub workflows, tags, releases, or publishing steps.
