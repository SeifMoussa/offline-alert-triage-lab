# Contributing

Contributions must preserve the project's defensive, offline-only,
synthetic-data safety model.

## Ground Rules

- Do not add network calls.
- Do not add live scanning.
- Do not add exploit code.
- Do not add external AI API, LLM, API-key, or threat-intelligence integration.
- Do not add real customer data, real credentials, real tokens, or private
  information.
- Use only approved synthetic IP ranges and safe example domains in fixtures and
  documentation.

## Local Quality Checks

```bash
python -m pytest
python -m pytest --cov=triage_lab --cov-report=term-missing --cov-fail-under=97
python -m ruff check .
python -m ruff format --check .
python scripts/check-docs.py
```

GitHub Actions, CodeQL, and Dependabot are configured locally. Hosted checks,
publishing, tags, releases, and branch protection require explicit approval and
must not be claimed complete until they are actually verified.
