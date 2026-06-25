from __future__ import annotations

from pathlib import Path

import triage_lab

ROOT = Path(__file__).resolve().parents[1]


def test_package_imports_and_exposes_version() -> None:
    assert triage_lab.__version__
    assert isinstance(triage_lab.__version__, str)


def test_config_placeholder_files_exist() -> None:
    expected = [
        ROOT / "config" / "README.md",
        ROOT / "config" / "rules.yaml",
        ROOT / "config" / "mitre_mapping.yaml",
        ROOT / "config" / "triage_steps.yaml",
    ]
    missing = [path for path in expected if not path.exists()]
    assert missing == []


def test_important_docs_exist() -> None:
    expected = [
        ROOT / "README.md",
        ROOT / "SECURITY.md",
        ROOT / "TESTING_REPORT.md",
        ROOT / "PROJECT_COMPLETION_CHECKLIST.md",
        ROOT / "docs" / "phase-0-plan.md",
        ROOT / "docs" / "safety-model.md",
        ROOT / "docs" / "design-decisions.md",
        ROOT / "docs" / "report-schema.md",
        ROOT / "docs" / "testing-guide.md",
        ROOT / "docs" / "release-checklist.md",
        ROOT / "docs" / "portfolio-notes.md",
    ]
    missing = [path for path in expected if not path.exists()]
    assert missing == []
