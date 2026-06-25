from __future__ import annotations

from pathlib import Path

import pytest

from triage_lab.triage.playbooks import PlaybookConfigError, load_playbooks


def test_default_playbook_config_loading() -> None:
    config = load_playbooks()

    assert config.name == "offline-alert-triage-local-playbooks"
    assert config.version == 1
    assert any(step["id"] == "TRIAGE-GLOBAL-FALLBACK" for step in config.steps)


def test_custom_local_playbook_config_loading(tmp_path: Path) -> None:
    source = Path("config/triage_steps.yaml").read_text(encoding="utf-8")
    custom = tmp_path / "triage_steps.yaml"
    custom.write_text(source.replace("version: 1", "version: 2"), encoding="utf-8")

    config = load_playbooks(custom)

    assert config.version == 2


def test_invalid_playbook_config_fails_clearly(tmp_path: Path) -> None:
    bad_config = tmp_path / "triage_steps.yaml"
    bad_config.write_text("[]", encoding="utf-8")

    with pytest.raises(PlaybookConfigError, match="YAML mapping"):
        load_playbooks(bad_config)


def test_playbook_url_is_rejected() -> None:
    with pytest.raises(PlaybookConfigError, match="network paths"):
        load_playbooks("https://example.com/triage_steps.yaml")


def test_playbook_path_traversal_is_rejected() -> None:
    with pytest.raises(PlaybookConfigError, match="path traversal"):
        load_playbooks("../config/triage_steps.yaml")
