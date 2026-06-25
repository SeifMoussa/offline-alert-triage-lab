from __future__ import annotations

from pathlib import Path

import pytest

from triage_lab.mitre.loader import MitreConfigError, load_mitre_mapping


def test_default_mitre_config_loading() -> None:
    config = load_mitre_mapping()

    assert config.name == "offline-alert-triage-local-mitre-mapping"
    assert config.version == 1
    assert config.mappings["brute_force"][0]["technique_id"] == "T1110"


def test_custom_local_mitre_config_loading(tmp_path: Path) -> None:
    source = Path("config/mitre_mapping.yaml").read_text(encoding="utf-8")
    custom = tmp_path / "mitre_mapping.yaml"
    custom.write_text(source.replace("version: 1", "version: 2"), encoding="utf-8")

    config = load_mitre_mapping(custom)

    assert config.version == 2


def test_invalid_mitre_config_fails_clearly(tmp_path: Path) -> None:
    bad_config = tmp_path / "mitre_mapping.yaml"
    bad_config.write_text("[]", encoding="utf-8")

    with pytest.raises(MitreConfigError, match="YAML mapping"):
        load_mitre_mapping(bad_config)


def test_mitre_config_url_is_rejected() -> None:
    with pytest.raises(MitreConfigError, match="network paths"):
        load_mitre_mapping("https://example.com/mitre_mapping.yaml")


def test_mitre_config_path_traversal_is_rejected() -> None:
    with pytest.raises(MitreConfigError, match="path traversal"):
        load_mitre_mapping("../config/mitre_mapping.yaml")
