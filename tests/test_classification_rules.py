from __future__ import annotations

from pathlib import Path

import pytest

from triage_lab.classification.rules import RuleConfigError, load_rules
from triage_lab.models.severity import Severity

EXPECTED_BASE = {
    "failed_login": Severity.LOW,
    "brute_force": Severity.HIGH,
    "port_scan": Severity.MEDIUM,
    "privilege_escalation": Severity.CRITICAL,
    "data_exfiltration": Severity.CRITICAL,
    "lateral_movement": Severity.HIGH,
    "malware_detected": Severity.CRITICAL,
    "c2_beacon": Severity.CRITICAL,
    "policy_violation": Severity.LOW,
    "anomalous_login_time": Severity.MEDIUM,
    "unknown": Severity.MEDIUM,
}


def test_default_config_loading_and_base_severity() -> None:
    ruleset = load_rules()

    assert ruleset.name == "offline-alert-triage-default-rules"
    assert ruleset.version == 1
    assert ruleset.default_severity == Severity.MEDIUM
    assert ruleset.base_severity == EXPECTED_BASE


def test_custom_local_config_loading(tmp_path: Path) -> None:
    source = Path("config/rules.yaml").read_text(encoding="utf-8")
    custom = tmp_path / "rules.yaml"
    custom.write_text(source.replace("version: 1", "version: 2"), encoding="utf-8")

    ruleset = load_rules(custom)

    assert ruleset.version == 2


def test_invalid_config_fails_clearly(tmp_path: Path) -> None:
    bad_config = tmp_path / "rules.yaml"
    bad_config.write_text("[]", encoding="utf-8")

    with pytest.raises(RuleConfigError, match="YAML mapping"):
        load_rules(bad_config)


def test_config_url_is_rejected() -> None:
    with pytest.raises(RuleConfigError, match="network paths"):
        load_rules("https://example.com/rules.yaml")


def test_config_path_traversal_is_rejected() -> None:
    with pytest.raises(RuleConfigError, match="path traversal"):
        load_rules("../config/rules.yaml")
