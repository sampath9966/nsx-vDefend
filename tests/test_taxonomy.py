"""Taxonomy configuration -- the thing that made this one shop's script."""

import json

import pytest

from nsx_toolkit.errors import ConfigError
from nsx_toolkit.taxonomy import DEFAULT_TAXONOMY, Taxonomy, load_taxonomy


def test_builtin_default_matches_the_original_hardcoded_scheme():
    t = Taxonomy()
    assert t.mandatory == ["tenant", "app", "env", "tier", "site", "server"]
    assert t.conditional == ["owner", "criticality", "data-class", "managed-by"]
    assert t.values_for("env") == ["prod", "uat", "dev", "staging", "dr"]
    assert t.values_for("tenant") is None


def test_rejects_a_value_outside_the_allowed_set():
    t = Taxonomy()
    assert t.validate_tag("env", "prod") == []
    issues = t.validate_tag("env", "production")
    assert len(issues) == 1 and "not allowed" in issues[0]


def test_rejects_a_scope_outside_the_taxonomy():
    t = Taxonomy()
    assert "not in taxonomy" in t.validate_tag("nonsense", "x")[0]


def test_allow_unknown_scopes_relaxes_that():
    t = Taxonomy({"scopes": {"env": {"required": True}},
                  "allow_unknown_scopes": True})
    assert t.validate_tag("anything", "value") == []


def test_reports_every_missing_mandatory_scope():
    t = Taxonomy()
    clean, issues = t.validate_vm_tags([("env", "prod")])
    assert not clean
    missing = [i for i in issues if "mandatory" in i]
    assert len(missing) == 5


def test_format_rule_is_configurable():
    t = Taxonomy({"format": r"^[A-Z]+$", "scopes": {"ENV": {"required": True}}})
    assert t.validate_tag("ENV", "PROD") == []
    assert t.validate_tag("ENV", "prod") != []


def test_loads_an_org_specific_scheme_from_json(tmp_path):
    spec = {"scopes": {"business-unit": {"required": True},
                       "zone": {"required": True, "values": ["red", "green"]}}}
    p = tmp_path / "taxonomy.json"
    p.write_text(json.dumps(spec), encoding="utf-8")
    t = load_taxonomy(None, search_dirs=[str(tmp_path)], names=("taxonomy.json",))
    assert t.mandatory == ["business-unit", "zone"]
    assert t.validate_tag("zone", "blue") != []
    assert t.source == str(p)


def test_falls_back_to_the_builtin_when_no_file_exists(tmp_path):
    expected = [k for k, v in DEFAULT_TAXONOMY["scopes"].items()
                if v.get("required")]
    t = load_taxonomy(None, search_dirs=[str(tmp_path)], names=("taxonomy.json",))
    assert t.source == "built-in default"
    assert t.mandatory == expected


def test_an_explicitly_named_missing_file_is_an_error(tmp_path):
    with pytest.raises(ConfigError) as exc:
        load_taxonomy(str(tmp_path / "nope.json"))
    assert "not found" in str(exc.value)


def test_invalid_json_is_reported_with_the_path(tmp_path):
    p = tmp_path / "taxonomy.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError) as exc:
        load_taxonomy(str(p))
    assert "taxonomy.json" in str(exc.value)


def test_a_broken_format_regex_is_reported():
    with pytest.raises(ConfigError) as exc:
        Taxonomy({"format": "([unclosed", "scopes": {}})
    assert "not a valid regex" in str(exc.value)
