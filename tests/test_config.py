"""Inventory loading and validation."""

import json

import pytest

from nsx_toolkit.config import (
    default_env_names,
    find_inventory,
    load_inventory,
    write_inventory,
)
from nsx_toolkit.errors import ConfigError


def write(tmp_path, data, name="inventory.json"):
    p = tmp_path / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


def test_loads_a_valid_inventory(tmp_path):
    p = write(tmp_path, {"managers": [
        {"name": "lm1", "role": "lm", "host": "h1"}]})
    managers = load_inventory(p)
    assert managers[0]["name"] == "lm1"
    assert managers[0]["port"] == 443
    assert managers[0]["auth"] == "session"


def test_missing_inventory_returns_none_rather_than_raising(tmp_path):
    assert find_inventory(None, [str(tmp_path)]) is None


def test_malformed_json_is_a_hard_error(tmp_path):
    p = tmp_path / "inventory.json"
    p.write_text("{oops", encoding="utf-8")
    with pytest.raises(ConfigError) as exc:
        load_inventory(str(p))
    assert "Invalid JSON" in str(exc.value)


def test_every_problem_is_reported_at_once(tmp_path):
    p = write(tmp_path, {"managers": [
        {"name": "a", "role": "wrong", "host": "h"},
        {"role": "lm"},
        {"name": "a", "role": "lm", "host": "h2"},
    ]})
    with pytest.raises(ConfigError) as exc:
        load_inventory(p)
    text = str(exc.value)
    assert "'role' must be" in text
    assert "missing 'name'" in text
    assert "missing 'host'" in text
    assert "duplicate manager name" in text


def test_empty_managers_list_is_rejected(tmp_path):
    with pytest.raises(ConfigError) as exc:
        load_inventory(write(tmp_path, {"managers": []}))
    assert "no 'managers'" in str(exc.value)


def test_bad_auth_mode_is_rejected(tmp_path):
    p = write(tmp_path, {"managers": [
        {"name": "a", "role": "lm", "host": "h", "auth": "magic"}]})
    with pytest.raises(ConfigError) as exc:
        load_inventory(p)
    assert "'auth' must be one of" in str(exc.value)


def test_env_var_names_are_derived_from_the_manager_name():
    assert default_env_names("lm-paris.1") == ("NSX_LM_PARIS_1_USER",
                                               "NSX_LM_PARIS_1_PASS")


def test_written_inventory_reloads_cleanly(tmp_path):
    entry = {"name": "lm1", "role": "lm", "host": "h", "port": 443,
             "verify_ssl": False, "auth": "session",
             "username_env": "U", "password_env": "P"}
    path = write_inventory(str(tmp_path / "sub" / "inventory.json"), [entry])
    assert load_inventory(path)[0]["name"] == "lm1"
