"""Parity: same-manager resolution and complete exports."""

import pytest
from fake_nsx import FakeNsx

from nsx_toolkit.actions.parity import act_parity, resolve_pair
from nsx_toolkit.errors import NsxError
from nsx_toolkit.export import Exporter


def _rows(exp):
    return exp.sets[0].rows


def _seed(fake, static_members, dynamic_members):
    fake.state.add_group("static-web", "Static Web",
                         members=[{"display_name": n, "id": n}
                                  for n in static_members])
    fake.state.add_group("dyn-web", "Dynamic Web",
                         members=[{"display_name": n, "id": n}
                                  for n in dynamic_members])


def test_exports_every_row_not_just_the_first_thirty(lm, make_session):
    """The console caps long listings; the export must not.

    Previously only the first 30 of each difference list reached the CSV, so
    the file handed to a change board silently under-reported the work.
    """
    only_static = ["s{:03d}".format(i) for i in range(45)]
    only_dynamic = ["d{:03d}".format(i) for i in range(40)]
    both = ["b{:03d}".format(i) for i in range(10)]
    _seed(lm, only_static + both, only_dynamic + both)

    exp = Exporter()
    act_parity([make_session(lm)], "default", "static-web", "dyn-web", exp)
    rows = _rows(exp)

    by_status = {}
    for r in rows:
        by_status.setdefault(r[4], []).append(r[0])
    assert len(by_status["needs_migration"]) == 45
    assert len(by_status["unexpected"]) == 40
    assert len(by_status["migrated"]) == 10
    assert len(rows) == 95


def test_both_groups_resolve_on_the_same_manager(make_session):
    """A name present on both GM and an LM must not compare a GM copy against
    an LM copy -- that reports a difference that is really two scopes."""
    with FakeNsx(role="gm", name="gm1") as gm, FakeNsx(role="lm", name="lm1") as lm1:
        gm.state.add_group("static-web", "Static Web",
                           members=[{"display_name": "gm-only", "id": "1"}])
        _seed(lm1, ["a", "b"], ["a"])
        nsx, base, gs, gd = resolve_pair(
            [make_session(gm), make_session(lm1)], "default",
            "static-web", "dyn-web")
        assert nsx.name == "lm1"
        assert gs["id"] == "static-web" and gd["id"] == "dyn-web"


def test_missing_static_group_names_which_side_failed(lm, make_session):
    lm.state.add_group("dyn-web", "Dynamic Web")
    with pytest.raises(NsxError) as exc:
        resolve_pair([make_session(lm)], "default", "static-web", "dyn-web")
    assert "Static group" in str(exc.value)


def test_groups_split_across_managers_is_refused(make_session):
    with FakeNsx(role="lm", name="lm1") as a, FakeNsx(role="lm", name="lm2") as b:
        a.state.add_group("static-web", "Static Web")
        b.state.add_group("dyn-web", "Dynamic Web")
        with pytest.raises(NsxError) as exc:
            resolve_pair([make_session(a), make_session(b)], "default",
                         "static-web", "dyn-web")
        assert "never on the same manager" in str(exc.value)


def test_full_parity_reports_every_member_as_migrated(lm, make_session):
    _seed(lm, ["a", "b", "c"], ["a", "b", "c"])
    exp = Exporter()
    act_parity([make_session(lm)], "default", "static-web", "dyn-web", exp)
    assert {r[4] for r in _rows(exp)} == {"migrated"}
