"""Transport, pagination, retry and authentication."""

import pytest

from nsx_toolkit.api import PATH_FABRIC_VMS
from nsx_toolkit.errors import NsxError
from nsx_toolkit.http import UrllibTransport


def test_session_auth_is_used_once_not_per_request(lm, make_session):
    for i in range(5):
        lm.state.add_vm("vm{}".format(i))
    s = make_session(lm)
    s.get_all(PATH_FABRIC_VMS)
    s.get_all(PATH_FABRIC_VMS)
    # One session create for many requests: Basic on every call is what risks
    # AD lockout, and is exactly what this asserts we no longer do.
    assert lm.state.count("POST /api/session/create") == 1
    assert lm.state.count("GET /api/v1/fabric/virtual-machines") >= 2


def test_basic_auth_mode_never_calls_session_create(lm, make_session):
    lm.state.add_vm("vm1")
    s = make_session(lm, auth="basic")
    s.get_all(PATH_FABRIC_VMS)
    assert lm.state.count("POST /api/session/create") == 0


def test_pagination_follows_cursor_to_completion(lm, make_session):
    for i in range(250):
        lm.state.add_vm("vm{:03d}".format(i))
    s = make_session(lm)
    # An explicit page_size wins over the default, so this walks 3 pages.
    vms = s.get_all(PATH_FABRIC_VMS, params={"page_size": 100})
    assert len(vms) == 250
    assert lm.state.count("GET /api/v1/fabric/virtual-machines") == 3
    assert len({v["display_name"] for v in vms}) == 250


def test_retries_transient_503_then_succeeds(lm, make_session):
    lm.state.add_vm("vm1")
    lm.state.fail_next("/api/v1/fabric/virtual-machines", times=2)
    s = make_session(lm)
    s.retries = 3
    vms = s.get_all(PATH_FABRIC_VMS)
    assert len(vms) == 1


def test_gives_up_after_retries_are_exhausted(lm, make_session):
    lm.state.add_vm("vm1")
    lm.state.fail_next("/api/v1/fabric/virtual-machines", times=10)
    s = make_session(lm)
    s.retries = 1
    with pytest.raises(NsxError) as exc:
        s.get_all(PATH_FABRIC_VMS)
    assert "503" in str(exc.value)


def test_gm_probes_its_api_base(gm, make_session):
    gm.state.add_group("g1")
    s = make_session(gm)
    assert s.base() == "/global-manager/api/v1/global-infra"


def test_stdlib_transport_works_without_requests(lm, make_session):
    lm.state.add_vm("vm1", tags=[("env", "prod")])
    s = make_session(lm)
    s.t = UrllibTransport()
    s._authenticated = False
    vms = s.get_all(PATH_FABRIC_VMS)
    assert [v["display_name"] for v in vms] == ["vm1"]


def test_vm_index_is_fetched_once_and_cached(lm, make_session):
    for i in range(10):
        lm.state.add_vm("web{}".format(i))
    s = make_session(lm)
    s.all_vms()
    s.all_vms()
    s.all_vms()
    assert lm.state.count("GET /api/v1/fabric/virtual-machines") == 1


def test_update_tags_invalidates_the_cache(lm, make_session):
    vm = lm.state.add_vm("web1", tags=[("env", "dev")])
    s = make_session(lm)
    s.all_vms()
    s.update_vm_tags(vm, [("env", "prod")])
    fresh = s.all_vms()
    assert fresh[0]["tags"] == [{"scope": "env", "tag": "prod"}]
