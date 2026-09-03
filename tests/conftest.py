import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "src"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fake_nsx import FakeNsx  # noqa: E402

from nsx_toolkit import output  # noqa: E402
from nsx_toolkit.http import Nsx  # noqa: E402


@pytest.fixture(autouse=True)
def quiet_output():
    """Tests assert on behaviour, not on console noise."""
    output.set_color(False)
    output.set_json_mode(False)
    output.set_interactive(False)
    output.set_assume_yes(False)
    output.set_debug(False)
    yield
    output.set_json_mode(False)


@pytest.fixture
def lm():
    with FakeNsx(role="lm", name="lm1") as f:
        yield f


@pytest.fixture
def gm():
    with FakeNsx(role="gm", name="gm1") as f:
        yield f


def session_for(fake, **overrides):
    return Nsx(fake.entry(**overrides), "user", "pass")


@pytest.fixture
def make_session():
    created = []

    def _make(fake, **overrides):
        s = session_for(fake, **overrides)
        created.append(s)
        return s

    yield _make
    for s in created:
        s.close()
