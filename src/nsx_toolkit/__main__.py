"""Support `python -m nsx_toolkit`, for environments where a console script
is awkward to put on PATH."""

import sys

from .cli import main

if __name__ == "__main__":
    # via_module: being run this way is the tell-tale of an install whose
    # launcher the shell cannot find, so the CLI offers the repair.
    sys.exit(main(via_module=True))
