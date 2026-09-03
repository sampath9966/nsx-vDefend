"""Support `python -m nsx_toolkit`, for environments where a console script
is awkward to put on PATH."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
