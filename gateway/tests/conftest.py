"""
Test fixture: make the gateway's ``app`` module importable from the
test files. The Dockerfile copies ``app.py`` to ``/app/app.py`` and the
tests to ``/app/tests/``. pytest's default rootdir handling does not
add ``/app`` to ``sys.path``, so we do it explicitly here.
"""

import pathlib
import sys

_HERE = pathlib.Path(__file__).resolve().parent
_GATEWAY_ROOT = _HERE.parent
if str(_GATEWAY_ROOT) not in sys.path:
    sys.path.insert(0, str(_GATEWAY_ROOT))
