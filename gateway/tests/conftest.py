"""
Test fixtures and path bootstrap.

Two responsibilities:

  1. Make the gateway's ``app`` module importable from the test files.
     The Dockerfile copies ``app.py`` to ``/app/app.py`` and the tests
     to ``/app/tests/``. pytest's default rootdir handling does not
     add ``/app`` to ``sys.path``, so we do it explicitly here.

  2. Reset token-service's rate limiter + nonce cache at the start of
     every test session. The /_test/reset endpoint is a lab-only
     affordance gated on APP_ENV=dev and a header secret, and makes
     our rate-limit assertions deterministic regardless of how many
     mints other tests consume.
"""

import pathlib
import sys

import pytest
import requests

_HERE = pathlib.Path(__file__).resolve().parent
_GATEWAY_ROOT = _HERE.parent
if str(_GATEWAY_ROOT) not in sys.path:
    sys.path.insert(0, str(_GATEWAY_ROOT))


@pytest.fixture(scope="session", autouse=True)
def _reset_stateful_caches():
    """Once per test session, reset the stateful caches in both
    token-service and the gateway so tests start from a clean state
    regardless of what a previous session did. Best-effort: unreachable
    services just skip."""
    for url in (
        "http://token-service:5003/_test/reset",
        "http://127.0.0.1:5000/_test/reset",
    ):
        try:
            requests.post(
                url,
                headers={"X-Test-Reset-Token": "dojo-test-reset"},
                timeout=2,
            )
        except Exception:
            pass
    yield
