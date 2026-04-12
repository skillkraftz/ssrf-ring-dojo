"""
Test fixtures and path bootstrap.

Two responsibilities:

  1. Make the gateway's ``app`` module importable from the test files.
     The Dockerfile copies ``app.py`` to ``/app/app.py`` and the tests
     to ``/app/tests/``. pytest's default rootdir handling does not
     add ``/app`` to ``sys.path``, so we do it explicitly here.

  2. Reset token-service's rate limiter + nonce cache and the gateway's
     /fetch rate limiter at the start of every test session. The
     /_test/reset endpoints are lab-only affordances gated on
     APP_ENV=dev and a header secret, and make our rate-limit
     assertions deterministic regardless of how many requests other
     sessions consumed.
"""

import pathlib
import sys

import pytest
import requests

_HERE = pathlib.Path(__file__).resolve().parent
_GATEWAY_ROOT = _HERE.parent
if str(_GATEWAY_ROOT) not in sys.path:
    sys.path.insert(0, str(_GATEWAY_ROOT))


# mTLS bundle for any internal call. Gateway-image containers have
# /certs mounted via docker-compose.
_CA_FILE = "/certs/ca.crt"
_CLIENT_CERT = "/certs/gateway.crt"
_CLIENT_KEY = "/certs/gateway.key"


@pytest.fixture(scope="session", autouse=True)
def _reset_stateful_caches():
    """Once per test session, reset state on token-service and gateway.
    Uses the mTLS client bundle for the token-service call (which is
    HTTPS-only). Gateway's /_test/reset is on the same-process HTTP
    listener (127.0.0.1) and does not need a cert."""
    try:
        requests.post(
            "https://token-service:5003/_test/reset",
            headers={"X-Test-Reset-Token": "dojo-test-reset"},
            cert=(_CLIENT_CERT, _CLIENT_KEY),
            verify=_CA_FILE,
            timeout=2,
        )
    except Exception:
        pass
    try:
        requests.post(
            "http://127.0.0.1:5000/_test/reset",
            headers={"X-Test-Reset-Token": "dojo-test-reset"},
            timeout=2,
        )
    except Exception:
        pass
    yield
