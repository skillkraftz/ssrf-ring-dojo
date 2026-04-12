import os
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app as token_app

BASE = "http://127.0.0.1:5003"
INTERNAL_ADMIN_BASE = "http://internal-admin:5001"
CLIENT_ID = os.getenv("INTERNAL_ADMIN_CLIENT_ID", "internal-admin")
CLIENT_SECRET = os.getenv(
    "INTERNAL_ADMIN_CLIENT_SECRET", "dev-internal-admin-client-secret"
)


def _service_assertion(audience: str, scope: str) -> str:
    return token_app.issue_service_assertion(CLIENT_ID, CLIENT_SECRET, audience, scope)


def _mint(audience: str, scope: str, assertion: str):
    return requests.get(
        f"{BASE}/mint",
        params={"aud": audience, "scope": scope},
        headers={"X-Service-Assertion": assertion},
        timeout=5,
    )


def test_authorized_service_can_mint_export_token_and_use_it_once():
    mint = _mint(
        "internal-admin",
        "admin.export.read",
        _service_assertion("internal-admin", "admin.export.read"),
    )
    assert mint.status_code == 200

    access_token = mint.json()["access_token"]
    export = requests.get(
        f"{INTERNAL_ADMIN_BASE}/admin/export",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=5,
    )
    assert export.status_code == 200
    assert export.json()["records"] == 2

    replay = requests.get(
        f"{INTERNAL_ADMIN_BASE}/admin/export",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=5,
    )
    assert replay.status_code == 403


def test_assertion_replay_is_rejected():
    assertion = _service_assertion("internal-admin", "admin.export.read")
    first = _mint("internal-admin", "admin.export.read", assertion)
    second = _mint("internal-admin", "admin.export.read", assertion)

    assert first.status_code == 200
    assert second.status_code == 403


def test_scope_bound_assertion_cannot_be_reused_for_other_scope():
    assertion = _service_assertion("internal-admin", "internal.metrics.read")
    r = _mint("internal-admin", "admin.export.read", assertion)
    assert r.status_code == 403


def test_metrics_token_cannot_access_export():
    mint = _mint(
        "internal-admin",
        "internal.metrics.read",
        _service_assertion("internal-admin", "internal.metrics.read"),
    )
    assert mint.status_code == 200

    access_token = mint.json()["access_token"]
    export = requests.get(
        f"{INTERNAL_ADMIN_BASE}/admin/export",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=5,
    )
    assert export.status_code == 403


def test_wrong_audience_is_rejected():
    r = _mint(
        "token-service",
        "admin.export.read",
        _service_assertion("token-service", "admin.export.read"),
    )
    assert r.status_code == 403


def test_tampered_access_token_is_rejected():
    mint = _mint(
        "internal-admin",
        "debug.config.read",
        _service_assertion("internal-admin", "debug.config.read"),
    )
    assert mint.status_code == 200

    access_token = mint.json()["access_token"]
    tampered = access_token[:-1] + ("A" if access_token[-1] != "A" else "B")
    debug = requests.get(
        f"{INTERNAL_ADMIN_BASE}/debug/config",
        headers={"Authorization": f"Bearer {tampered}"},
        timeout=5,
    )
    assert debug.status_code == 403
