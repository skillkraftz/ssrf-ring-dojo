import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shared.auth import issue_signed_payload, new_jti, now_epoch

TOKEN_SERVICE_BASE = "http://token-service:5003"
INTERNAL_ADMIN_BASE = "http://internal-admin:5001"
TOKEN_ISSUER = "token-service"
TOKEN_TTL_SECONDS = 60
ASSERTION_TTL_SECONDS = 30
EXPORTER_ID = "admin-exporter"
OBSERVER_ID = "admin-observer"
EXPORTER_KEY_PATH = "/keys/admin-exporter-private.pem"
OBSERVER_KEY_PATH = "/keys/admin-observer-private.pem"


def _service_assertion(
    service_id: str, key_path: str, audience: str, scope: str
) -> str:
    now = now_epoch()
    return issue_signed_payload(
        {
            "kind": "service_assertion",
            "iss": service_id,
            "sub": service_id,
            "aud": TOKEN_ISSUER,
            "request_aud": audience,
            "request_scope": scope,
            "iat": now,
            "exp": now + ASSERTION_TTL_SECONDS,
            "jti": new_jti(),
        },
        key_path,
    )


def _access_token(
    signer_key_path: str,
    subject: str,
    scope: str,
    audience: str = "internal-admin",
    issuer: str = TOKEN_ISSUER,
):
    now = now_epoch()
    return issue_signed_payload(
        {
            "kind": "access_token",
            "iss": issuer,
            "sub": subject,
            "aud": audience,
            "scope": scope,
            "iat": now,
            "exp": now + TOKEN_TTL_SECONDS,
            "jti": new_jti(),
            "one_time": True,
        },
        signer_key_path,
    )


def _mint(audience: str, scope: str, assertion: str):
    return requests.get(
        f"{TOKEN_SERVICE_BASE}/mint",
        params={"aud": audience, "scope": scope},
        headers={"X-Service-Assertion": assertion},
        timeout=5,
    )


def test_mint_requires_service_assertion():
    r = requests.get(
        f"{TOKEN_SERVICE_BASE}/mint",
        params={"aud": "internal-admin", "scope": "admin.export.read"},
        timeout=5,
    )
    assert r.status_code == 403


def test_observer_can_access_token_discovery():
    r = requests.get(
        f"{TOKEN_SERVICE_BASE}/.well-known/mesh",
        headers={
            "X-Service-Assertion": _service_assertion(
                OBSERVER_ID,
                OBSERVER_KEY_PATH,
                TOKEN_ISSUER,
                "token.discovery",
            )
        },
        timeout=5,
    )
    assert r.status_code == 200
    assert r.json()["mode"] == "ed25519-scoped-tokens"


def test_exporter_can_mint_export_token_and_replay_is_blocked():
    mint = _mint(
        "internal-admin",
        "admin.export.read",
        _service_assertion(
            EXPORTER_ID,
            EXPORTER_KEY_PATH,
            "internal-admin",
            "admin.export.read",
        ),
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


def test_service_assertion_replay_is_rejected():
    assertion = _service_assertion(
        EXPORTER_ID,
        EXPORTER_KEY_PATH,
        "internal-admin",
        "admin.export.read",
    )
    first = _mint("internal-admin", "admin.export.read", assertion)
    second = _mint("internal-admin", "admin.export.read", assertion)

    assert first.status_code == 200
    assert second.status_code == 403


def test_observer_can_read_metrics_and_debug_but_not_export():
    metrics_mint = _mint(
        "internal-admin",
        "internal.metrics.read",
        _service_assertion(
            OBSERVER_ID,
            OBSERVER_KEY_PATH,
            "internal-admin",
            "internal.metrics.read",
        ),
    )
    assert metrics_mint.status_code == 200

    metrics = requests.get(
        f"{INTERNAL_ADMIN_BASE}/internal/metrics",
        headers={"Authorization": f"Bearer {metrics_mint.json()['access_token']}"},
        timeout=5,
    )
    assert metrics.status_code == 200

    debug_mint = _mint(
        "internal-admin",
        "debug.config.read",
        _service_assertion(
            OBSERVER_ID,
            OBSERVER_KEY_PATH,
            "internal-admin",
            "debug.config.read",
        ),
    )
    assert debug_mint.status_code == 200

    debug = requests.get(
        f"{INTERNAL_ADMIN_BASE}/debug/config",
        headers={"Authorization": f"Bearer {debug_mint.json()['access_token']}"},
        timeout=5,
    )
    assert debug.status_code == 200

    export = requests.get(
        f"{INTERNAL_ADMIN_BASE}/admin/export",
        headers={"Authorization": f"Bearer {metrics_mint.json()['access_token']}"},
        timeout=5,
    )
    assert export.status_code == 403


def test_wrong_scope_and_wrong_audience_are_rejected():
    wrong_scope = _mint(
        "internal-admin",
        "admin.export.read",
        _service_assertion(
            OBSERVER_ID,
            OBSERVER_KEY_PATH,
            "internal-admin",
            "admin.export.read",
        ),
    )
    assert wrong_scope.status_code == 403

    wrong_audience = _mint(
        TOKEN_ISSUER,
        "admin.export.read",
        _service_assertion(
            EXPORTER_ID,
            EXPORTER_KEY_PATH,
            TOKEN_ISSUER,
            "admin.export.read",
        ),
    )
    assert wrong_audience.status_code == 403


def test_forged_exporter_assertion_with_observer_key_is_rejected():
    forged = _service_assertion(
        EXPORTER_ID,
        OBSERVER_KEY_PATH,
        "internal-admin",
        "admin.export.read",
    )
    r = _mint("internal-admin", "admin.export.read", forged)
    assert r.status_code == 403


def test_client_signed_access_token_is_rejected():
    forged_token = _access_token(EXPORTER_KEY_PATH, EXPORTER_ID, "admin.export.read")
    r = requests.get(
        f"{INTERNAL_ADMIN_BASE}/admin/export",
        headers={"Authorization": f"Bearer {forged_token}"},
        timeout=5,
    )
    assert r.status_code == 403


def test_tampered_access_token_is_rejected():
    mint = _mint(
        "internal-admin",
        "debug.config.read",
        _service_assertion(
            OBSERVER_ID,
            OBSERVER_KEY_PATH,
            "internal-admin",
            "debug.config.read",
        ),
    )
    assert mint.status_code == 200

    access_token = mint.json()["access_token"]
    payload_b64, signature_b64 = access_token.split(".", 1)
    tampered_signature = ("A" if signature_b64[0] != "A" else "B") + signature_b64[1:]
    tampered = f"{payload_b64}.{tampered_signature}"
    debug = requests.get(
        f"{INTERNAL_ADMIN_BASE}/debug/config",
        headers={"Authorization": f"Bearer {tampered}"},
        timeout=5,
    )
    assert debug.status_code == 403


def test_alg_none_style_token_is_rejected():
    fake_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJraW5kIjoiYWNjZXNzX3Rva2VuIn0."
    r = requests.get(
        f"{INTERNAL_ADMIN_BASE}/admin/export",
        headers={"Authorization": f"Bearer {fake_jwt}"},
        timeout=5,
    )
    assert r.status_code == 403
