import sys
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shared.auth import issue_signed_payload, new_jti, now_epoch, peek_signed_payload

TOKEN_ISSUER = "token-service"
TOKEN_SERVICE_HTTP_BASE = "http://token-service:5003"
TOKEN_SERVICE_HTTPS_BASE = "https://token-service:5443"
INTERNAL_ADMIN_HTTP_BASE = "http://internal-admin:5001"
INTERNAL_ADMIN_HTTPS_BASE = "https://internal-admin:5443"
CA_CERT_PATH = "/tls/ca-cert.pem"
ASSERTION_TTL_SECONDS = 30
PROOF_TTL_SECONDS = 15
EXPORTER_ID = "admin-exporter"
OBSERVER_ID = "admin-observer"
EXPORTER_KEY_PATH = "/keys/admin-exporter-private.pem"
OBSERVER_KEY_PATH = "/keys/admin-observer-private.pem"
EXPORTER_CLIENT_CERT = ("/tls/admin-exporter-client-cert.pem", EXPORTER_KEY_PATH)
OBSERVER_CLIENT_CERT = ("/tls/admin-observer-client-cert.pem", OBSERVER_KEY_PATH)


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


def _service_proof(
    service_id: str, key_path: str, access_token: str, path: str, method: str = "GET"
) -> str:
    now = now_epoch()
    token_payload = peek_signed_payload(access_token)
    return issue_signed_payload(
        {
            "kind": "service_proof",
            "iss": service_id,
            "sub": service_id,
            "aud": "internal-admin",
            "method": method,
            "path": path,
            "token_jti": token_payload["jti"],
            "iat": now,
            "exp": now + PROOF_TTL_SECONDS,
            "jti": new_jti(),
        },
        key_path,
    )


def _https_get(url: str, *, cert=None, headers=None, params=None):
    return requests.get(
        url,
        cert=cert,
        verify=CA_CERT_PATH,
        headers=headers,
        params=params,
        timeout=5,
    )


def _mint(audience: str, scope: str, assertion: str, client_cert):
    return _https_get(
        f"{TOKEN_SERVICE_HTTPS_BASE}/mint",
        cert=client_cert,
        params={"aud": audience, "scope": scope},
        headers={"X-Service-Assertion": assertion},
    )


def _authorized_get(
    path: str,
    access_token: str,
    service_id: str,
    key_path: str,
    client_cert,
    proof=None,
    use_https: bool = True,
):
    headers = {"Authorization": f"Bearer {access_token}"}
    if proof is None:
        proof = _service_proof(service_id, key_path, access_token, path)
    headers["X-Service-Proof"] = proof

    if use_https:
        return _https_get(
            f"{INTERNAL_ADMIN_HTTPS_BASE}{path}",
            cert=client_cert,
            headers=headers,
        )

    return requests.get(
        f"{INTERNAL_ADMIN_HTTP_BASE}{path}",
        headers=headers,
        timeout=5,
    )


def test_https_mint_requires_client_certificate():
    assertion = _service_assertion(
        EXPORTER_ID,
        EXPORTER_KEY_PATH,
        "internal-admin",
        "admin.export.read",
    )

    with pytest.raises(requests.exceptions.SSLError):
        _https_get(
            f"{TOKEN_SERVICE_HTTPS_BASE}/mint",
            params={"aud": "internal-admin", "scope": "admin.export.read"},
            headers={"X-Service-Assertion": assertion},
        )


def test_http_privileged_endpoints_are_rejected_without_mtls():
    assertion = _service_assertion(
        EXPORTER_ID,
        EXPORTER_KEY_PATH,
        "internal-admin",
        "admin.export.read",
    )
    mint = requests.get(
        f"{TOKEN_SERVICE_HTTP_BASE}/mint",
        params={"aud": "internal-admin", "scope": "admin.export.read"},
        headers={"X-Service-Assertion": assertion},
        timeout=5,
    )
    assert mint.status_code == 403

    https_mint = _mint(
        "internal-admin",
        "admin.export.read",
        assertion,
        EXPORTER_CLIENT_CERT,
    )
    assert https_mint.status_code == 200

    access_token = https_mint.json()["access_token"]
    proof = _service_proof(
        EXPORTER_ID, EXPORTER_KEY_PATH, access_token, "/admin/export"
    )
    export = requests.get(
        f"{INTERNAL_ADMIN_HTTP_BASE}/admin/export",
        headers={
            "Authorization": f"Bearer {access_token}",
            "X-Service-Proof": proof,
        },
        timeout=5,
    )
    assert export.status_code == 403


def test_mint_requires_service_assertion():
    r = _https_get(
        f"{TOKEN_SERVICE_HTTPS_BASE}/mint",
        cert=EXPORTER_CLIENT_CERT,
        params={"aud": "internal-admin", "scope": "admin.export.read"},
    )
    assert r.status_code == 403


def test_observer_can_access_token_discovery():
    r = _https_get(
        f"{TOKEN_SERVICE_HTTPS_BASE}/.well-known/mesh",
        cert=OBSERVER_CLIENT_CERT,
        headers={
            "X-Service-Assertion": _service_assertion(
                OBSERVER_ID,
                OBSERVER_KEY_PATH,
                TOKEN_ISSUER,
                "token.discovery",
            )
        },
    )
    assert r.status_code == 200
    assert r.json()["mode"] == "ed25519-scoped-tokens"


def test_exporter_cannot_access_token_discovery():
    r = _https_get(
        f"{TOKEN_SERVICE_HTTPS_BASE}/.well-known/mesh",
        cert=EXPORTER_CLIENT_CERT,
        headers={
            "X-Service-Assertion": _service_assertion(
                EXPORTER_ID,
                EXPORTER_KEY_PATH,
                TOKEN_ISSUER,
                "token.discovery",
            )
        },
    )
    assert r.status_code == 403


def test_assertion_subject_must_match_client_certificate():
    r = _mint(
        "internal-admin",
        "admin.export.read",
        _service_assertion(
            EXPORTER_ID,
            EXPORTER_KEY_PATH,
            "internal-admin",
            "admin.export.read",
        ),
        OBSERVER_CLIENT_CERT,
    )
    assert r.status_code == 403


def test_exporter_can_mint_export_token_and_token_replay_is_blocked():
    mint = _mint(
        "internal-admin",
        "admin.export.read",
        _service_assertion(
            EXPORTER_ID,
            EXPORTER_KEY_PATH,
            "internal-admin",
            "admin.export.read",
        ),
        EXPORTER_CLIENT_CERT,
    )
    assert mint.status_code == 200

    access_token = mint.json()["access_token"]
    export = _authorized_get(
        "/admin/export",
        access_token,
        EXPORTER_ID,
        EXPORTER_KEY_PATH,
        EXPORTER_CLIENT_CERT,
    )
    assert export.status_code == 200
    assert export.json()["records"] == 2

    replay = _authorized_get(
        "/admin/export",
        access_token,
        EXPORTER_ID,
        EXPORTER_KEY_PATH,
        EXPORTER_CLIENT_CERT,
    )
    assert replay.status_code == 403


def test_service_assertion_replay_is_rejected():
    assertion = _service_assertion(
        EXPORTER_ID,
        EXPORTER_KEY_PATH,
        "internal-admin",
        "admin.export.read",
    )
    first = _mint(
        "internal-admin",
        "admin.export.read",
        assertion,
        EXPORTER_CLIENT_CERT,
    )
    second = _mint(
        "internal-admin",
        "admin.export.read",
        assertion,
        EXPORTER_CLIENT_CERT,
    )

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
        OBSERVER_CLIENT_CERT,
    )
    assert metrics_mint.status_code == 200

    metrics = _authorized_get(
        "/internal/metrics",
        metrics_mint.json()["access_token"],
        OBSERVER_ID,
        OBSERVER_KEY_PATH,
        OBSERVER_CLIENT_CERT,
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
        OBSERVER_CLIENT_CERT,
    )
    assert debug_mint.status_code == 200

    debug = _authorized_get(
        "/debug/config",
        debug_mint.json()["access_token"],
        OBSERVER_ID,
        OBSERVER_KEY_PATH,
        OBSERVER_CLIENT_CERT,
    )
    assert debug.status_code == 200

    export = _authorized_get(
        "/admin/export",
        metrics_mint.json()["access_token"],
        OBSERVER_ID,
        OBSERVER_KEY_PATH,
        OBSERVER_CLIENT_CERT,
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
        OBSERVER_CLIENT_CERT,
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
        EXPORTER_CLIENT_CERT,
    )
    assert wrong_audience.status_code == 403


def test_access_token_without_service_proof_is_rejected():
    mint = _mint(
        "internal-admin",
        "admin.export.read",
        _service_assertion(
            EXPORTER_ID,
            EXPORTER_KEY_PATH,
            "internal-admin",
            "admin.export.read",
        ),
        EXPORTER_CLIENT_CERT,
    )
    assert mint.status_code == 200

    r = _https_get(
        f"{INTERNAL_ADMIN_HTTPS_BASE}/admin/export",
        cert=EXPORTER_CLIENT_CERT,
        headers={"Authorization": f"Bearer {mint.json()['access_token']}"},
    )
    assert r.status_code == 403


def test_access_token_subject_must_match_client_certificate():
    mint = _mint(
        "internal-admin",
        "admin.export.read",
        _service_assertion(
            EXPORTER_ID,
            EXPORTER_KEY_PATH,
            "internal-admin",
            "admin.export.read",
        ),
        EXPORTER_CLIENT_CERT,
    )
    assert mint.status_code == 200

    access_token = mint.json()["access_token"]
    proof = _service_proof(
        EXPORTER_ID, EXPORTER_KEY_PATH, access_token, "/admin/export"
    )
    r = _authorized_get(
        "/admin/export",
        access_token,
        EXPORTER_ID,
        EXPORTER_KEY_PATH,
        OBSERVER_CLIENT_CERT,
        proof=proof,
    )
    assert r.status_code == 403


def test_service_proof_signed_by_wrong_key_is_rejected():
    mint = _mint(
        "internal-admin",
        "admin.export.read",
        _service_assertion(
            EXPORTER_ID,
            EXPORTER_KEY_PATH,
            "internal-admin",
            "admin.export.read",
        ),
        EXPORTER_CLIENT_CERT,
    )
    assert mint.status_code == 200

    access_token = mint.json()["access_token"]
    wrong_proof = _service_proof(
        EXPORTER_ID,
        OBSERVER_KEY_PATH,
        access_token,
        "/admin/export",
    )
    r = _authorized_get(
        "/admin/export",
        access_token,
        EXPORTER_ID,
        EXPORTER_KEY_PATH,
        EXPORTER_CLIENT_CERT,
        proof=wrong_proof,
    )
    assert r.status_code == 403


def test_service_proof_path_mismatch_is_rejected():
    mint = _mint(
        "internal-admin",
        "debug.config.read",
        _service_assertion(
            OBSERVER_ID,
            OBSERVER_KEY_PATH,
            "internal-admin",
            "debug.config.read",
        ),
        OBSERVER_CLIENT_CERT,
    )
    assert mint.status_code == 200

    access_token = mint.json()["access_token"]
    wrong_proof = _service_proof(
        OBSERVER_ID,
        OBSERVER_KEY_PATH,
        access_token,
        "/internal/metrics",
    )
    r = _authorized_get(
        "/debug/config",
        access_token,
        OBSERVER_ID,
        OBSERVER_KEY_PATH,
        OBSERVER_CLIENT_CERT,
        proof=wrong_proof,
    )
    assert r.status_code == 403


def test_client_signed_access_token_is_rejected():
    forged_token = issue_signed_payload(
        {
            "kind": "access_token",
            "iss": TOKEN_ISSUER,
            "sub": EXPORTER_ID,
            "aud": "internal-admin",
            "scope": "admin.export.read",
            "iat": now_epoch(),
            "exp": now_epoch() + 60,
            "jti": new_jti(),
            "one_time": True,
        },
        EXPORTER_KEY_PATH,
    )
    r = _authorized_get(
        "/admin/export",
        forged_token,
        EXPORTER_ID,
        EXPORTER_KEY_PATH,
        EXPORTER_CLIENT_CERT,
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
        OBSERVER_CLIENT_CERT,
    )
    assert mint.status_code == 200

    access_token = mint.json()["access_token"]
    payload_b64, signature_b64 = access_token.split(".", 1)
    tampered_signature = ("A" if signature_b64[0] != "A" else "B") + signature_b64[1:]
    tampered = f"{payload_b64}.{tampered_signature}"
    r = _authorized_get(
        "/debug/config",
        tampered,
        OBSERVER_ID,
        OBSERVER_KEY_PATH,
        OBSERVER_CLIENT_CERT,
        proof=_service_proof(
            OBSERVER_ID, OBSERVER_KEY_PATH, access_token, "/debug/config"
        ),
    )
    assert r.status_code == 403


def test_alg_none_style_token_is_rejected():
    fake_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJraW5kIjoiYWNjZXNzX3Rva2VuIn0."
    proof = issue_signed_payload(
        {
            "kind": "service_proof",
            "iss": EXPORTER_ID,
            "sub": EXPORTER_ID,
            "aud": "internal-admin",
            "method": "GET",
            "path": "/admin/export",
            "token_jti": "bogus",
            "iat": now_epoch(),
            "exp": now_epoch() + PROOF_TTL_SECONDS,
            "jti": new_jti(),
        },
        EXPORTER_KEY_PATH,
    )
    r = _https_get(
        f"{INTERNAL_ADMIN_HTTPS_BASE}/admin/export",
        cert=EXPORTER_CLIENT_CERT,
        headers={
            "Authorization": f"Bearer {fake_token}",
            "X-Service-Proof": proof,
        },
    )
    assert r.status_code == 403
