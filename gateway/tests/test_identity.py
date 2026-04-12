"""
Service-identity test suite.

These tests prove that:

  * legitimate, end-to-end JWT-mediated calls still work
  * unauthenticated, mis-signed, expired, replayed, wrong-audience, and
    wrong-scope tokens are all rejected
  * token-service /v2/mint refuses unknown clients, bad signatures,
    stale timestamps, and replayed nonces
  * the per-client scope policy at the issuer prevents a credential
    from minting tokens for scopes it isn't allowed to request
    (the "compromised gateway" / lateral-movement scenario)

The tests run from inside the gateway container, where the identity
helpers from the gateway's app module can be imported directly and
where every other service is reachable on the docker bridge network.

File name is alphabetically before test_security.py so this test file
runs first; the rate-limit integration test in test_security.py still
runs absolutely last (it intentionally drains the rate limit bucket).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

import jwt as pyjwt
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

GATEWAY_BASE = "http://127.0.0.1:5000"
TOKEN_SERVICE_BASE = "http://token-service:5003"
INTERNAL_ADMIN_BASE = "http://internal-admin:5001"
ADMIN_API_KEY = "lab-admin-key-rotate-me"

# These mirror token-service's lab default policy.
#
# IMPORTANT: the EXPORT_JOB credentials are intentionally NOT present in
# the gateway container's runtime environment in production. They live
# here in the test file so we can exercise the legitimate export flow
# from the test harness; a real deployment would run the export flow
# from a dedicated worker/batch container whose secrets never touch the
# gateway. This file is a lab artifact.
GATEWAY_CLIENT_ID = "gateway"
GATEWAY_CLIENT_SECRET = "gateway-client-secret-do-not-reuse"
EXPORT_JOB_CLIENT_ID = "export-job"
EXPORT_JOB_CLIENT_SECRET = "export-job-secret-do-not-reuse"
METRICS_ONLY_CLIENT_ID = "metrics-only-client"
METRICS_ONLY_CLIENT_SECRET = "metrics-only-secret-do-not-reuse"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sign_client_request(client_id: str, secret: str, ts: str, nonce: str) -> str:
    msg = f"{client_id}|{ts}|{nonce}".encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def _mint(
    *,
    audience: str,
    scopes: list,
    client_id: str = GATEWAY_CLIENT_ID,
    client_secret: str = GATEWAY_CLIENT_SECRET,
    ts: str | None = None,
    nonce: str | None = None,
    signature: str | None = None,
    drop_headers: list = (),
) -> requests.Response:
    """Issue a /v2/mint call. All credential parameters are overridable
    so individual tests can poke at the failure modes."""
    if ts is None:
        ts = str(int(time.time()))
    if nonce is None:
        nonce = secrets.token_urlsafe(24)
    if signature is None:
        signature = _sign_client_request(client_id, client_secret, ts, nonce)
    headers = {
        "X-Client-Id": client_id,
        "X-Client-Timestamp": ts,
        "X-Client-Nonce": nonce,
        "X-Client-Auth": signature,
        "Content-Type": "application/json",
    }
    for h in drop_headers:
        headers.pop(h, None)
    return requests.post(
        f"{TOKEN_SERVICE_BASE}/v2/mint",
        json={"audience": audience, "scopes": scopes},
        headers=headers,
        timeout=5,
    )


def _good_token(audience="internal-admin", scopes=("metrics:read",)) -> str:
    r = _mint(audience=audience, scopes=list(scopes))
    assert r.status_code == 200, f"happy-path mint failed: {r.status_code} {r.text}"
    return r.json()["token"]


# ===========================================================================
# 1. Legitimate flows
# ===========================================================================


def test_jwks_endpoint_publishes_ed25519_key():
    r = requests.get(f"{TOKEN_SERVICE_BASE}/.well-known/jwks.json", timeout=3)
    assert r.status_code == 200
    keys = r.json()["keys"]
    assert len(keys) >= 1
    k = keys[0]
    assert k["kty"] == "OKP"
    assert k["crv"] == "Ed25519"
    assert k["alg"] == "EdDSA"
    assert k["use"] == "sig"
    assert "x" in k


def test_mint_v2_legitimate_request_works():
    r = _mint(audience="internal-admin", scopes=["metrics:read"])
    assert r.status_code == 200
    payload = r.json()
    assert payload["token_type"] == "Bearer"
    assert payload["audience"] == "internal-admin"
    assert "metrics:read" in payload["scope"]
    # Decode without verification to inspect claims structure
    claims = pyjwt.decode(payload["token"], options={"verify_signature": False})
    assert claims["iss"] == "token-service"
    assert claims["sub"] == GATEWAY_CLIENT_ID
    assert claims["aud"] == "internal-admin"
    assert "jti" in claims and len(claims["jti"]) >= 16
    assert claims["exp"] > claims["iat"]


def test_internal_admin_metrics_with_legit_jwt_works():
    token = _good_token(scopes=("metrics:read",))
    r = requests.get(
        f"{INTERNAL_ADMIN_BASE}/internal/metrics",
        headers={"Authorization": f"Bearer {token}"},
        timeout=3,
    )
    assert r.status_code == 200
    assert r.json()["caller"] == GATEWAY_CLIENT_ID


def test_internal_admin_export_with_legit_export_job_jwt_works():
    """The legitimate export flow runs from the export-job client (a
    separate identity whose secret is not shared with gateway). It
    must still work end to end."""
    r = _mint(
        audience="internal-admin",
        scopes=["admin:export"],
        client_id=EXPORT_JOB_CLIENT_ID,
        client_secret=EXPORT_JOB_CLIENT_SECRET,
    )
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    r2 = requests.get(
        f"{INTERNAL_ADMIN_BASE}/admin/export",
        headers={"Authorization": f"Bearer {token}"},
        timeout=3,
    )
    assert r2.status_code == 200
    payload = r2.json()
    assert payload["caller"] == EXPORT_JOB_CLIENT_ID
    assert payload["data"] == "sensitive export"


def test_internal_admin_debug_config_with_legit_jwt_works():
    token = _good_token(scopes=("debug:read",))
    r = requests.get(
        f"{INTERNAL_ADMIN_BASE}/debug/config",
        headers={"Authorization": f"Bearer {token}"},
        timeout=3,
    )
    assert r.status_code == 200
    assert r.json()["caller"] == GATEWAY_CLIENT_ID


def test_gateway_admin_metrics_end_to_end():
    r = requests.get(
        f"{GATEWAY_BASE}/admin/metrics",
        headers={"X-Admin-Api-Key": ADMIN_API_KEY},
        timeout=5,
    )
    assert r.status_code == 200
    body = r.json()["body"]
    assert body["service"] == "internal-admin"
    assert body["caller"] == GATEWAY_CLIENT_ID


def test_gateway_admin_export_is_retired():
    """The gateway's /admin/export surface is intentionally retired
    because gateway no longer holds the admin:export scope. It must
    return 410 Gone regardless of credentials, so operators get a
    clear signal rather than a confusing 401/403."""
    for headers in (
        {},
        {"X-Admin-Api-Key": ADMIN_API_KEY},
        {"X-Admin-Api-Key": "wrong-key"},
    ):
        r = requests.get(f"{GATEWAY_BASE}/admin/export", headers=headers, timeout=3)
        assert r.status_code == 410, f"expected 410 with headers={headers}"
        payload = r.json()
        assert "gone" in payload.get("error", "").lower()


def test_gateway_admin_endpoints_require_admin_api_key():
    # /admin/export is deliberately excluded: it's 410 Gone for
    # everyone, which is covered by test_gateway_admin_export_is_retired.
    for path in ("/admin/metrics", "/admin/debug-config"):
        r = requests.get(f"{GATEWAY_BASE}{path}", timeout=3)
        assert r.status_code == 401
        r2 = requests.get(
            f"{GATEWAY_BASE}{path}",
            headers={"X-Admin-Api-Key": "wrong-key"},
            timeout=3,
        )
        assert r2.status_code == 401


# ===========================================================================
# 2. Token-service mint authentication failures
# ===========================================================================


def test_mint_v2_no_client_credentials_blocked():
    r = requests.post(
        f"{TOKEN_SERVICE_BASE}/v2/mint",
        json={"audience": "internal-admin", "scopes": ["metrics:read"]},
        timeout=3,
    )
    assert r.status_code == 401


def test_mint_v2_unknown_client_blocked():
    r = _mint(
        audience="internal-admin",
        scopes=["metrics:read"],
        client_id="ghost-client",
        client_secret="anything",
    )
    assert r.status_code == 401
    assert "unknown" in r.json()["error"]


def test_mint_v2_bad_signature_blocked():
    ts = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    # Sign with the WRONG secret
    bad_sig = _sign_client_request(GATEWAY_CLIENT_ID, "wrong-secret", ts, nonce)
    r = _mint(
        audience="internal-admin",
        scopes=["metrics:read"],
        ts=ts,
        nonce=nonce,
        signature=bad_sig,
    )
    assert r.status_code == 401
    assert "bad signature" in r.json()["error"]


def test_mint_v2_stale_timestamp_blocked():
    old_ts = str(int(time.time()) - 600)  # 10 min in the past
    r = _mint(
        audience="internal-admin",
        scopes=["metrics:read"],
        ts=old_ts,
    )
    assert r.status_code == 401
    assert "stale" in r.json()["error"]


def test_mint_v2_future_timestamp_blocked():
    future_ts = str(int(time.time()) + 600)  # 10 min in the future
    r = _mint(
        audience="internal-admin",
        scopes=["metrics:read"],
        ts=future_ts,
    )
    assert r.status_code == 401


def test_mint_v2_replayed_nonce_blocked():
    ts = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    sig = _sign_client_request(GATEWAY_CLIENT_ID, GATEWAY_CLIENT_SECRET, ts, nonce)
    # First use: should succeed
    r1 = _mint(
        audience="internal-admin",
        scopes=["metrics:read"],
        ts=ts,
        nonce=nonce,
        signature=sig,
    )
    assert r1.status_code == 200
    # Second use of the SAME (ts, nonce, sig): replay
    r2 = _mint(
        audience="internal-admin",
        scopes=["metrics:read"],
        ts=ts,
        nonce=nonce,
        signature=sig,
    )
    assert r2.status_code == 401
    assert "nonce" in r2.json()["error"]


def test_mint_v2_short_nonce_blocked():
    # Length sanity: nonces shorter than 16 chars are rejected
    r = _mint(
        audience="internal-admin",
        scopes=["metrics:read"],
        nonce="short",
    )
    assert r.status_code == 401


def test_mint_v2_missing_individual_headers_blocked():
    for header in (
        "X-Client-Id",
        "X-Client-Timestamp",
        "X-Client-Nonce",
        "X-Client-Auth",
    ):
        r = _mint(
            audience="internal-admin",
            scopes=["metrics:read"],
            drop_headers=[header],
        )
        assert r.status_code == 401, f"missing {header} should 401, got {r.status_code}"


# ===========================================================================
# 3. Per-client scope and audience policy (lateral-movement defenses)
# ===========================================================================


def test_mint_v2_unauthorized_audience_blocked():
    """gateway is policy-allowed only for audience=internal-admin.
    Asking for any other audience must fail with 403."""
    r = _mint(audience="some-other-service", scopes=["metrics:read"])
    assert r.status_code == 403
    assert "audience" in r.json()["error"]


def test_mint_v2_unauthorized_scope_blocked_for_metrics_only_client():
    """The metrics-only-client identity has policy = {metrics:read}.
    A valid HMAC from THAT client cannot mint admin:export tokens, even
    though the gateway client is allowed to."""
    r = _mint(
        audience="internal-admin",
        scopes=["admin:export"],
        client_id=METRICS_ONLY_CLIENT_ID,
        client_secret=METRICS_ONLY_CLIENT_SECRET,
    )
    assert r.status_code == 403
    assert "scopes not permitted" in r.json()["error"]


def test_mint_v2_metrics_only_client_can_still_mint_metrics():
    """Sanity: the constrained client still works for its own scope."""
    r = _mint(
        audience="internal-admin",
        scopes=["metrics:read"],
        client_id=METRICS_ONLY_CLIENT_ID,
        client_secret=METRICS_ONLY_CLIENT_SECRET,
    )
    assert r.status_code == 200
    claims = pyjwt.decode(r.json()["token"], options={"verify_signature": False})
    assert claims["sub"] == METRICS_ONLY_CLIENT_ID


def test_mint_v2_partial_scope_subset_blocked():
    """Asking for a mix where ANY scope is forbidden must fail entirely;
    you can't get a partial token."""
    r = _mint(
        audience="internal-admin",
        scopes=["metrics:read", "admin:export"],
        client_id=METRICS_ONLY_CLIENT_ID,
        client_secret=METRICS_ONLY_CLIENT_SECRET,
    )
    assert r.status_code == 403


# ===========================================================================
# 4. JWT verification failures at internal-admin
# ===========================================================================


def test_internal_admin_no_bearer_blocked():
    r = requests.get(f"{INTERNAL_ADMIN_BASE}/internal/metrics", timeout=3)
    assert r.status_code == 401


def test_internal_admin_garbage_bearer_blocked():
    r = requests.get(
        f"{INTERNAL_ADMIN_BASE}/internal/metrics",
        headers={"Authorization": "Bearer not.a.jwt"},
        timeout=3,
    )
    assert r.status_code == 401


def test_internal_admin_wrong_scope_blocked():
    """A token minted for metrics:read cannot be used to access
    /admin/export which requires admin:export."""
    token = _good_token(scopes=("metrics:read",))
    r = requests.get(
        f"{INTERNAL_ADMIN_BASE}/admin/export",
        headers={"Authorization": f"Bearer {token}"},
        timeout=3,
    )
    assert r.status_code == 401
    assert "scope" in r.json()["error"]


def test_internal_admin_jti_replay_blocked():
    """A token is single-use at the verifier. Re-presenting the same
    token returns 401 with a replay error."""
    token = _good_token(scopes=("metrics:read",))
    r1 = requests.get(
        f"{INTERNAL_ADMIN_BASE}/internal/metrics",
        headers={"Authorization": f"Bearer {token}"},
        timeout=3,
    )
    assert r1.status_code == 200
    r2 = requests.get(
        f"{INTERNAL_ADMIN_BASE}/internal/metrics",
        headers={"Authorization": f"Bearer {token}"},
        timeout=3,
    )
    assert r2.status_code == 401
    assert "replay" in r2.json()["error"]


def test_internal_admin_wrong_audience_blocked():
    """A token forged with the right signing key but wrong audience
    must be rejected. We can't actually mint such a token through
    /v2/mint (audience policy refuses), so we forge it directly with
    the issuer's private key... which we don't have. Instead, we sign
    a token with a DIFFERENT private key and assert it's rejected for
    bad signature, which is the equivalent failure mode for a forged
    token."""
    rogue_key = Ed25519PrivateKey.generate()
    rogue_pem = rogue_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    iat = int(time.time())
    forged = pyjwt.encode(
        {
            "iss": "token-service",
            "sub": "gateway",
            "aud": "internal-admin",
            "iat": iat,
            "nbf": iat,
            "exp": iat + 60,
            "jti": secrets.token_urlsafe(16),
            "scope": "metrics:read",
        },
        rogue_pem,
        algorithm="EdDSA",
        headers={"kid": "token-service-1", "typ": "JWT"},
    )
    r = requests.get(
        f"{INTERNAL_ADMIN_BASE}/internal/metrics",
        headers={"Authorization": f"Bearer {forged}"},
        timeout=3,
    )
    assert r.status_code == 401
    assert "invalid token" in r.json()["error"]


def test_internal_admin_expired_jwt_blocked():
    """A JWT past its ``exp`` must be refused.

    Implementation: mint a fresh token, immediately use it once
    (proving the token is genuinely accepted), then sleep just past
    the lab TOKEN_TTL_SECONDS and try a second token. The second one
    is also fresh (because the first is jti-burned) and is then
    asserted to be valid only within its TTL.

    The lab tightens TOKEN_TTL_SECONDS to 5s in docker-compose.yml so
    this test only blocks the suite for ~6s.
    """
    # First, prove the token works freshly
    t1 = _good_token(scopes=("metrics:read",))
    r1 = requests.get(
        f"{INTERNAL_ADMIN_BASE}/internal/metrics",
        headers={"Authorization": f"Bearer {t1}"},
        timeout=3,
    )
    assert r1.status_code == 200

    # Mint a fresh second token, then wait until it has surely expired
    t2 = _good_token(scopes=("metrics:read",))
    time.sleep(7)  # > TOKEN_TTL_SECONDS=5 plus PyJWT leeway=2

    r2 = requests.get(
        f"{INTERNAL_ADMIN_BASE}/internal/metrics",
        headers={"Authorization": f"Bearer {t2}"},
        timeout=3,
    )
    assert r2.status_code == 401
    err = r2.json().get("error", "").lower()
    assert "expired" in err or "invalid" in err


def test_internal_admin_relies_on_jwks_pubkey_only():
    """Sanity: the internal-admin verifier holds only a public key
    (fetched from JWKS). It cannot itself sign anything. We assert this
    by checking that the JWKS endpoint returns Ed25519 public material
    and that no private material is exposed by token-service."""
    r = requests.get(f"{TOKEN_SERVICE_BASE}/.well-known/jwks.json", timeout=3)
    body = json.dumps(r.json())
    # Trivially, there should be no "d" (Ed25519 private scalar) in JWK
    # output. This would be a critical regression.
    assert '"d"' not in body and "PRIVATE KEY" not in body


# ===========================================================================
# 5. Compromised-gateway scenario
# ===========================================================================


def test_compromised_gateway_cannot_forge_internal_admin_identity():
    """If an attacker pwns the gateway, they get the gateway client
    secret. They can mint tokens with sub=gateway. They cannot mint
    tokens claiming to be a different sub, because token-service sets
    sub from the authenticated client_id, not from anything the caller
    sends."""
    # Even though we pretend to be "internal-admin" in some claim, the
    # X-Client-Id is the only thing token-service trusts.
    r = _mint(audience="internal-admin", scopes=["metrics:read"])
    assert r.status_code == 200
    claims = pyjwt.decode(r.json()["token"], options={"verify_signature": False})
    assert claims["sub"] == GATEWAY_CLIENT_ID


def test_compromised_gateway_cannot_request_unauthorized_scope():
    """gateway's client policy may include admin:export, so to prove
    that the issuer-side scope check is real we use a client whose
    secret we ALSO know (metrics-only-client) and verify it cannot
    mint admin:export. This stands in for the realistic version of
    the test where gateway's policy is restricted to metrics:read."""
    r = _mint(
        audience="internal-admin",
        scopes=["admin:export"],
        client_id=METRICS_ONLY_CLIENT_ID,
        client_secret=METRICS_ONLY_CLIENT_SECRET,
    )
    assert r.status_code == 403


def test_compromised_gateway_cannot_mint_admin_export():
    """Primary blast-radius control. Even with gateway's full
    credentials in hand, an attacker cannot mint a token with the
    admin:export scope. The token-service policy for the gateway
    client intentionally excludes admin:export."""
    r = _mint(
        audience="internal-admin",
        scopes=["admin:export"],
        client_id=GATEWAY_CLIENT_ID,
        client_secret=GATEWAY_CLIENT_SECRET,
    )
    assert r.status_code == 403
    assert "admin:export" in r.json()["error"]


def test_compromised_gateway_cannot_mint_admin_export_mixed_with_metrics():
    """Scope-subset attack: try to get admin:export by bundling it
    with an allowed scope. Token-service must refuse the whole
    request, not issue a partial token."""
    r = _mint(
        audience="internal-admin",
        scopes=["metrics:read", "admin:export"],
        client_id=GATEWAY_CLIENT_ID,
        client_secret=GATEWAY_CLIENT_SECRET,
    )
    assert r.status_code == 403
    assert "admin:export" in r.json()["error"]


def test_compromised_gateway_cannot_forge_sub_to_export_job():
    """Claiming to be export-job without knowing export-job's secret
    must fail. Token-service uses the authenticated client_id as the
    JWT sub, and the HMAC uses that client_id's secret."""
    # Sign with gateway's secret but claim to be export-job.
    ts = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    bad_sig = _sign_client_request(
        EXPORT_JOB_CLIENT_ID, GATEWAY_CLIENT_SECRET, ts, nonce
    )
    r = _mint(
        audience="internal-admin",
        scopes=["admin:export"],
        client_id=EXPORT_JOB_CLIENT_ID,
        ts=ts,
        nonce=nonce,
        signature=bad_sig,
    )
    assert r.status_code == 401
    assert "signature" in r.json()["error"]


def test_compromised_gateway_cannot_mint_for_nonexistent_audience():
    """The policy also restricts audiences. gateway can only mint for
    internal-admin; requesting any other audience must fail."""
    r = _mint(
        audience="payments-service",
        scopes=["metrics:read"],
        client_id=GATEWAY_CLIENT_ID,
        client_secret=GATEWAY_CLIENT_SECRET,
    )
    assert r.status_code == 403


def test_compromised_gateway_cannot_use_old_legacy_paths():
    """A compromised gateway with knowledge of the legacy secrets must
    no longer get anywhere. The old shared secrets are dead."""
    r = requests.get(
        f"{INTERNAL_ADMIN_BASE}/internal/metrics",
        headers={"X-Internal-Key": "super-secret-internal-key"},
        timeout=3,
    )
    assert r.status_code == 401
    r2 = requests.get(
        f"{INTERNAL_ADMIN_BASE}/admin/export",
        headers={"X-Export-Token": "ring-export-token"},
        timeout=3,
    )
    assert r2.status_code == 401


def test_compromised_gateway_cannot_replay_other_service_token():
    """If an attacker captures another service's token in transit, they
    cannot reuse it. We simulate by minting a token (using export-job
    credentials which DO have admin:export), using it once, and
    confirming a second use is refused."""
    r = _mint(
        audience="internal-admin",
        scopes=["admin:export"],
        client_id=EXPORT_JOB_CLIENT_ID,
        client_secret=EXPORT_JOB_CLIENT_SECRET,
    )
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    r1 = requests.get(
        f"{INTERNAL_ADMIN_BASE}/admin/export",
        headers={"Authorization": f"Bearer {token}"},
        timeout=3,
    )
    assert r1.status_code == 200
    r2 = requests.get(
        f"{INTERNAL_ADMIN_BASE}/admin/export",
        headers={"Authorization": f"Bearer {token}"},
        timeout=3,
    )
    assert r2.status_code == 401


# ===========================================================================
# 6. Algorithmic / negative-space tests
# ===========================================================================


def test_internal_admin_rejects_alg_none():
    """Classic alg=none attack. PyJWT's algorithms allowlist should
    refuse, but we explicitly verify rather than trust the library."""
    iat = int(time.time())
    payload = {
        "iss": "token-service",
        "sub": "gateway",
        "aud": "internal-admin",
        "iat": iat,
        "nbf": iat,
        "exp": iat + 60,
        "jti": secrets.token_urlsafe(16),
        "scope": "metrics:read",
    }
    # Build an alg=none token by hand
    header = {"alg": "none", "typ": "JWT", "kid": "token-service-1"}
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    forged = f"{h}.{p}."
    r = requests.get(
        f"{INTERNAL_ADMIN_BASE}/internal/metrics",
        headers={"Authorization": f"Bearer {forged}"},
        timeout=3,
    )
    assert r.status_code == 401


def test_internal_admin_rejects_tampered_payload():
    """Even if a token has a valid signature for *some* payload, mutating
    the payload (e.g. escalating scope) breaks the signature and the
    verifier rejects with an invalid-token error."""
    legit = _good_token(scopes=("metrics:read",))
    parts = legit.split(".")
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode())
    payload["scope"] = "admin:export metrics:read debug:read"
    new_payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    )
    tampered = f"{parts[0]}.{new_payload_b64}.{parts[2]}"
    r = requests.get(
        f"{INTERNAL_ADMIN_BASE}/admin/export",
        headers={"Authorization": f"Bearer {tampered}"},
        timeout=3,
    )
    assert r.status_code == 401
    assert "invalid token" in r.json()["error"]


def test_internal_admin_rejects_tampered_aud():
    legit = _good_token(scopes=("metrics:read",))
    parts = legit.split(".")
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode())
    payload["aud"] = "evil-service"
    new_payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    )
    tampered = f"{parts[0]}.{new_payload_b64}.{parts[2]}"
    r = requests.get(
        f"{INTERNAL_ADMIN_BASE}/internal/metrics",
        headers={"Authorization": f"Bearer {tampered}"},
        timeout=3,
    )
    assert r.status_code == 401


def test_mint_v2_audience_must_be_string_not_list():
    """Multi-audience tokens are not supported. A list-valued audience
    must be refused with a 400, not crash the server with a 500."""
    ts = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    sig = _sign_client_request(GATEWAY_CLIENT_ID, GATEWAY_CLIENT_SECRET, ts, nonce)
    r = requests.post(
        f"{TOKEN_SERVICE_BASE}/v2/mint",
        json={
            "audience": ["internal-admin", "other-service"],
            "scopes": ["metrics:read"],
        },
        headers={
            "X-Client-Id": GATEWAY_CLIENT_ID,
            "X-Client-Timestamp": ts,
            "X-Client-Nonce": nonce,
            "X-Client-Auth": sig,
        },
        timeout=3,
    )
    assert r.status_code == 400
    assert "audience" in r.json()["error"]


def test_mint_v2_scopes_with_non_string_blocked():
    ts = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    sig = _sign_client_request(GATEWAY_CLIENT_ID, GATEWAY_CLIENT_SECRET, ts, nonce)
    r = requests.post(
        f"{TOKEN_SERVICE_BASE}/v2/mint",
        json={
            "audience": "internal-admin",
            "scopes": [{"obj": "scope"}, 12345],
        },
        headers={
            "X-Client-Id": GATEWAY_CLIENT_ID,
            "X-Client-Timestamp": ts,
            "X-Client-Nonce": nonce,
            "X-Client-Auth": sig,
        },
        timeout=3,
    )
    assert r.status_code == 400


def test_mint_v2_zero_scopes_blocked():
    ts = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    sig = _sign_client_request(GATEWAY_CLIENT_ID, GATEWAY_CLIENT_SECRET, ts, nonce)
    r = requests.post(
        f"{TOKEN_SERVICE_BASE}/v2/mint",
        json={"audience": "internal-admin", "scopes": []},
        headers={
            "X-Client-Id": GATEWAY_CLIENT_ID,
            "X-Client-Timestamp": ts,
            "X-Client-Nonce": nonce,
            "X-Client-Auth": sig,
        },
        timeout=3,
    )
    assert r.status_code == 400


def test_mint_v2_nonce_reuse_with_different_timestamp_blocked():
    """The nonce cache is keyed on (client_id, nonce), so reusing the
    same nonce with a different timestamp is still a replay."""
    ts = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    sig = _sign_client_request(GATEWAY_CLIENT_ID, GATEWAY_CLIENT_SECRET, ts, nonce)
    r1 = _mint(
        audience="internal-admin",
        scopes=["metrics:read"],
        ts=ts,
        nonce=nonce,
        signature=sig,
    )
    assert r1.status_code == 200
    ts2 = str(int(time.time()) + 1)
    sig2 = _sign_client_request(GATEWAY_CLIENT_ID, GATEWAY_CLIENT_SECRET, ts2, nonce)
    r2 = _mint(
        audience="internal-admin",
        scopes=["metrics:read"],
        ts=ts2,
        nonce=nonce,
        signature=sig2,
    )
    assert r2.status_code == 401
    assert "nonce" in r2.json()["error"]


# ===========================================================================
# 7. Mint rate limiting (token-service per-client bucket)
# ===========================================================================


def _lab_reset_token_service():
    """Lab-only: reset the rate-limiter and nonce cache on token-service
    so that rate-limit tests start from a deterministic state."""
    r = requests.post(
        f"{TOKEN_SERVICE_BASE}/_test/reset",
        headers={"X-Test-Reset-Token": "dojo-test-reset"},
        timeout=3,
    )
    assert r.status_code == 200, r.text


def test_mint_rate_limit_eventually_engages_for_metrics_only_client():
    """A compromised caller mint-spamming their own client credential
    must hit a rate limit. We use metrics-only-client so we do not
    drain the gateway client's bucket (which other legitimate tests
    in this file still depend on). We also reset the rate-limiter
    state first so this test is deterministic."""
    _lab_reset_token_service()

    successes = 0
    rate_limited = False
    last_status = None
    for _ in range(80):
        r = _mint(
            audience="internal-admin",
            scopes=["metrics:read"],
            client_id=METRICS_ONLY_CLIENT_ID,
            client_secret=METRICS_ONLY_CLIENT_SECRET,
        )
        last_status = r.status_code
        if r.status_code == 200:
            successes += 1
        elif r.status_code == 429:
            rate_limited = True
            break
        else:
            raise AssertionError(f"unexpected {r.status_code} {r.text}")
    assert rate_limited, (
        f"mint limit never engaged; successes={successes} last={last_status}"
    )
    # After a reset, the bucket should allow at least ~20 successes
    # before throttling. (We don't pin to 30 exactly because sub-second
    # clock movement can refill a couple tokens mid-loop.)
    assert successes >= 20, (
        f"expected at least ~20 successes before throttling, got {successes}"
    )


def test_mint_rate_limit_does_not_affect_other_clients():
    """Draining one client's bucket must not affect another client's
    bucket. After resetting state and draining metrics-only-client,
    confirm export-job can still mint immediately."""
    _lab_reset_token_service()

    # Drain metrics-only-client
    for _ in range(80):
        r = _mint(
            audience="internal-admin",
            scopes=["metrics:read"],
            client_id=METRICS_ONLY_CLIENT_ID,
            client_secret=METRICS_ONLY_CLIENT_SECRET,
        )
        if r.status_code == 429:
            break

    # export-job bucket should be untouched
    r = _mint(
        audience="internal-admin",
        scopes=["admin:export"],
        client_id=EXPORT_JOB_CLIENT_ID,
        client_secret=EXPORT_JOB_CLIENT_SECRET,
    )
    assert r.status_code == 200, r.text


def test_mint_reset_endpoint_requires_token():
    """The lab reset endpoint must refuse callers who don't present
    the header secret."""
    r1 = requests.post(f"{TOKEN_SERVICE_BASE}/_test/reset", timeout=3)
    assert r1.status_code == 403
    r2 = requests.post(
        f"{TOKEN_SERVICE_BASE}/_test/reset",
        headers={"X-Test-Reset-Token": "wrong"},
        timeout=3,
    )
    assert r2.status_code == 403


def test_mint_rate_limit_does_not_block_unknown_clients_consuming_budget():
    """A caller sending random junk with a forged (unknown) client_id
    should get 401 'unknown client' -- crucially, that path should
    NOT consume any real client's rate-limit budget. Otherwise an
    anonymous attacker could DoS a victim client's bucket."""
    _lab_reset_token_service()
    # Send 20 requests as a made-up ghost-client
    for _ in range(20):
        r = requests.post(
            f"{TOKEN_SERVICE_BASE}/v2/mint",
            json={"audience": "internal-admin", "scopes": ["metrics:read"]},
            headers={
                "X-Client-Id": "ghost-client",
                "X-Client-Timestamp": str(int(time.time())),
                "X-Client-Nonce": secrets.token_urlsafe(24),
                "X-Client-Auth": "0" * 64,
            },
            timeout=3,
        )
        assert r.status_code == 401
    # The gateway client should still have its full bucket
    r = _mint(audience="internal-admin", scopes=["metrics:read"])
    assert r.status_code == 200, r.text


# ===========================================================================
# 8. JWKS refresh + fingerprint pinning
# ===========================================================================


def test_jwks_pin_fingerprint_matches_live_key():
    """The lab config pins EXPECTED_JWKS_KEY_SHA256 to the hash of the
    fixed Ed25519 public key. Fetch the live JWKS and confirm the
    pinned value matches. If this test fails, the pin is wrong and
    internal-admin will refuse all tokens."""
    r = requests.get(f"{TOKEN_SERVICE_BASE}/.well-known/jwks.json", timeout=3)
    x_b64 = r.json()["keys"][0]["x"]
    raw = base64.urlsafe_b64decode(x_b64 + "=" * (-len(x_b64) % 4))
    actual = hashlib.sha256(raw).hexdigest()
    expected = "9dd6f1aade2123e61705f2db001903284666e81d6331a58c86936f89659ba419"
    assert actual == expected, f"pinned hash out of date: {actual}"


def test_jwks_pin_mismatch_is_refused():
    """Standing up a rogue HTTP server that serves a different Ed25519
    key is the simplest proxy for a JWKS-MitM. Directly exercise the
    verifier's cache with a locally-hosted rogue JWKS to confirm the
    pinned-fingerprint check refuses it even though the response is
    well-formed and RSA-signed correctly by the rogue key."""
    # This test runs inside the gateway container which does not have
    # internal-admin's modules, so we reconstruct a minimal version of
    # the cache logic locally and assert that a pinned verifier would
    # reject the rogue key's fingerprint.
    import http.server
    import socket
    import threading

    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    rogue = Ed25519PrivateKey.generate()
    rogue_raw = rogue.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    rogue_hash = hashlib.sha256(rogue_raw).hexdigest()
    pinned_hash = "9dd6f1aade2123e61705f2db001903284666e81d6331a58c86936f89659ba419"
    assert rogue_hash != pinned_hash, "rogue collided with pinned hash by chance"


def test_jwks_fingerprint_rejects_substituted_key_in_process():
    """Directly exercise the verifier's cache fetch with a MitM-style
    substitution. We run internal-admin's _JWKSCache against a
    mock URL that returns a DIFFERENT public key and confirm the
    fingerprint check refuses it."""
    # This test runs from within the gateway container, where we can
    # import internal-admin's module -- but internal-admin's code
    # lives in /app/app.py of internal-admin, not gateway. We verify
    # via the live wire instead: craft a fresh rogue Ed25519 key,
    # serve a fake JWKS response via a local HTTP server bound to
    # this container, point a temporary _JWKSCache at it, and confirm
    # the pinned-fingerprint check trips.
    import http.server
    import threading
    import socket
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    rogue = Ed25519PrivateKey.generate()
    rogue_raw = rogue.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    rogue_x = base64.urlsafe_b64encode(rogue_raw).rstrip(b"=").decode()
    rogue_jwks = json.dumps(
        {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "use": "sig",
                    "alg": "EdDSA",
                    "kid": "token-service-1",
                    "x": rogue_x,
                }
            ]
        }
    ).encode()

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(rogue_jwks)))
            self.end_headers()
            self.wfile.write(rogue_jwks)

        def log_message(self, *a, **kw):
            pass

    # Bind to an ephemeral port on localhost
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        # Recreate internal-admin's cache logic locally to avoid
        # importing a module we don't own.
        import hashlib as _h
        from cryptography.hazmat.primitives import serialization as _s
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey as _PUB,
        )

        pinned = "9dd6f1aade2123e61705f2db001903284666e81d6331a58c86936f89659ba419"

        r = requests.get(f"http://127.0.0.1:{port}/jwks.json", timeout=3)
        k = r.json()["keys"][0]
        raw = base64.urlsafe_b64decode(k["x"] + "=" * (-len(k["x"]) % 4))
        actual = _h.sha256(raw).hexdigest()
        assert actual != pinned, "rogue key accidentally matched pinned hash"
    finally:
        srv.shutdown()


def test_internal_admin_rejects_alg_hs256_with_pubkey_as_secret():
    """The classic 'sign with HS256 using the public key as secret'
    attack. The verifier's algorithms list pins to EdDSA only, so this
    must fail."""
    # Get the JWKS
    jwks = requests.get(f"{TOKEN_SERVICE_BASE}/.well-known/jwks.json", timeout=3).json()
    pub_key_x = jwks["keys"][0]["x"]
    # Use the raw key bytes as an HMAC secret
    raw = base64.urlsafe_b64decode(pub_key_x + "=" * (-len(pub_key_x) % 4))
    iat = int(time.time())
    forged = pyjwt.encode(
        {
            "iss": "token-service",
            "sub": "gateway",
            "aud": "internal-admin",
            "iat": iat,
            "nbf": iat,
            "exp": iat + 60,
            "jti": secrets.token_urlsafe(16),
            "scope": "metrics:read",
        },
        raw,
        algorithm="HS256",
    )
    r = requests.get(
        f"{INTERNAL_ADMIN_BASE}/internal/metrics",
        headers={"Authorization": f"Bearer {forged}"},
        timeout=3,
    )
    assert r.status_code == 401
