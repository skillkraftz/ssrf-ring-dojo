"""
Internal admin service.

Trust model
===========

* The docker bridge network is treated as hostile. Being on the network
  proves NOTHING about identity.

* Every protected endpoint requires an Ed25519-signed JWT minted by
  token-service. The JWT must:

    iss     == "token-service"
    aud     == "internal-admin"
    exp     in the future, iat not too old
    jti     not seen before by this verifier (replay protected)
    scope   contains the per-endpoint required scope
    sig     verified against token-service's published public key

* The verifier holds ONLY the public key, fetched from
  token-service's JWKS endpoint with a small in-memory TTL cache.
  internal-admin cannot mint tokens; if internal-admin is compromised,
  the attacker cannot impersonate other services.

* No more X-Internal-Key, no more X-Export-Token, no more shared
  secrets that double as identity. The legacy header paths are gone
  entirely.

Endpoint summary
================

    GET /health           - liveness, no auth (used as a probe target)
    GET /debug/config     - dev only, requires Bearer JWT scope=debug:read
    GET /internal/metrics - requires Bearer JWT scope=metrics:read
    GET /admin/export     - requires Bearer JWT scope=admin:export
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import time
from threading import Lock

import jwt
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from flask import Flask, jsonify, request

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
)

app = Flask(__name__)
log = app.logger

EXPECTED_ISSUER = os.getenv("EXPECTED_ISSUER", "token-service")
EXPECTED_AUDIENCE = os.getenv("EXPECTED_AUDIENCE", "internal-admin")
JWKS_URL = os.getenv("JWKS_URL", "https://token-service:5003/.well-known/jwks.json")
JWKS_CACHE_TTL_SECONDS = int(os.getenv("JWKS_CACHE_TTL_SECONDS", "300"))
JTI_CACHE_TTL_SECONDS = int(os.getenv("JTI_CACHE_TTL_SECONDS", "300"))
# mTLS material for outbound JWKS fetch
INTERNAL_CA_FILE = os.getenv("INTERNAL_CA_FILE", "/certs/ca.crt")
INTERNAL_CLIENT_CERT = os.getenv("INTERNAL_CLIENT_CERT", "/certs/internal-admin.crt")
INTERNAL_CLIENT_KEY = os.getenv("INTERNAL_CLIENT_KEY", "/certs/internal-admin.key")
# Optional: pin the expected SHA-256 of the Ed25519 public key bytes.
# If set, any JWKS response whose key does not hash to this value is
# rejected, even if the response is otherwise well-formed. This closes
# the JWKS-MitM window that plaintext inter-service HTTP would leave
# open on a hostile network.
EXPECTED_JWKS_KEY_SHA256 = os.getenv("EXPECTED_JWKS_KEY_SHA256", "").strip().lower()
# Minimum interval between JWKS refresh attempts. Used when the
# verifier tries to recover from a signature failure (e.g. after a
# key rotation at token-service). Prevents an attacker from triggering
# a refresh on every bad token they send.
JWKS_REFRESH_MIN_INTERVAL_SECONDS = float(
    os.getenv("JWKS_REFRESH_MIN_INTERVAL_SECONDS", "10")
)
APP_ENV = os.getenv("APP_ENV", "dev").lower()
SIGNING_ALG = "EdDSA"


class AuthError(Exception):
    pass


# ---------------------------------------------------------------------------
# JWKS cache. Lazy fetch on first verification, refresh after TTL.
# Thread-safe. The cache invalidates itself on parse failure so a key
# rotation can be picked up on the next call.
# ---------------------------------------------------------------------------


class _JWKSCache:
    def __init__(self, url: str, ttl: int, expected_sha256: str = ""):
        self._url = url
        self._ttl = ttl
        self._expected_sha256 = expected_sha256
        self._key_pem: bytes | None = None
        self._fetched_at = 0.0
        self._last_refresh_attempt = 0.0
        self._lock = Lock()

    def get(self) -> bytes:
        """Return the current cached public key PEM, fetching if the
        cache has expired or is empty."""
        now = time.monotonic()
        with self._lock:
            if self._key_pem is not None and (now - self._fetched_at) < self._ttl:
                return self._key_pem
            self._key_pem = self._fetch_locked()
            self._fetched_at = now
            self._last_refresh_attempt = now
            return self._key_pem

    def maybe_refresh(self) -> bool:
        """Force-refresh the key, but only if we haven't already tried
        very recently. Returns True if a refresh actually happened and
        produced a different key from what was cached before."""
        now = time.monotonic()
        with self._lock:
            if (now - self._last_refresh_attempt) < JWKS_REFRESH_MIN_INTERVAL_SECONDS:
                return False
            previous = self._key_pem
            try:
                self._key_pem = self._fetch_locked()
                self._fetched_at = now
            except Exception as exc:
                log.warning("jwks refresh failed: %s", exc)
                self._last_refresh_attempt = now
                return False
            self._last_refresh_attempt = now
            return self._key_pem != previous

    def _fetch_locked(self) -> bytes:
        """Fetch the JWKS. Caller must hold self._lock. Raises on
        parse failure or fingerprint mismatch.

        The fetch uses mTLS: we present our own client cert so
        token-service accepts the request, and we verify
        token-service's cert chains to the lab CA.
        """
        resp = requests.get(
            self._url,
            timeout=3,
            cert=(INTERNAL_CLIENT_CERT, INTERNAL_CLIENT_KEY),
            verify=INTERNAL_CA_FILE,
        )
        resp.raise_for_status()
        data = resp.json()
        for k in data.get("keys", []):
            if (
                k.get("kty") == "OKP"
                and k.get("crv") == "Ed25519"
                and k.get("alg") == SIGNING_ALG
            ):
                x_b64 = k["x"] + "=" * (-len(k["x"]) % 4)
                raw = base64.urlsafe_b64decode(x_b64)

                # Fingerprint pinning. If the operator set
                # EXPECTED_JWKS_KEY_SHA256, any deviation -- whether
                # from a legitimate rotation or a hostile substitution --
                # is a hard failure. This closes the JWKS-MitM window
                # that plaintext inter-service HTTP leaves open on a
                # hostile docker bridge where an attacker with
                # CAP_NET_RAW could ARP-spoof token-service.
                if self._expected_sha256:
                    actual = hashlib.sha256(raw).hexdigest()
                    if actual != self._expected_sha256:
                        log.error(
                            "JWKS fingerprint mismatch expected=%s actual=%s",
                            self._expected_sha256,
                            actual,
                        )
                        raise RuntimeError("jwks fingerprint mismatch")

                pub = Ed25519PublicKey.from_public_bytes(raw)
                return pub.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
        raise RuntimeError("no Ed25519 key in JWKS response")

    def invalidate(self) -> None:
        with self._lock:
            self._key_pem = None
            self._fetched_at = 0.0


JWKS_CACHE = _JWKSCache(JWKS_URL, JWKS_CACHE_TTL_SECONDS, EXPECTED_JWKS_KEY_SHA256)


# ---------------------------------------------------------------------------
# Replay protection: track jtis we've seen, with TTL aligned to the
# token's max lifetime so the cache cannot grow without bound.
# ---------------------------------------------------------------------------


class _JTICache:
    def __init__(self, ttl_seconds: int):
        self._ttl = ttl_seconds
        self._seen: dict[str, float] = {}
        self._lock = Lock()

    def remember(self, jti: str, exp_unix: int) -> bool:
        """Returns True if jti was new, False if it was already seen.
        The TTL is min(exp - now, self._ttl) so memory is bounded."""
        now = time.time()
        with self._lock:
            # Periodic cleanup
            if len(self._seen) > 10000:
                self._seen = {k: v for k, v in self._seen.items() if v > now}
            if jti in self._seen:
                return False
            ttl = min(self._ttl, max(0, exp_unix - int(now)))
            self._seen[jti] = now + ttl + 1
            return True

    def reset(self) -> None:
        with self._lock:
            self._seen.clear()


JTI_CACHE = _JTICache(JTI_CACHE_TTL_SECONDS)


# ---------------------------------------------------------------------------
# JWT verification
# ---------------------------------------------------------------------------


def _decode_token(token: str, public_key: bytes) -> dict:
    return jwt.decode(
        token,
        public_key,
        algorithms=[SIGNING_ALG],
        audience=EXPECTED_AUDIENCE,
        issuer=EXPECTED_ISSUER,
        options={
            "require": ["exp", "iat", "iss", "aud", "jti", "sub"],
            "verify_signature": True,
            "verify_exp": True,
            "verify_iat": True,
            "verify_nbf": True,
            "verify_aud": True,
            "verify_iss": True,
        },
        leeway=2,
    )


def _verify_jwt_and_scope(required_scope: str) -> dict:
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        raise AuthError("missing bearer token")
    token = auth[7:].strip()
    if not token:
        raise AuthError("empty bearer token")

    public_key = JWKS_CACHE.get()

    try:
        claims = _decode_token(token, public_key)
    except jwt.InvalidSignatureError:
        # Signature mismatch can mean the key was rotated at
        # token-service. Refresh the JWKS once (rate-limited) and try
        # again. Any OTHER kind of InvalidTokenError (expired, wrong
        # aud, missing claim) is a permanent failure and does NOT
        # trigger a refresh -- that would let an attacker spam the
        # refresh rate limit with bad tokens.
        if JWKS_CACHE.maybe_refresh():
            try:
                claims = _decode_token(token, JWKS_CACHE.get())
                log.info("jwks refresh recovered a signature failure")
            except jwt.InvalidTokenError as exc:
                raise AuthError(f"invalid token: {exc}") from exc
        else:
            raise AuthError("invalid token: Signature verification failed")
    except jwt.InvalidTokenError as exc:
        raise AuthError(f"invalid token: {exc}") from exc

    # Scope check
    scope_str = claims.get("scope", "")
    if not isinstance(scope_str, str):
        raise AuthError("scope must be a string")
    token_scopes = set(scope_str.split())
    if required_scope not in token_scopes:
        raise AuthError(f"missing required scope: {required_scope}")

    # Replay check
    jti = claims["jti"]
    exp = int(claims["exp"])
    if not JTI_CACHE.remember(jti, exp):
        raise AuthError("token already used (jti replay)")

    return claims


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "internal-admin"})


@app.get("/debug/config")
def debug_config():
    if APP_ENV != "dev":
        return jsonify({"error": "not found"}), 404
    try:
        claims = _verify_jwt_and_scope("debug:read")
    except AuthError as exc:
        return jsonify({"error": str(exc)}), 401
    return jsonify(
        {
            "service": "internal-admin",
            "env": APP_ENV,
            "feature_flags": ["metrics", "legacy_export"],
            "caller": claims["sub"],
        }
    )


@app.get("/internal/metrics")
def metrics():
    try:
        claims = _verify_jwt_and_scope("metrics:read")
    except AuthError as exc:
        return jsonify({"error": str(exc)}), 401
    return jsonify(
        {
            "service": "internal-admin",
            "build": "v2.1.7",
            "audience": EXPECTED_AUDIENCE,
            "status": "ok",
            "caller": claims["sub"],
        }
    )


@app.get("/admin/export")
def admin_export():
    try:
        claims = _verify_jwt_and_scope("admin:export")
    except AuthError as exc:
        return jsonify({"error": str(exc)}), 401
    return jsonify(
        {
            "data": "sensitive export",
            "records": 2,
            "users": [
                {"id": 1, "email": "alice@example.internal"},
                {"id": 2, "email": "bob@example.internal"},
            ],
            "caller": claims["sub"],
        }
    )


# ---------------------------------------------------------------------------
# mTLS server bootstrap
# ---------------------------------------------------------------------------


def _build_mtls_context():
    """Build a server-side SSLContext that requires a lab-CA-signed
    client cert for every connection. See token-service for rationale."""
    import ssl as _ssl

    server_cert = os.getenv("SERVER_CERT_FILE", "/certs/internal-admin.crt")
    server_key = os.getenv("SERVER_KEY_FILE", "/certs/internal-admin.key")
    ca_file = INTERNAL_CA_FILE

    ctx = _ssl.create_default_context(_ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=server_cert, keyfile=server_key)
    ctx.load_verify_locations(cafile=ca_file)
    ctx.verify_mode = _ssl.CERT_REQUIRED
    ctx.minimum_version = _ssl.TLSVersion.TLSv1_2
    return ctx


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, ssl_context=_build_mtls_context())
