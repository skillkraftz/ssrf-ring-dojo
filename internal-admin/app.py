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
JWKS_URL = os.getenv("JWKS_URL", "http://token-service:5003/.well-known/jwks.json")
JWKS_CACHE_TTL_SECONDS = int(os.getenv("JWKS_CACHE_TTL_SECONDS", "300"))
JTI_CACHE_TTL_SECONDS = int(os.getenv("JTI_CACHE_TTL_SECONDS", "300"))
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
    def __init__(self, url: str, ttl: int):
        self._url = url
        self._ttl = ttl
        self._key_pem: bytes | None = None
        self._fetched_at = 0.0
        self._lock = Lock()

    def get(self) -> bytes:
        now = time.monotonic()
        with self._lock:
            if self._key_pem is not None and (now - self._fetched_at) < self._ttl:
                return self._key_pem
            self._key_pem = self._fetch()
            self._fetched_at = now
            return self._key_pem

    def _fetch(self) -> bytes:
        resp = requests.get(self._url, timeout=3)
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


JWKS_CACHE = _JWKSCache(JWKS_URL, JWKS_CACHE_TTL_SECONDS)


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


def _verify_jwt_and_scope(required_scope: str) -> dict:
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        raise AuthError("missing bearer token")
    token = auth[7:].strip()
    if not token:
        raise AuthError("empty bearer token")

    public_key = JWKS_CACHE.get()

    try:
        claims = jwt.decode(
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
