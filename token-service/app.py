"""
Token service.

Issues short-lived Ed25519-signed JWTs scoped to a target audience and
to a small set of permitted scopes. Authenticates each minting client
by HMAC over a fresh nonce + timestamp using a per-client secret.

Security model
==============

* Each calling service has its OWN client_id + client_secret pair,
  distinct from every other service. Compromise of one service
  therefore reveals only one identity, not the entire mesh.

* Mint requests must include a recent timestamp (within
  TIMESTAMP_SKEW_SECONDS of "now") and a fresh nonce. The nonce is
  rejected if seen before within the sliding window, defeating naive
  capture-and-replay of an Authorization line.

* The HMAC commits the caller to its claimed identity, the timestamp,
  and the nonce. There is nothing to forge unless the secret leaks.

* Issued JWTs:
    iss = "token-service"
    sub = client_id of the caller
    aud = the requested audience (must be in client's allow-list)
    iat / exp (default 60 second TTL)
    jti = random nonce, used by verifiers for replay protection
    scope = space-separated list (must be subset of client's allow-list)

* Tokens are signed with Ed25519. Verifiers hold ONLY the public key,
  fetched via /.well-known/jwks.json. Token-service is the only party
  in the mesh that holds material capable of forging a token.

The legacy /mint endpoint (which trusted any caller claiming
service=internal-admin) has been removed entirely. /v2/mint is the
only minting endpoint.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from threading import Lock

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from flask import Flask, jsonify, request

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
)

app = Flask(__name__)
log = app.logger

ISSUER = "token-service"
SIGNING_ALG = "EdDSA"
KEY_ID = "token-service-1"
TOKEN_TTL_SECONDS = int(os.getenv("TOKEN_TTL_SECONDS", "60"))
TIMESTAMP_SKEW_SECONDS = int(os.getenv("TIMESTAMP_SKEW_SECONDS", "30"))


# ---------------------------------------------------------------------------
# Per-client policy
#
# In production this would be loaded from a policy store. For the lab the
# defaults are baked in and can be overridden by the TOKEN_CLIENTS_JSON
# env var. Each client has:
#
#   secret              - per-client HMAC secret used to authenticate /v2/mint
#   allowed_audiences   - which JWT audiences this client may mint for
#   allowed_scopes      - which scopes this client may include in its tokens
#
# A client whose secret leaks can do EXACTLY what its policy entry allows
# and nothing more. Audience and scope cannot be escalated by the caller.
# ---------------------------------------------------------------------------


def _load_clients() -> dict:
    raw = os.getenv("TOKEN_CLIENTS_JSON", "")
    if raw:
        try:
            data = json.loads(raw)
        except Exception as exc:
            log.error("failed to parse TOKEN_CLIENTS_JSON: %s", exc)
            data = {}
    else:
        data = {}

    if not data:
        # Lab defaults. NEVER reuse these in production.
        data = {
            "gateway": {
                "secret": "gateway-client-secret-do-not-reuse",
                "allowed_audiences": ["internal-admin"],
                "allowed_scopes": ["metrics:read", "admin:export", "debug:read"],
            },
            "metrics-only-client": {
                # Demonstrates per-client scope restriction. Has valid
                # credentials but is policy-limited to metrics:read.
                "secret": "metrics-only-secret-do-not-reuse",
                "allowed_audiences": ["internal-admin"],
                "allowed_scopes": ["metrics:read"],
            },
        }

    return {
        cid: {
            "secret": entry["secret"],
            "allowed_audiences": set(entry.get("allowed_audiences", [])),
            "allowed_scopes": set(entry.get("allowed_scopes", [])),
        }
        for cid, entry in data.items()
    }


CLIENTS = _load_clients()


# ---------------------------------------------------------------------------
# Signing key (Ed25519). Loaded from env if provided, otherwise an
# ephemeral key is generated at startup. The public key is published
# via /.well-known/jwks.json.
# ---------------------------------------------------------------------------


def _load_private_key() -> Ed25519PrivateKey:
    raw = os.getenv("TOKEN_SIGNING_PRIVATE_KEY_PEM", "")
    if raw:
        key = serialization.load_pem_private_key(raw.encode(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise RuntimeError("TOKEN_SIGNING_PRIVATE_KEY_PEM is not Ed25519")
        log.info("loaded Ed25519 signing key from env")
        return key
    key = Ed25519PrivateKey.generate()
    log.warning("no TOKEN_SIGNING_PRIVATE_KEY_PEM in env; generated ephemeral keypair")
    return key


PRIVATE_KEY = _load_private_key()
PUBLIC_KEY = PRIVATE_KEY.public_key()
PRIVATE_KEY_PEM = PRIVATE_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode()


# ---------------------------------------------------------------------------
# Sliding nonce cache for client-credential replay protection.
# ---------------------------------------------------------------------------


class _NonceCache:
    def __init__(self, ttl_seconds: int):
        self._ttl = ttl_seconds
        self._seen: dict[str, float] = {}
        self._lock = Lock()

    def remember(self, key: str) -> bool:
        """Returns True if the nonce was new (and is now remembered),
        False if it was already seen within the TTL window."""
        now = time.monotonic()
        with self._lock:
            if len(self._seen) > 10000:
                self._seen = {k: v for k, v in self._seen.items() if v > now}
            if key in self._seen:
                return False
            self._seen[key] = now + self._ttl
            return True

    def reset(self) -> None:
        with self._lock:
            self._seen.clear()


# Window must comfortably exceed the timestamp skew so an attacker can't
# replay a (timestamp, nonce) pair just outside the cache window but
# inside the timestamp window.
NONCE_CACHE = _NonceCache(TIMESTAMP_SKEW_SECONDS * 4)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "token-service"})


@app.get("/.well-known/jwks.json")
def jwks():
    """Public-key discovery. Anyone may fetch."""
    raw = PUBLIC_KEY.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return jsonify(
        {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "use": "sig",
                    "alg": SIGNING_ALG,
                    "kid": KEY_ID,
                    "x": x,
                }
            ]
        }
    )


def _verify_client_signature(
    client_id: str, secret: str, ts: str, nonce: str, signature: str
) -> bool:
    """Constant-time HMAC verification of a client request."""
    msg = f"{client_id}|{ts}|{nonce}".encode()
    expected = hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


@app.post("/v2/mint")
def mint_v2():
    # 1. Extract client-credential headers
    client_id = request.headers.get("X-Client-Id", "")
    ts_str = request.headers.get("X-Client-Timestamp", "")
    nonce = request.headers.get("X-Client-Nonce", "")
    signature = request.headers.get("X-Client-Auth", "")

    if not client_id or not ts_str or not nonce or not signature:
        return jsonify({"error": "missing client auth headers"}), 401

    # 2. Validate timestamp window before doing any expensive work
    try:
        ts = int(ts_str)
    except ValueError:
        return jsonify({"error": "invalid timestamp"}), 401
    now = int(time.time())
    if abs(now - ts) > TIMESTAMP_SKEW_SECONDS:
        return jsonify({"error": "stale timestamp"}), 401

    # 3. Nonce sanity (length only; uniqueness is checked after the
    # signature so an attacker can't pollute the nonce cache without
    # knowing the secret)
    if not (16 <= len(nonce) <= 128):
        return jsonify({"error": "invalid nonce"}), 401

    # 4. Look up the client and verify the HMAC. Use compare_digest in
    # both lookup and signature compare to keep timing flat.
    if client_id not in CLIENTS:
        # Even for unknown clients we run a dummy compare to keep
        # timing similar.
        _verify_client_signature(client_id, "x" * 32, ts_str, nonce, signature)
        log.warning("mint denied: unknown client client_id=%s", client_id)
        return jsonify({"error": "unknown client"}), 401

    client = CLIENTS[client_id]
    if not _verify_client_signature(
        client_id, client["secret"], ts_str, nonce, signature
    ):
        log.warning("mint denied: bad signature client_id=%s", client_id)
        return jsonify({"error": "bad signature"}), 401

    # 5. Only NOW do we burn a nonce. This means an attacker without
    # the secret cannot grief by exhausting the nonce cache.
    if not NONCE_CACHE.remember(f"{client_id}:{nonce}"):
        log.warning("mint denied: replayed nonce client_id=%s", client_id)
        return jsonify({"error": "nonce already used"}), 401

    # 6. Validate the request body
    body = request.get_json(silent=True) or {}
    audience = body.get("audience", "")
    scopes = body.get("scopes", [])
    if isinstance(scopes, str):
        scopes = [scopes]
    if not isinstance(scopes, list) or not all(isinstance(s, str) for s in scopes):
        return jsonify({"error": "scopes must be a list of strings"}), 400

    if not isinstance(audience, str):
        # We deliberately refuse list-valued audiences. A multi-aud
        # token would let a single capture be replayed against multiple
        # services, which we want to avoid.
        return jsonify({"error": "audience must be a single string"}), 400
    if not audience:
        return jsonify({"error": "missing audience"}), 400
    if audience not in client["allowed_audiences"]:
        log.warning(
            "mint denied: audience not permitted client_id=%s aud=%s",
            client_id,
            audience,
        )
        return jsonify({"error": "audience not permitted for this client"}), 403

    if not scopes:
        return jsonify({"error": "missing scopes"}), 400
    forbidden = set(scopes) - client["allowed_scopes"]
    if forbidden:
        log.warning(
            "mint denied: scopes not permitted client_id=%s forbidden=%s",
            client_id,
            sorted(forbidden),
        )
        return jsonify({"error": f"scopes not permitted: {sorted(forbidden)}"}), 403

    # 7. Issue the JWT
    iat = int(time.time())
    exp = iat + TOKEN_TTL_SECONDS
    jti = secrets.token_urlsafe(16)
    claims = {
        "iss": ISSUER,
        "sub": client_id,
        "aud": audience,
        "iat": iat,
        "nbf": iat,
        "exp": exp,
        "jti": jti,
        "scope": " ".join(sorted(set(scopes))),
    }
    token = jwt.encode(
        claims,
        PRIVATE_KEY_PEM,
        algorithm=SIGNING_ALG,
        headers={"kid": KEY_ID, "typ": "JWT"},
    )
    log.info(
        "minted token client_id=%s aud=%s scope=%s jti=%s",
        client_id,
        audience,
        claims["scope"],
        jti,
    )
    return jsonify(
        {
            "token": token,
            "token_type": "Bearer",
            "expires_in": TOKEN_TTL_SECONDS,
            "audience": audience,
            "scope": claims["scope"],
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003)
