import os

from flask import Flask, jsonify, request

from shared.auth import AuthError, now_epoch, verify_signed_payload

app = Flask(__name__)

SERVICE_ID = os.getenv("SERVICE_ID", "internal-admin")
TOKEN_ISSUER = os.getenv("TOKEN_ISSUER", "token-service")
TOKEN_SIGNING_PUBLIC_KEY_PATH = os.getenv(
    "TOKEN_SIGNING_PUBLIC_KEY_PATH", "/keys/token-service-public.pem"
)
MAX_CLOCK_SKEW_SECONDS = 5
USED_ACCESS_TOKEN_JTIS = {}
ALLOWED_SUBJECTS_BY_SCOPE = {
    "admin.export.read": {"admin-exporter"},
    "debug.config.read": {"admin-observer"},
    "internal.metrics.read": {"admin-observer"},
}


def _prune_used_jtis(cache: dict):
    now = now_epoch()
    expired = [jti for jti, expires_at in cache.items() if expires_at <= now]
    for jti in expired:
        cache.pop(jti, None)


def _consume_access_token_jti(jti: str, expires_at: int):
    if not jti:
        raise AuthError("missing jti")

    _prune_used_jtis(USED_ACCESS_TOKEN_JTIS)
    if jti in USED_ACCESS_TOKEN_JTIS:
        raise AuthError("replayed token")

    USED_ACCESS_TOKEN_JTIS[jti] = expires_at


def _read_access_token() -> str:
    auth_header = request.headers.get("Authorization", "")
    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise AuthError("missing bearer token")
    return token.strip()


def _authorize(required_scope: str):
    payload = verify_signed_payload(_read_access_token(), TOKEN_SIGNING_PUBLIC_KEY_PATH)
    now = now_epoch()

    if payload.get("kind") != "access_token":
        raise AuthError("bad token kind")
    if payload.get("iss") != TOKEN_ISSUER:
        raise AuthError("bad issuer")
    if payload.get("aud") != SERVICE_ID:
        raise AuthError("bad audience")
    if payload.get("scope") != required_scope:
        raise AuthError("insufficient scope")

    subject = payload.get("sub", "")
    if subject not in ALLOWED_SUBJECTS_BY_SCOPE.get(required_scope, set()):
        raise AuthError("wrong subject")

    try:
        expires_at = int(payload.get("exp", 0))
        issued_at = int(payload.get("iat", 0))
    except (TypeError, ValueError) as exc:
        raise AuthError("bad timestamps") from exc

    if expires_at <= now:
        raise AuthError("expired token")
    if issued_at > now + MAX_CLOCK_SKEW_SECONDS:
        raise AuthError("token from the future")

    if payload.get("one_time") is True:
        _consume_access_token_jti(payload.get("jti", ""), expires_at)

    return payload


def _require_scope(required_scope: str):
    try:
        return _authorize(required_scope)
    except AuthError:
        return None


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "internal-admin"})


@app.get("/debug/config")
def debug_config():
    if _require_scope("debug.config.read") is None:
        return jsonify({"error": "forbidden"}), 403

    return jsonify(
        {
            "service": "internal-admin",
            "note": "debug requires observer bearer token",
            "env": os.getenv("APP_ENV", "dev"),
            "feature_flags": ["metrics", "asymmetric_service_tokens"],
        }
    )


@app.get("/internal/metrics")
def metrics():
    if _require_scope("internal.metrics.read") is None:
        return jsonify({"error": "forbidden"}), 403

    return jsonify(
        {
            "service": "internal-admin",
            "build": "v2.1.7",
            "token_provider": "token-service",
            "audience": SERVICE_ID,
            "legacy_mode": False,
            "status": "ok",
        }
    )


@app.get("/admin/export")
def admin_export():
    if _require_scope("admin.export.read") is None:
        return jsonify({"error": "forbidden"}), 403

    return jsonify(
        {
            "data": "sensitive export",
            "records": 2,
            "users": [
                {"id": 1, "email": "alice@example.internal"},
                {"id": 2, "email": "bob@example.internal"},
            ],
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
