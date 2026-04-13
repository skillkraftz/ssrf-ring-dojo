import os

from flask import Flask, jsonify, request

from shared.auth import AuthError, now_epoch, verify_signed_payload
from shared.mtls import build_server_ssl_context, serve_http_and_mtls

app = Flask(__name__)

SERVICE_ID = os.getenv("SERVICE_ID", "internal-admin")
TOKEN_ISSUER = os.getenv("TOKEN_ISSUER", "token-service")
HTTP_PORT = int(os.getenv("HTTP_PORT", "5001"))
HTTPS_PORT = int(os.getenv("HTTPS_PORT", "5443"))
TOKEN_SIGNING_PUBLIC_KEY_PATH = os.getenv(
    "TOKEN_SIGNING_PUBLIC_KEY_PATH", "/keys/token-service-public.pem"
)
TLS_SERVER_CERT_PATH = os.getenv(
    "TLS_SERVER_CERT_PATH", "/tls/internal-admin-server-cert.pem"
)
TLS_SERVER_KEY_PATH = os.getenv(
    "TLS_SERVER_KEY_PATH", "/tls/internal-admin-server-key.pem"
)
TLS_CA_CERT_PATH = os.getenv("TLS_CA_CERT_PATH", "/tls/ca-cert.pem")
PROOF_TTL_SECONDS = int(os.getenv("PROOF_TTL_SECONDS", "15"))
MAX_CLOCK_SKEW_SECONDS = 5
USED_ACCESS_TOKEN_JTIS = {}
USED_PROOF_JTIS = {}
ALLOWED_SUBJECTS_BY_SCOPE = {
    "admin.export.read": {"admin-exporter"},
    "debug.config.read": {"admin-observer"},
    "internal.metrics.read": {"admin-observer"},
}
SUBJECT_PUBLIC_KEY_PATHS = {
    "admin-exporter": os.getenv(
        "ADMIN_EXPORTER_PUBLIC_KEY_PATH", "/keys/admin-exporter-public.pem"
    ),
    "admin-observer": os.getenv(
        "ADMIN_OBSERVER_PUBLIC_KEY_PATH", "/keys/admin-observer-public.pem"
    ),
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


def _consume_proof_jti(jti: str, expires_at: int):
    if not jti:
        raise AuthError("missing proof jti")

    _prune_used_jtis(USED_PROOF_JTIS)
    if jti in USED_PROOF_JTIS:
        raise AuthError("replayed proof")

    USED_PROOF_JTIS[jti] = expires_at


def _read_access_token() -> str:
    auth_header = request.headers.get("Authorization", "")
    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise AuthError("missing bearer token")
    return token.strip()


def _read_service_proof() -> str:
    proof = request.headers.get("X-Service-Proof", "").strip()
    if not proof:
        raise AuthError("missing service proof")
    return proof


def _require_mtls_subject(expected_subject: str):
    if not request.environ.get("mtls.client_verified"):
        raise AuthError("mTLS required")

    client_subject = request.environ.get("mtls.client_common_name", "")
    if client_subject != expected_subject:
        raise AuthError("client subject mismatch")


def _validate_service_proof(subject: str, token_jti: str):
    verification_key = SUBJECT_PUBLIC_KEY_PATHS.get(subject)
    if not verification_key:
        raise AuthError("unknown subject")

    payload = verify_signed_payload(_read_service_proof(), verification_key)
    now = now_epoch()

    if payload.get("kind") != "service_proof":
        raise AuthError("bad proof kind")
    if payload.get("iss") != subject or payload.get("sub") != subject:
        raise AuthError("bad proof issuer")
    if payload.get("aud") != SERVICE_ID:
        raise AuthError("bad proof audience")
    if payload.get("method") != request.method:
        raise AuthError("bad proof method")
    if payload.get("path") != request.path:
        raise AuthError("bad proof path")
    if payload.get("token_jti") != token_jti:
        raise AuthError("bad proof binding")

    try:
        expires_at = int(payload.get("exp", 0))
        issued_at = int(payload.get("iat", 0))
    except (TypeError, ValueError) as exc:
        raise AuthError("bad proof timestamps") from exc

    if expires_at <= now:
        raise AuthError("expired proof")
    if expires_at - issued_at > PROOF_TTL_SECONDS + MAX_CLOCK_SKEW_SECONDS:
        raise AuthError("proof ttl too long")
    if issued_at > now + MAX_CLOCK_SKEW_SECONDS:
        raise AuthError("proof from the future")

    _consume_proof_jti(payload.get("jti", ""), expires_at)
    return payload


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

    _require_mtls_subject(subject)
    _validate_service_proof(subject, payload.get("jti", ""))

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
    ssl_context = build_server_ssl_context(
        TLS_SERVER_CERT_PATH,
        TLS_SERVER_KEY_PATH,
        TLS_CA_CERT_PATH,
    )
    serve_http_and_mtls(app, HTTP_PORT, HTTPS_PORT, ssl_context)
