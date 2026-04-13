import os

from flask import Flask, jsonify, request

from shared.auth import (
    AuthError,
    issue_signed_payload,
    new_jti,
    normalize_scope,
    now_epoch,
    peek_signed_payload,
    verify_signed_payload,
)
from shared.mtls import build_server_ssl_context, serve_http_and_mtls

app = Flask(__name__)

TOKEN_ISSUER = os.getenv("TOKEN_ISSUER", "token-service")
HTTP_PORT = int(os.getenv("HTTP_PORT", "5003"))
HTTPS_PORT = int(os.getenv("HTTPS_PORT", "5443"))
TOKEN_SIGNING_PRIVATE_KEY_PATH = os.getenv(
    "TOKEN_SIGNING_PRIVATE_KEY_PATH", "/keys/token-service-private.pem"
)
TLS_SERVER_CERT_PATH = os.getenv(
    "TLS_SERVER_CERT_PATH", "/tls/token-service-server-cert.pem"
)
TLS_SERVER_KEY_PATH = os.getenv(
    "TLS_SERVER_KEY_PATH", "/tls/token-service-server-key.pem"
)
TLS_CA_CERT_PATH = os.getenv("TLS_CA_CERT_PATH", "/tls/ca-cert.pem")
ACCESS_TOKEN_TTL_SECONDS = int(os.getenv("ACCESS_TOKEN_TTL_SECONDS", "60"))
MAX_CLOCK_SKEW_SECONDS = 5
USED_ASSERTION_JTIS = {}

SERVICE_POLICIES = {
    "admin-exporter": {
        "public_key_path": os.getenv(
            "ADMIN_EXPORTER_PUBLIC_KEY_PATH", "/keys/admin-exporter-public.pem"
        ),
        "permissions": {("internal-admin", "admin.export.read")},
    },
    "admin-observer": {
        "public_key_path": os.getenv(
            "ADMIN_OBSERVER_PUBLIC_KEY_PATH", "/keys/admin-observer-public.pem"
        ),
        "permissions": {
            ("internal-admin", "debug.config.read"),
            ("internal-admin", "internal.metrics.read"),
            (TOKEN_ISSUER, "token.discovery"),
        },
    },
}


def _prune_used_jtis(cache: dict):
    now = now_epoch()
    expired = [jti for jti, expires_at in cache.items() if expires_at <= now]
    for jti in expired:
        cache.pop(jti, None)


def _consume_assertion_jti(jti: str, expires_at: int):
    if not jti:
        raise AuthError("missing jti")

    _prune_used_jtis(USED_ASSERTION_JTIS)
    if jti in USED_ASSERTION_JTIS:
        raise AuthError("replayed assertion")

    USED_ASSERTION_JTIS[jti] = expires_at


def _load_policy(service_id: str):
    policy = SERVICE_POLICIES.get(service_id)
    if policy is None:
        raise AuthError("unknown service")
    return policy


def _forbidden():
    return jsonify({"error": "forbidden"}), 403


def _bad_request(message: str):
    return jsonify({"error": message}), 400


def _require_mtls_subject(expected_subject: str):
    if not request.environ.get("mtls.client_verified"):
        raise AuthError("mTLS required")

    client_subject = request.environ.get("mtls.client_common_name", "")
    if client_subject != expected_subject:
        raise AuthError("client subject mismatch")


def _verify_service_assertion(
    assertion: str, requested_audience: str, requested_scope: str
):
    if not assertion:
        raise AuthError("missing service assertion")

    preview = peek_signed_payload(assertion)
    service_id = preview.get("sub", "")
    policy = _load_policy(service_id)
    _require_mtls_subject(service_id)
    payload = verify_signed_payload(assertion, policy["public_key_path"])

    now = now_epoch()
    if payload.get("kind") != "service_assertion":
        raise AuthError("bad token kind")
    if payload.get("iss") != service_id or payload.get("sub") != service_id:
        raise AuthError("bad issuer")
    if payload.get("aud") != TOKEN_ISSUER:
        raise AuthError("bad audience")
    if payload.get("request_aud") != requested_audience:
        raise AuthError("audience mismatch")
    if payload.get("request_scope") != requested_scope:
        raise AuthError("scope mismatch")
    if (requested_audience, requested_scope) not in policy["permissions"]:
        raise AuthError("permission not allowed")

    try:
        expires_at = int(payload.get("exp", 0))
        issued_at = int(payload.get("iat", 0))
    except (TypeError, ValueError) as exc:
        raise AuthError("bad timestamps") from exc

    if expires_at <= now:
        raise AuthError("expired assertion")
    if issued_at > now + MAX_CLOCK_SKEW_SECONDS:
        raise AuthError("assertion from the future")

    _consume_assertion_jti(payload.get("jti", ""), expires_at)
    return payload, policy


def _issue_access_token(service_id: str, audience: str, scope: str) -> str:
    now = now_epoch()
    return issue_signed_payload(
        {
            "kind": "access_token",
            "iss": TOKEN_ISSUER,
            "sub": service_id,
            "aud": audience,
            "scope": scope,
            "iat": now,
            "exp": now + ACCESS_TOKEN_TTL_SECONDS,
            "jti": new_jti(),
            "one_time": True,
        },
        TOKEN_SIGNING_PRIVATE_KEY_PATH,
    )


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "token-service"})


@app.get("/.well-known/mesh")
def mesh():
    assertion = request.headers.get("X-Service-Assertion", "").strip()
    try:
        _verify_service_assertion(assertion, TOKEN_ISSUER, "token.discovery")
    except AuthError:
        return _forbidden()

    return jsonify(
        {
            "service": "token-service",
            "issuer": TOKEN_ISSUER,
            "mode": "ed25519-scoped-tokens",
        }
    )


@app.get("/mint")
def mint():
    audience = request.args.get("aud", "").strip()
    if not audience:
        return _bad_request("missing audience")

    try:
        scope = normalize_scope(request.args.get("scope", ""))
    except AuthError as exc:
        return _bad_request(str(exc))

    assertion = request.headers.get("X-Service-Assertion", "").strip()
    try:
        payload, policy = _verify_service_assertion(assertion, audience, scope)
    except AuthError:
        return _forbidden()

    service_id = payload["sub"]
    return jsonify(
        {
            "access_token": _issue_access_token(service_id, audience, scope),
            "audience": audience,
            "scope": scope,
            "issued_to": service_id,
        }
    )


if __name__ == "__main__":
    ssl_context = build_server_ssl_context(
        TLS_SERVER_CERT_PATH,
        TLS_SERVER_KEY_PATH,
        TLS_CA_CERT_PATH,
    )
    serve_http_and_mtls(app, HTTP_PORT, HTTPS_PORT, ssl_context)
