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

app = Flask(__name__)

TOKEN_ISSUER = os.getenv("TOKEN_ISSUER", "token-service")
ACCESS_TOKEN_SIGNING_SECRET = os.getenv(
    "ACCESS_TOKEN_SIGNING_SECRET", "dev-access-token-signing-secret"
)
ACCESS_TOKEN_TTL_SECONDS = int(os.getenv("ACCESS_TOKEN_TTL_SECONDS", "60"))
ASSERTION_TTL_SECONDS = int(os.getenv("ASSERTION_TTL_SECONDS", "30"))
INTERNAL_ADMIN_CLIENT_ID = os.getenv("INTERNAL_ADMIN_CLIENT_ID", "internal-admin")
INTERNAL_ADMIN_CLIENT_SECRET = os.getenv(
    "INTERNAL_ADMIN_CLIENT_SECRET", "dev-internal-admin-client-secret"
)
MAX_CLOCK_SKEW_SECONDS = 5
USED_ASSERTION_JTIS = {}

SERVICE_POLICIES = {
    INTERNAL_ADMIN_CLIENT_ID: {
        "secret": INTERNAL_ADMIN_CLIENT_SECRET,
        "audiences": {"internal-admin"},
        "scopes": {
            "admin.export.read",
            "debug.config.read",
            "internal.metrics.read",
            "token.discovery",
        },
    }
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


def _verify_service_assertion(
    assertion: str, requested_audience: str, requested_scope: str
):
    if not assertion:
        raise AuthError("missing service assertion")

    preview = peek_signed_payload(assertion)
    service_id = preview.get("sub", "")
    policy = _load_policy(service_id)
    payload = verify_signed_payload(assertion, policy["secret"])

    now = now_epoch()
    if payload.get("iss") != service_id:
        raise AuthError("bad issuer")
    if payload.get("aud") != TOKEN_ISSUER:
        raise AuthError("bad audience")
    if payload.get("request_aud") != requested_audience:
        raise AuthError("audience mismatch")
    if payload.get("request_scope") != requested_scope:
        raise AuthError("scope mismatch")

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
            "iss": TOKEN_ISSUER,
            "sub": service_id,
            "aud": audience,
            "scope": scope,
            "iat": now,
            "exp": now + ACCESS_TOKEN_TTL_SECONDS,
            "jti": new_jti(),
            "one_time": True,
        },
        ACCESS_TOKEN_SIGNING_SECRET,
    )


def issue_service_assertion(
    service_id: str, service_secret: str, audience: str, scope: str
) -> str:
    now = now_epoch()
    return issue_signed_payload(
        {
            "iss": service_id,
            "sub": service_id,
            "aud": TOKEN_ISSUER,
            "request_aud": audience,
            "request_scope": scope,
            "iat": now,
            "exp": now + ASSERTION_TTL_SECONDS,
            "jti": new_jti(),
        },
        service_secret,
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
            "mode": "scoped-service-tokens",
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

    if audience not in policy["audiences"] or scope not in policy["scopes"]:
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
    app.run(host="0.0.0.0", port=5003)
