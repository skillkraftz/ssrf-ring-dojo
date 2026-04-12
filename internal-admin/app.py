"""
Internal admin service.

This service has no inbound exposure outside the docker bridge network.
We still authenticate the sensitive endpoints because being on the bridge
network is not a sufficient identity assertion: any compromised peer or
SSRF foothold would otherwise reach them.

Endpoint summary:

    GET /health           - liveness, no auth (used as a probe target)
    GET /debug/config     - dev only, requires X-Internal-Key
    GET /internal/metrics - requires X-Internal-Key
    GET /admin/export     - requires X-Export-Token (header only)
"""

import hmac
import os

from flask import Flask, jsonify, request

app = Flask(__name__)

INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY", "dev-internal-key")
EXPORT_TOKEN = os.getenv("EXPORT_TOKEN", "export-me")
MINT_AUDIENCE = os.getenv("MINT_AUDIENCE", "internal-admin-export")
APP_ENV = os.getenv("APP_ENV", "dev").lower()


def _check_internal_key() -> bool:
    provided = request.headers.get("X-Internal-Key", "")
    if not provided:
        return False
    return hmac.compare_digest(provided, INTERNAL_API_KEY)


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "internal-admin"})


@app.get("/debug/config")
def debug_config():
    # Defense in depth:
    #   1. /debug/config is a development affordance and should not exist
    #      in production. If APP_ENV is anything other than "dev" we
    #      pretend the route does not exist (404), so an attacker who
    #      reaches the network cannot even confirm the endpoint shape.
    #   2. Even in dev, require the shared internal key. This avoids
    #      "any process on the bridge network can read this".
    if APP_ENV != "dev":
        return jsonify({"error": "not found"}), 404
    if not _check_internal_key():
        return jsonify({"error": "forbidden"}), 403
    return jsonify(
        {
            "service": "internal-admin",
            "note": "debug disabled soon",
            "env": APP_ENV,
            "feature_flags": ["metrics", "legacy_export"],
        }
    )


@app.get("/internal/metrics")
def metrics():
    # Metrics endpoints are reasonable to keep enabled in production but
    # must always be authenticated. The previous version was a free
    # information disclosure to anyone on the bridge network.
    if not _check_internal_key():
        return jsonify({"error": "forbidden"}), 403
    return jsonify(
        {
            "service": "internal-admin",
            "build": "v2.1.7",
            "token_provider": "token-service",
            "audience": MINT_AUDIENCE,
            "legacy_mode": True,
            "status": "ok",
        }
    )


@app.get("/admin/export")
def admin_export():
    # Tokens MUST come from a header. The legacy ?access_token= path was
    # a credential-in-URL antipattern that allowed an SSRF chain to
    # smuggle the token inside a fetched URL and to leak it into logs /
    # metrics. Header-only enforcement closes that off. We use a constant
    # time compare to avoid token-byte timing leaks.
    header_token = request.headers.get("X-Export-Token", "")
    if not header_token or not hmac.compare_digest(header_token, EXPORT_TOKEN):
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
