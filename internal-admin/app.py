from flask import Flask, jsonify, request
import os

app = Flask(__name__)

INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY", "dev-internal-key")
EXPORT_TOKEN = os.getenv("EXPORT_TOKEN", "export-me")
MINT_AUDIENCE = os.getenv("MINT_AUDIENCE", "internal-admin-export")


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "internal-admin"})


@app.get("/debug/config")
def debug_config():
    return jsonify(
        {
            "service": "internal-admin",
            "note": "debug disabled soon",
            "env": os.getenv("APP_ENV", "dev"),
            "feature_flags": ["metrics", "legacy_export"],
        }
    )


@app.get("/internal/metrics")
def metrics():
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
    # Tokens MUST come from a header. The legacy ?access_token= path
    # was a credential-in-URL antipattern that allowed an SSRF chain
    # to smuggle the token inside a fetched URL and to leak it into
    # logs / metrics. Header-only enforcement closes that off.
    header_token = request.headers.get("X-Export-Token", "")
    if not header_token or header_token != EXPORT_TOKEN:
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
