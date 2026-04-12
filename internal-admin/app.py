import base64
import binascii
import hashlib
import hmac
import json
import os
import time

from flask import Flask, jsonify, request

app = Flask(__name__)

INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY", "dev-internal-key")
MINT_AUDIENCE = os.getenv("MINT_AUDIENCE", "internal-admin-export")
EXPORT_SIGNING_SECRET = os.getenv("EXPORT_SIGNING_SECRET", "dev-export-signing-secret")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _read_export_token() -> str:
    if request.headers.get("X-Export-Token"):
        return request.headers["X-Export-Token"].strip()

    auth_header = request.headers.get("Authorization", "")
    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() == "bearer" and token:
        return token.strip()

    return ""


def _verify_export_token(token: str):
    if not token:
        return None

    try:
        payload_b64, signature_b64 = token.split(".", 1)
        expected_signature = (
            base64.urlsafe_b64encode(
                hmac.new(
                    EXPORT_SIGNING_SECRET.encode("utf-8"),
                    payload_b64.encode("ascii"),
                    hashlib.sha256,
                ).digest()
            )
            .rstrip(b"=")
            .decode("ascii")
        )

        if not hmac.compare_digest(signature_b64, expected_signature):
            return None

        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError, binascii.Error):
        return None

    now = int(time.time())
    if payload.get("aud") != MINT_AUDIENCE:
        return None
    if not payload.get("service"):
        return None

    try:
        expires_at = int(payload.get("exp", 0))
        issued_at = int(payload.get("iat", 0))
    except (TypeError, ValueError):
        return None

    if expires_at <= now:
        return None
    if issued_at > now + 5:
        return None

    return payload


def _has_internal_api_key() -> bool:
    provided = request.headers.get("X-Internal-Api-Key", "")
    return bool(provided) and hmac.compare_digest(provided, INTERNAL_API_KEY)


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "internal-admin"})


@app.get("/debug/config")
def debug_config():
    if not _has_internal_api_key():
        return jsonify({"error": "forbidden"}), 403

    return jsonify(
        {
            "service": "internal-admin",
            "note": "debug requires internal api key",
            "env": os.getenv("APP_ENV", "dev"),
            "feature_flags": ["metrics", "signed_export_tokens"],
        }
    )


@app.get("/internal/metrics")
def metrics():
    if not _has_internal_api_key():
        return jsonify({"error": "forbidden"}), 403

    return jsonify(
        {
            "service": "internal-admin",
            "build": "v2.1.7",
            "token_provider": "token-service",
            "audience": MINT_AUDIENCE,
            "legacy_mode": False,
            "status": "ok",
        }
    )


@app.get("/admin/export")
def admin_export():
    token = _read_export_token()
    if _verify_export_token(token) is None:
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
