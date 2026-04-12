import base64
import hashlib
import hmac
import json
import os
import time

from flask import Flask, jsonify, request

app = Flask(__name__)

TOKEN_AUDIENCE = os.getenv("TOKEN_AUDIENCE", "internal-admin-export")
SERVICE_SHARED_SECRET = os.getenv("SERVICE_SHARED_SECRET", "dojo-shared-secret")
EXPORT_SIGNING_SECRET = os.getenv("EXPORT_SIGNING_SECRET", "dev-export-signing-secret")
TOKEN_TTL_SECONDS = int(os.getenv("TOKEN_TTL_SECONDS", "60"))


def _has_service_secret() -> bool:
    provided = request.headers.get("X-Service-Secret", "")
    return bool(provided) and hmac.compare_digest(provided, SERVICE_SHARED_SECRET)


def _issue_export_token(service: str) -> str:
    now = int(time.time())
    payload = {
        "aud": TOKEN_AUDIENCE,
        "service": service,
        "iat": now,
        "exp": now + TOKEN_TTL_SECONDS,
    }
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    payload_b64 = base64.urlsafe_b64encode(payload_json).rstrip(b"=").decode("ascii")
    signature = (
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
    return f"{payload_b64}.{signature}"


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "token-service"})


@app.get("/.well-known/mesh")
def mesh():
    if not _has_service_secret():
        return jsonify({"error": "forbidden"}), 403

    return jsonify(
        {
            "service": "token-service",
            "audience": TOKEN_AUDIENCE,
            "mode": "authenticated-internal",
        }
    )


@app.get("/mint")
def mint():
    aud = request.args.get("aud", "")
    service = request.args.get("service", "")

    if aud != TOKEN_AUDIENCE:
        return jsonify({"error": "bad audience"}), 400

    if service != "internal-admin" or not _has_service_secret():
        return jsonify({"error": "forbidden"}), 403

    return jsonify(
        {
            "access_token": _issue_export_token(service),
            "audience": TOKEN_AUDIENCE,
            "issued_to": service,
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003)
