from flask import Flask, jsonify, request
import os

app = Flask(__name__)

TOKEN_AUDIENCE = os.getenv("TOKEN_AUDIENCE", "internal-admin-export")
SERVICE_SHARED_SECRET = os.getenv("SERVICE_SHARED_SECRET", "dojo-shared-secret")


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "token-service"})


@app.get("/.well-known/mesh")
def mesh():
    return jsonify({
        "service": "token-service",
        "audience": TOKEN_AUDIENCE,
        "mode": "legacy-internal",
    })


@app.get("/mint")
def mint():
    aud = request.args.get("aud", "")
    service = request.args.get("service", "")
    provided = request.headers.get("X-Service-Secret", "")

    if aud != TOKEN_AUDIENCE:
        return jsonify({"error": "bad audience"}), 400

    if service != "internal-admin" and provided != SERVICE_SHARED_SECRET:
        return jsonify({"error": "forbidden"}), 403

    return jsonify({
        "access_token": "ring-export-token",
        "audience": TOKEN_AUDIENCE,
        "issued_to": service or "legacy",
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003)
