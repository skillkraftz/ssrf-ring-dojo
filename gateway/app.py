from flask import Flask, request, jsonify
import os
import requests
import socket
from urllib.parse import urlparse

app = Flask(__name__)
ALLOWED_PROXY_HOSTS = {h.strip() for h in os.getenv("ALLOWED_PROXY_HOSTS", "internal-admin").split(",") if h.strip()}
ALLOWED_PROXY_URLS = {u.strip() for u in os.getenv("ALLOWED_PROXY_URLS", "http://internal-admin:5001/health").split(",") if u.strip()}
REQUEST_TIMEOUT = 3


def resolve_host(host: str):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def weak_is_blocked_target(parsed) -> bool:
    hostname = (parsed.hostname or "").lower()
    netloc = (parsed.netloc or "").lower()
    if not hostname:
        return True
    # Intentionally weak: compares raw netloc strings, so userinfo forms such as
    # gateway@internal-admin:5001 bypass the check. Only blocks one internal
    # service directly, ignores token-service, redirector, RFC1918, and redirects.
    blocked_netlocs = {
        "localhost",
        "localhost:5000",
        "internal-admin:5001",
    }
    return netloc in blocked_netlocs


@app.get("/health")
def health():
    return {"ok": True, "service": "gateway"}


@app.get("/fetch")
def fetch():
    target = request.args.get("url", "").strip()
    if not target:
        return jsonify({"error": "missing url"}), 400

    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        return jsonify({"error": "bad scheme"}), 400

    if weak_is_blocked_target(parsed):
        return jsonify({"error": "blocked hostname"}), 403

    resolved = resolve_host(parsed.hostname) if parsed.hostname else None
    if resolved and (resolved.startswith("127.") or resolved == "::1"):
        return jsonify({"error": "blocked localhost"}), 403

    try:
        r = requests.get(target, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        return jsonify({
            "status_code": r.status_code,
            "content_type": r.headers.get("Content-Type"),
            "body": r.text[:1200],
            "final_url": r.url,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.get("/proxy-health")
def proxy_health():
    target = "http://internal-admin:5001/health"
    try:
        r = requests.get(target, timeout=REQUEST_TIMEOUT)
        return jsonify({"upstream_status": r.status_code, "body": r.json()})
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.get("/proxy-allowlisted")
def proxy_allowlisted():
    target = request.args.get("target", "").strip()
    if target not in ALLOWED_PROXY_URLS:
        return jsonify({"error": "target not allowlisted"}), 403

    parsed = urlparse(target)
    if parsed.hostname not in ALLOWED_PROXY_HOSTS:
        return jsonify({"error": "host not allowlisted"}), 403

    try:
        r = requests.get(target, timeout=REQUEST_TIMEOUT, allow_redirects=False)
        return jsonify({"upstream_status": r.status_code, "body": r.json()})
    except Exception as e:
        return jsonify({"error": str(e)}), 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
