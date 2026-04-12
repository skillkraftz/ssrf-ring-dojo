from flask import Flask, request, jsonify
import ipaddress
import os
import requests
import socket
from urllib.parse import urljoin, urlparse

app = Flask(__name__)
ALLOWED_PROXY_HOSTS = {
    h.strip()
    for h in os.getenv("ALLOWED_PROXY_HOSTS", "internal-admin").split(",")
    if h.strip()
}
ALLOWED_PROXY_URLS = {
    u.strip()
    for u in os.getenv("ALLOWED_PROXY_URLS", "http://internal-admin:5001/health").split(
        ","
    )
    if u.strip()
}
REQUEST_TIMEOUT = 3
MAX_REDIRECTS = 5


class UnsafeTargetError(ValueError):
    pass


def resolve_addresses(host: str):
    try:
        info = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise UnsafeTargetError("unresolvable host") from exc

    addresses = set()
    for _, _, _, _, sockaddr in info:
        raw_ip = sockaddr[0].split("%", 1)[0]
        addresses.add(ipaddress.ip_address(raw_ip))

    if not addresses:
        raise UnsafeTargetError("unresolvable host")

    return addresses


def validate_external_url(target: str):
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        raise UnsafeTargetError("bad scheme")

    if not parsed.hostname:
        raise UnsafeTargetError("missing hostname")

    try:
        parsed.port
    except ValueError as exc:
        raise UnsafeTargetError("bad port") from exc

    addresses = resolve_addresses(parsed.hostname)
    if any(not address.is_global for address in addresses):
        raise UnsafeTargetError("blocked internal address")

    return parsed


def safe_fetch(target: str):
    current = target

    with requests.Session() as session:
        session.trust_env = False

        for _ in range(MAX_REDIRECTS + 1):
            validate_external_url(current)
            response = session.get(
                current, timeout=REQUEST_TIMEOUT, allow_redirects=False
            )

            if not response.is_redirect:
                return response

            location = response.headers.get("Location")
            if not location:
                return response

            current = urljoin(response.url, location)

    raise UnsafeTargetError("too many redirects")


@app.get("/health")
def health():
    return {"ok": True, "service": "gateway"}


@app.get("/fetch")
def fetch():
    target = request.args.get("url", "").strip()
    if not target:
        return jsonify({"error": "missing url"}), 400

    try:
        r = safe_fetch(target)
        return jsonify(
            {
                "status_code": r.status_code,
                "content_type": r.headers.get("Content-Type"),
                "body": r.text[:1200],
                "final_url": r.url,
            }
        )
    except UnsafeTargetError as exc:
        message = str(exc)
        status_code = (
            400
            if message
            in {"bad scheme", "missing hostname", "bad port", "unresolvable host"}
            else 403
        )
        return jsonify({"error": message}), status_code
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
