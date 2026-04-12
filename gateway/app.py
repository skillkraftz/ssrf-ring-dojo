"""
Gateway service.

Public surface:
    GET /health             - liveness
    GET /fetch?url=         - user-supplied URL fetcher (SSRF-hardened)
    GET /proxy-health       - hardcoded internal health probe
    GET /proxy-allowlisted  - exact-string allowlisted internal probe

The /fetch endpoint is the only place we follow user-supplied URLs.
It uses safe_external_get() which:

  * rejects non-http(s) schemes
  * rejects any URL containing userinfo (user@host) so the parsed
    netloc cannot be desynced from the validated hostname
  * resolves *all* A / AAAA records for the host and refuses if any
    of them are private, loopback, link-local, multicast, reserved
    or unspecified (with IPv4-mapped-IPv6 unwrapped)
  * for HTTP, pins the outgoing TCP connection to the validated IP
    by rewriting the URL to the IP literal while preserving the
    original Host header. This closes the validate-then-connect
    DNS-rebinding race.
  * follows redirects manually, re-validating every hop, with a hop
    cap and a response size cap

/proxy-health and /proxy-allowlisted are *not* routed through the
SSRF guard because they make code-controlled calls to a fixed
internal allowlist. Letting user input through them is gated by an
exact-string match in /proxy-allowlisted.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from typing import Tuple
from urllib.parse import urlparse, urlunparse

import requests
from flask import Flask, jsonify, request

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
MAX_RESPONSE_BYTES = int(os.getenv("FETCH_MAX_RESPONSE_BYTES", str(1024 * 1024)))
ALLOWED_SCHEMES = ("http", "https")


class SSRFBlocked(Exception):
    """Raised when a URL fails SSRF validation."""


# ---------------------------------------------------------------------------
# IP / host validation
# ---------------------------------------------------------------------------


def _normalize_ip(addr: str):
    """Parse an address string and unwrap ::ffff: IPv4-mapped form."""
    ip = ipaddress.ip_address(addr)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _is_disallowed_ip(ip) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _resolve_all(host: str):
    """Return *all* addresses (v4 and v6) that ``host`` currently resolves to."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFBlocked(f"dns resolution failed: {exc}") from exc

    addrs = []
    for family, _type, _proto, _canon, sockaddr in infos:
        if family == socket.AF_INET:
            addrs.append(_normalize_ip(sockaddr[0]))
        elif family == socket.AF_INET6:
            # Strip any zone-id (e.g. "fe80::1%eth0")
            raw = sockaddr[0].split("%", 1)[0]
            addrs.append(_normalize_ip(raw))
    if not addrs:
        raise SSRFBlocked("host did not resolve")
    return addrs


def _validate_url(url: str) -> Tuple[str, int, "ipaddress._BaseAddress", str]:
    """
    Validate a URL for use as a /fetch target.

    Returns ``(hostname, port, pinned_ip, scheme)``.
    Raises ``SSRFBlocked`` for any disallowed input.
    """
    if not url or not isinstance(url, str):
        raise SSRFBlocked("missing url")

    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SSRFBlocked("bad scheme")

    if (
        parsed.username is not None
        or parsed.password is not None
        or "@" in (parsed.netloc or "")
    ):
        # Refuse any URL that carries userinfo. This kills the
        #   http://gateway@internal-admin:5001/health
        # bypass class because the validator can no longer be
        # desynced from the actual connection target.
        raise SSRFBlocked("userinfo not permitted")

    host = (parsed.hostname or "").strip()
    if not host:
        raise SSRFBlocked("missing host")

    # Hostnames must be plain ASCII letters/digits/hyphens/dots (or
    # bracketed IPv6 literals, which urlparse already strips). We
    # explicitly refuse:
    #   * percent-encoded host components ("internal-admin%2E.")
    #   * IPv6 zone identifiers ("fe80::1%eth0")
    #   * embedded NUL or whitespace
    if "%" in host or any(ch.isspace() or ch == "\x00" for ch in host):
        raise SSRFBlocked("malformed host")

    try:
        port = (
            parsed.port
            if parsed.port is not None
            else (443 if scheme == "https" else 80)
        )
    except ValueError as exc:
        raise SSRFBlocked(f"bad port: {exc}") from exc

    # Sanity-check the port range. We deliberately do *not* maintain a
    # narrow allowlist of "web" ports because the legitimate use of
    # /fetch is to fetch arbitrary user-supplied URLs, which can live
    # on any port. The IP-range filter below is the load-bearing
    # control against SSRF; the port check is just a parser sanity gate.
    if not (0 < port < 65536):
        raise SSRFBlocked("bad port range")

    # If the host is an IP literal in any form Python recognises,
    # validate it directly so we don't even hand it to getaddrinfo.
    try:
        literal = _normalize_ip(host)
    except ValueError:
        literal = None

    if literal is not None:
        if _is_disallowed_ip(literal):
            raise SSRFBlocked("blocked address range")
        return host, port, literal, scheme

    # Hostname path: resolve everything and reject if *any* answer is
    # internal. We then pin to the first allowed answer.
    addrs = _resolve_all(host)
    for ip in addrs:
        if _is_disallowed_ip(ip):
            raise SSRFBlocked("blocked address range")
    return host, port, addrs[0], scheme


# ---------------------------------------------------------------------------
# IP-pinned HTTP client
# ---------------------------------------------------------------------------


def _ip_literal_for_url(ip) -> str:
    if isinstance(ip, ipaddress.IPv6Address):
        return f"[{ip.compressed}]"
    return ip.compressed


def _safe_single_get(url: str) -> requests.Response:
    """One validated, optionally IP-pinned, non-redirect-following GET."""
    host, port, ip, scheme = _validate_url(url)

    parsed = urlparse(url)
    if scheme == "http":
        # IP-pin: rewrite the URL host to the validated IP literal,
        # but preserve the original Host header so name-based vhosts
        # still resolve correctly upstream. This means the connection
        # we make is provably to the same address we just validated,
        # closing the validate-then-resolve race (DNS rebinding).
        pinned_netloc = f"{_ip_literal_for_url(ip)}:{port}"
        pinned_url = urlunparse(parsed._replace(netloc=pinned_netloc))
        # Preserve the original Host header (with explicit port if it
        # was non-default) so name-based virtual hosting still works
        # at the upstream.
        host_header = host if port == 80 else f"{host}:{port}"
        headers = {"Host": host_header}
        request_url = pinned_url
    else:
        # HTTPS: rewriting the URL to an IP literal would break SNI
        # and certificate verification. We rely on validation alone
        # for HTTPS and accept a small DNS-rebinding window. The
        # realistic exposure here is bounded because internal targets
        # in our threat model do not have publicly trusted certs.
        headers = {}
        request_url = url

    resp = requests.get(
        request_url,
        timeout=REQUEST_TIMEOUT,
        allow_redirects=False,
        headers=headers,
        stream=True,
    )
    try:
        chunks = []
        total = 0
        for chunk in resp.iter_content(chunk_size=8192):
            if not chunk:
                continue
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                resp.close()
                raise SSRFBlocked("response too large")
            chunks.append(chunk)
        body = b"".join(chunks)
    finally:
        resp.close()
    resp._content = body  # type: ignore[attr-defined]
    resp._content_consumed = True  # type: ignore[attr-defined]
    # Restore the user-visible URL so the caller does not see the pinned IP.
    resp.url = url
    return resp


def safe_external_get(url: str) -> requests.Response:
    """
    Validated, IP-pinned, manually-followed GET for user-supplied URLs.

    Performs up to ``MAX_REDIRECTS`` hops, re-running the SSRF validator
    on every Location header so an external server cannot redirect us
    into an internal target.
    """
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        resp = _safe_single_get(current)
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location")
            if not location:
                return resp
            # Resolve relative redirects against the *current* URL.
            next_url = requests.compat.urljoin(current, location)
            current = next_url
            continue
        return resp
    raise SSRFBlocked("too many redirects")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/health")
def health():
    return {"ok": True, "service": "gateway"}


@app.get("/fetch")
def fetch():
    target = request.args.get("url", "").strip()
    if not target:
        return jsonify({"error": "missing url"}), 400
    try:
        r = safe_external_get(target)
    except SSRFBlocked as exc:
        return jsonify({"error": f"blocked: {exc}"}), 403
    except requests.RequestException as exc:
        return jsonify({"error": str(exc)}), 502
    body_text = ""
    try:
        body_text = r.text[:1200]
    except Exception:
        body_text = ""
    return jsonify(
        {
            "status_code": r.status_code,
            "content_type": r.headers.get("Content-Type"),
            "body": body_text,
            "final_url": r.url,
        }
    )


@app.get("/proxy-health")
def proxy_health():
    # Hardcoded code-controlled internal call. Not user-influenced, so
    # it does not pass through safe_external_get.
    target = "http://internal-admin:5001/health"
    try:
        r = requests.get(target, timeout=REQUEST_TIMEOUT, allow_redirects=False)
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
