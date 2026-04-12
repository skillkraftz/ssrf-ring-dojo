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
  * rejects malformed hostnames (percent-encoded, NUL, whitespace)
  * resolves *all* A / AAAA records for the host and refuses if any
    of them are private, loopback, link-local, multicast, reserved
    or unspecified (with IPv4-mapped-IPv6 unwrapped)
  * pins the outgoing TCP connection to the validated IP for BOTH
    HTTP and HTTPS, while preserving SNI and certificate verification
    against the original hostname (urllib3 server_hostname +
    assert_hostname). This closes the validate-then-connect race
    that lets DNS rebinding swap a public address for an internal
    one between validation and the actual TCP connect.
  * follows redirects manually, re-validating every hop, with a hop
    cap and a response size cap
  * is rate limited per remote client IP via a token bucket so the
    endpoint cannot be abused as an external port scanner

Validator failures and rate-limit hits are logged with the client IP,
the requested URL, and a structured reason.

/proxy-health and /proxy-allowlisted are *not* routed through the
SSRF guard because they make code-controlled calls to a fixed
internal allowlist. The user-influenced one (/proxy-allowlisted)
is gated by an exact-string allowlist.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
import ssl
import time
from threading import Lock
from typing import Tuple
from urllib.parse import urljoin, urlparse

import requests
import urllib3
from flask import Flask, jsonify, request

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
)

app = Flask(__name__)
log = app.logger

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

REQUEST_TIMEOUT = float(os.getenv("FETCH_REQUEST_TIMEOUT", "3"))
CONNECT_TIMEOUT = float(os.getenv("FETCH_CONNECT_TIMEOUT", "2"))
MAX_REDIRECTS = int(os.getenv("FETCH_MAX_REDIRECTS", "5"))
MAX_RESPONSE_BYTES = int(os.getenv("FETCH_MAX_RESPONSE_BYTES", str(1024 * 1024)))
ALLOWED_SCHEMES = ("http", "https")

# Per-IP rate limit on /fetch. Token bucket: tokens refill at
# RATE_LIMIT_PER_MINUTE / 60 per second, capped at RATE_LIMIT_BURST.
# Defaults are sized so the test suite (~30 calls in <1s from a single
# loopback client) does not trip the limiter, but a real abuser making
# >2 req/s sustained will quickly run out of tokens.
RATE_LIMIT_PER_MINUTE = int(os.getenv("FETCH_RATE_LIMIT_PER_MINUTE", "120"))
RATE_LIMIT_BURST = int(os.getenv("FETCH_RATE_LIMIT_BURST", "60"))


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
        raise SSRFBlocked("userinfo not permitted")

    host = (parsed.hostname or "").strip()
    if not host:
        raise SSRFBlocked("missing host")

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
# Rate limiter (per remote client IP, in-memory token bucket)
# ---------------------------------------------------------------------------


class _RateLimiter:
    """In-memory per-key token bucket. Single-process only.

    A request consumes 1 token. Tokens refill at ``per_minute/60`` per
    second up to ``burst``. Cleared LRU-style when the bucket population
    exceeds ``max_keys`` to bound memory.
    """

    def __init__(self, per_minute: int, burst: int, max_keys: int = 10000):
        self._burst = float(max(1, burst))
        self._refill_per_sec = max(0.0, per_minute) / 60.0
        self._buckets: dict[str, list] = {}  # key -> [tokens, last_touch]
        self._lock = Lock()
        self._max_keys = max_keys

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if len(self._buckets) > self._max_keys:
                # Drop the oldest half by last_touch. Cheap, bounded.
                survivors = sorted(
                    self._buckets.items(), key=lambda kv: kv[1][1], reverse=True
                )[: self._max_keys // 2]
                self._buckets = {k: v for k, v in survivors}

            entry = self._buckets.get(key)
            if entry is None:
                tokens, last = self._burst, now
            else:
                tokens, last = entry
                tokens = min(self._burst, tokens + (now - last) * self._refill_per_sec)

            if tokens < 1.0:
                self._buckets[key] = [tokens, now]
                return False
            self._buckets[key] = [tokens - 1.0, now]
            return True

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


_rate_limiter = _RateLimiter(RATE_LIMIT_PER_MINUTE, RATE_LIMIT_BURST)


# ---------------------------------------------------------------------------
# IP-pinned HTTP/HTTPS client (urllib3 with custom server_hostname)
# ---------------------------------------------------------------------------


class _SafeResponse:
    """Minimal response container used by the manual redirect loop and
    the /fetch handler. We avoid dragging the high-level requests.Response
    through the pinned-pool flow because we want one consistent path for
    HTTP and HTTPS."""

    __slots__ = ("url", "status_code", "headers", "body")

    def __init__(self, url, status_code, headers, body):
        self.url = url
        self.status_code = status_code
        self.headers = headers
        self.body = body

    @property
    def text(self) -> str:
        ct = (self.headers.get("Content-Type") or "").lower()
        encoding = "utf-8"
        if "charset=" in ct:
            try:
                encoding = (
                    ct.split("charset=", 1)[1].split(";", 1)[0].strip().strip("\"'")
                )
            except Exception:  # pragma: no cover
                encoding = "utf-8"
        try:
            return self.body.decode(encoding, errors="replace")
        except (LookupError, UnicodeDecodeError):
            return self.body.decode("utf-8", errors="replace")

    def is_redirect(self) -> bool:
        return self.status_code in (301, 302, 303, 307, 308)


# A single shared SSLContext built from the system trust store. We
# deliberately use ``ssl.create_default_context()`` rather than certifi:
# the slim Debian image we run on has a CA bundle that includes the
# issuer chain we need, and using the system store keeps trust decisions
# consistent with everything else on the host.
_TLS_CONTEXT = ssl.create_default_context()


def _build_pinned_pool(scheme: str, host: str, ip, port: int):
    """Construct a one-shot urllib3 connection pool that:

      * connects to the validated/pinned IP (``host=str(ip)``)
      * uses the original hostname for SNI (``server_hostname=host``)
      * verifies the certificate against the original hostname
        (``assert_hostname=host``)

    The pool is fresh per call so there is no chance of cached state
    leaking between requests with different validation outcomes.
    """
    timeout = urllib3.Timeout(connect=CONNECT_TIMEOUT, read=REQUEST_TIMEOUT)
    common = dict(
        host=str(ip),
        port=port,
        timeout=timeout,
        maxsize=1,
        block=True,
        retries=False,
    )
    if scheme == "https":
        return urllib3.HTTPSConnectionPool(
            **common,
            server_hostname=host,
            assert_hostname=host,
            cert_reqs="CERT_REQUIRED",
            ssl_context=_TLS_CONTEXT,
        )
    return urllib3.HTTPConnectionPool(**common)


def _safe_single_get(url: str) -> _SafeResponse:
    """One validated, IP-pinned, non-redirect-following GET."""
    host, port, ip, scheme = _validate_url(url)

    parsed = urlparse(url)
    request_path = parsed.path or "/"
    if parsed.query:
        request_path = f"{request_path}?{parsed.query}"

    is_default_port = (scheme == "http" and port == 80) or (
        scheme == "https" and port == 443
    )
    host_header = host if is_default_port else f"{host}:{port}"

    pool = _build_pinned_pool(scheme, host, ip, port)
    try:
        resp = pool.urlopen(
            "GET",
            request_path,
            headers={
                "Host": host_header,
                "Accept": "*/*",
                "User-Agent": "ssrf-ring-dojo-gateway/2.0",
            },
            redirect=False,
            preload_content=False,
            decode_content=True,
        )
        try:
            chunks = []
            total = 0
            for chunk in resp.stream(8192, decode_content=True):
                if not chunk:
                    continue
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    raise SSRFBlocked("response too large")
                chunks.append(chunk)
            body = b"".join(chunks)
        finally:
            try:
                resp.release_conn()
            except Exception:  # pragma: no cover
                pass
        return _SafeResponse(
            url=url,
            status_code=resp.status,
            headers=dict(resp.headers.items()),
            body=body,
        )
    finally:
        pool.close()


def safe_external_get(url: str) -> _SafeResponse:
    """
    Validated, IP-pinned, manually-followed GET for user-supplied URLs.

    Performs up to ``MAX_REDIRECTS`` hops, re-running the SSRF validator
    on every Location header so an external server cannot redirect us
    into an internal target.
    """
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        resp = _safe_single_get(current)
        if resp.is_redirect():
            location = resp.headers.get("Location")
            if not location:
                return resp
            current = urljoin(current, location)
            continue
        return resp
    raise SSRFBlocked("too many redirects")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def _client_key() -> str:
    return request.remote_addr or "anonymous"


@app.get("/health")
def health():
    return {"ok": True, "service": "gateway"}


@app.get("/fetch")
def fetch():
    client = _client_key()

    # Rate-limit *before* validation so a probing attacker cannot bypass
    # the rate limit by sending only invalid URLs.
    if not _rate_limiter.allow(client):
        log.warning(
            "ratelimit hit client=%s url=%s", client, request.args.get("url", "")
        )
        return jsonify({"error": "rate limit exceeded"}), 429

    target = request.args.get("url", "").strip()
    if not target:
        return jsonify({"error": "missing url"}), 400

    try:
        r = safe_external_get(target)
    except SSRFBlocked as exc:
        log.warning("ssrf blocked client=%s url=%s reason=%s", client, target, exc)
        return jsonify({"error": f"blocked: {exc}"}), 403
    except urllib3.exceptions.MaxRetryError as exc:
        return jsonify({"error": str(exc)}), 502
    except urllib3.exceptions.HTTPError as exc:
        return jsonify({"error": str(exc)}), 502
    except OSError as exc:
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
    # Hardcoded code-controlled internal call. Not user-influenced.
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
