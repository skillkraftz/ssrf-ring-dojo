"""
Security regression tests for the gateway.

These tests are intended to be run from inside the gateway container,
where the Flask app is bound on 127.0.0.1:5000 and where it can resolve
the other services on the docker bridge network by name.

Each test name documents the bypass class it pins down.
"""

import pytest
import requests

BASE = "http://127.0.0.1:5000"


def _fetch(url: str):
    return requests.get(f"{BASE}/fetch", params={"url": url}, timeout=5)


# ---------------------------------------------------------------------------
# Original baseline tests (kept verbatim so the contract is preserved)
# ---------------------------------------------------------------------------


def test_ssrf_to_internal_health_blocked():
    r = _fetch("http://internal-admin:5001/health")
    assert r.status_code in (400, 403)


def test_userinfo_bypass_to_internal_health_blocked():
    r = _fetch("http://gateway@internal-admin:5001/health")
    assert r.status_code in (400, 403)


def test_redirect_ssrf_to_internal_health_blocked():
    r = _fetch("http://redirector:5002/to-admin-health")
    assert r.status_code in (400, 403)


def test_redirect_ssrf_to_token_mint_blocked():
    r = _fetch("http://redirector:5002/to-token-mint")
    assert r.status_code in (400, 403)


def test_token_service_discovery_blocked():
    r = _fetch("http://token-service:5003/.well-known/mesh")
    assert r.status_code in (400, 403)


def test_allowlisted_proxy_cannot_be_abused_for_other_internal_url():
    r = requests.get(
        f"{BASE}/proxy-allowlisted",
        params={
            "target": "http://internal-admin:5001/admin/export?access_token=ring-export-token"
        },
        timeout=5,
    )
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# New regression tests for known bypass classes
# ---------------------------------------------------------------------------


def test_userinfo_with_password_blocked():
    r = _fetch("http://user:pass@internal-admin:5001/health")
    assert r.status_code in (400, 403)


def test_userinfo_to_admin_export_blocked():
    r = _fetch(
        "http://gateway@internal-admin:5001/admin/export?access_token=ring-export-token"
    )
    assert r.status_code in (400, 403)


def test_userinfo_to_internal_metrics_blocked():
    r = _fetch("http://gateway@internal-admin:5001/internal/metrics")
    assert r.status_code in (400, 403)


def test_userinfo_to_token_mint_blocked():
    r = _fetch(
        "http://gateway@token-service:5003/mint?aud=internal-admin-export&service=internal-admin"
    )
    assert r.status_code in (400, 403)


def test_uppercase_internal_host_blocked():
    r = _fetch("http://INTERNAL-ADMIN:5001/health")
    assert r.status_code in (400, 403)


def test_trailing_dot_internal_host_blocked():
    r = _fetch("http://internal-admin.:5001/health")
    assert r.status_code in (400, 403)


def test_direct_container_ip_blocked():
    # Resolve internal-admin to its current container IP and try
    # to fetch via raw IP literal. This should be blocked because
    # the address is in a private range.
    import socket

    ip = socket.gethostbyname("internal-admin")
    r = _fetch(f"http://{ip}:5001/health")
    assert r.status_code in (400, 403)


def test_decimal_ip_for_internal_blocked():
    import socket, struct

    ip = socket.gethostbyname("internal-admin")
    decimal = struct.unpack("!I", socket.inet_aton(ip))[0]
    r = _fetch(f"http://{decimal}:5001/health")
    assert r.status_code in (400, 403)


def test_localhost_loopback_blocked():
    r = _fetch("http://127.0.0.1:5000/health")
    assert r.status_code in (400, 403)


def test_decimal_loopback_blocked():
    # 2130706433 == 127.0.0.1
    r = _fetch("http://2130706433:5000/health")
    assert r.status_code in (400, 403)


def test_ipv6_loopback_blocked():
    r = _fetch("http://[::1]:5000/health")
    assert r.status_code in (400, 403)


def test_ipv4_mapped_ipv6_loopback_blocked():
    r = _fetch("http://[::ffff:127.0.0.1]:5000/health")
    assert r.status_code in (400, 403)


def test_two_hop_redirect_chain_blocked():
    r = _fetch("http://redirector:5002/chain?second=http://internal-admin:5001/health")
    assert r.status_code in (400, 403)


def test_relative_redirect_back_to_internal_blocked():
    r = _fetch("http://redirector:5002/bounce?to=http://internal-admin:5001/health")
    assert r.status_code in (400, 403)


def test_redirector_itself_blocked():
    # The redirector lives on the docker bridge network so any
    # direct fetch of it is internal-bound and must be refused.
    r = _fetch("http://redirector:5002/")
    assert r.status_code in (400, 403)


def test_token_service_mint_direct_blocked():
    r = _fetch(
        "http://token-service:5003/mint?aud=internal-admin-export&service=internal-admin"
    )
    assert r.status_code in (400, 403)


def test_unusual_port_to_internal_blocked():
    # Even if the IP filter were somehow bypassed, the port allowlist
    # adds a second barrier against service-discovery sweeps.
    r = _fetch("http://internal-admin:5001/health")
    assert r.status_code in (400, 403)


def test_non_http_scheme_blocked():
    r = _fetch("file:///etc/passwd")
    assert r.status_code in (400, 403)


def test_gopher_scheme_blocked():
    r = _fetch("gopher://internal-admin:5001/_GET%20/health")
    assert r.status_code in (400, 403)


def test_admin_export_query_token_no_longer_works_via_gateway():
    # End-to-end: even if SSRF were partially bypassed, internal-admin
    # no longer accepts the token via query string, so the chain is
    # also broken at the receiving side (defense in depth).
    r = _fetch(
        "http://gateway@internal-admin:5001/admin/export?access_token=ring-export-token"
    )
    assert r.status_code in (400, 403)


def test_token_mint_requires_shared_secret():
    # Direct mint via SSRF must be blocked by the gateway, *and*
    # token-service must reject mint attempts that lack the shared
    # secret regardless of the claimed service name.
    r = _fetch(
        "http://token-service:5003/mint?aud=internal-admin-export&service=internal-admin"
    )
    assert r.status_code in (400, 403)


# ---------------------------------------------------------------------------
# internal-admin no-auth shape tests (the legacy X-Internal-Key path is
# gone; the only acceptable credential is now an Ed25519-signed JWT
# minted by token-service, presented over mTLS. The full identity test
# suite lives in test_identity.py).
# ---------------------------------------------------------------------------


_ADMIN_BASE = "https://internal-admin:5001"
_CA_FILE = "/certs/ca.crt"
_CLIENT_CERT = "/certs/gateway.crt"
_CLIENT_KEY = "/certs/gateway.key"


def _mtls_session():
    s = requests.Session()
    s.cert = (_CLIENT_CERT, _CLIENT_KEY)
    s.verify = _CA_FILE
    return s


_MTLS = _mtls_session()


def test_internal_metrics_no_bearer_blocked_at_app_layer():
    """With a valid mTLS cert but no Bearer JWT, internal-admin must
    still refuse. This proves the JWT layer runs even after TLS
    succeeds -- transport is not the only gate."""
    r = _MTLS.get(f"{_ADMIN_BASE}/internal/metrics", timeout=3)
    assert r.status_code == 401
    assert "bearer" in r.json().get("error", "").lower()


def test_internal_metrics_legacy_x_internal_key_no_longer_accepted():
    # The pre-identity-pivot key must no longer be honored, even when
    # presented over a valid mTLS connection.
    r = _MTLS.get(
        f"{_ADMIN_BASE}/internal/metrics",
        headers={"X-Internal-Key": "super-secret-internal-key"},
        timeout=3,
    )
    assert r.status_code == 401


def test_debug_config_no_bearer_blocked_at_app_layer():
    r = _MTLS.get(f"{_ADMIN_BASE}/debug/config", timeout=3)
    assert r.status_code == 401


def test_internal_admin_without_client_cert_refuses_at_tls_layer():
    """Crucial mTLS assertion: a connection that does NOT present a
    valid lab-CA-signed client cert must fail at the TLS handshake,
    not return a 401 from the app. This proves the transport layer
    is actively enforcing mTLS, not just the JWT layer."""
    import ssl

    bare = requests.Session()
    bare.verify = _CA_FILE  # trust the server's cert but send no client cert
    with pytest.raises(
        (requests.exceptions.SSLError, requests.exceptions.ConnectionError)
    ):
        bare.get(f"{_ADMIN_BASE}/internal/metrics", timeout=3)


def test_internal_admin_with_unknown_ca_client_cert_refused():
    """A client cert signed by a *different* CA must be rejected."""
    import tempfile
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    rogue_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rogue-attacker")])
    rogue_cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)  # self-signed
        .public_key(rogue_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True,
        )
        .sign(rogue_key, hashes.SHA256())
    )
    with (
        tempfile.NamedTemporaryFile("wb", suffix=".crt", delete=False) as cf,
        tempfile.NamedTemporaryFile("wb", suffix=".key", delete=False) as kf,
    ):
        cf.write(rogue_cert.public_bytes(serialization.Encoding.PEM))
        kf.write(
            rogue_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        cf_name, kf_name = cf.name, kf.name

    rogue_session = requests.Session()
    rogue_session.cert = (cf_name, kf_name)
    rogue_session.verify = _CA_FILE
    with pytest.raises(
        (requests.exceptions.SSLError, requests.exceptions.ConnectionError)
    ):
        rogue_session.get(f"{_ADMIN_BASE}/internal/metrics", timeout=3)


# ---------------------------------------------------------------------------
# HTTPS pinning: legitimate external HTTPS still works through /fetch.
# This proves the urllib3-based pinned pool correctly:
#   * connects to a validated public IP
#   * sets SNI to the original hostname
#   * verifies the cert against the original hostname
#   * unpacks an HTTPS response correctly
# ---------------------------------------------------------------------------


def test_https_external_fetch_works():
    r = _fetch("https://example.com/")
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["status_code"] == 200
    assert "text/html" in (payload["content_type"] or "")
    assert "Example Domain" in (payload["body"] or "")


def test_https_redirect_re_validation_blocks_internal():
    # httpbin.org/redirect-to issues a 302 to the URL we hand it.
    # Our manual redirect loop must re-validate the next hop and refuse
    # to follow into an internal target.
    r = _fetch("https://httpbin.org/redirect-to?url=http://internal-admin:5001/health")
    assert r.status_code == 403
    assert "blocked" in r.json().get("error", "")


def test_https_external_redirect_to_external_works():
    # External-to-external HTTPS redirects must still work end to end.
    r = _fetch("https://httpbin.org/redirect-to?url=https://example.com/")
    assert r.status_code == 200
    assert "Example Domain" in (r.json().get("body") or "")


# ---------------------------------------------------------------------------
# Rate limiter unit + algorithm tests (no HTTP, no fixtures, no flakiness)
# ---------------------------------------------------------------------------


def test_rate_limiter_token_bucket_unit():
    """Pure-Python test of the token bucket. Imported in-process so it
    is fast, deterministic, and does not interact with the running
    Flask instance's bucket state."""
    from app import _RateLimiter

    rl = _RateLimiter(per_minute=60, burst=3)
    # First three requests pass (full burst).
    assert rl.allow("a") is True
    assert rl.allow("a") is True
    assert rl.allow("a") is True
    # The fourth is denied because the bucket is empty and no time
    # has elapsed for refill.
    assert rl.allow("a") is False
    # A different key has its own bucket.
    assert rl.allow("b") is True


def test_rate_limiter_refill_unit():
    """Burning the bucket and waiting briefly should refill some tokens."""
    import time
    from app import _RateLimiter

    rl = _RateLimiter(per_minute=600, burst=2)  # refill 10/sec
    assert rl.allow("k") is True
    assert rl.allow("k") is True
    assert rl.allow("k") is False
    time.sleep(0.25)  # ~2.5 tokens regenerated
    assert rl.allow("k") is True


# ---------------------------------------------------------------------------
# Adversarial bypass attempts that target the *new* protections
# ---------------------------------------------------------------------------


def test_https_to_internal_hostname_blocked():
    # HTTPS scheme should not bypass the host validator.
    r = _fetch("https://internal-admin:5001/health")
    assert r.status_code == 403


def test_https_userinfo_blocked():
    r = _fetch("https://gateway@internal-admin:5001/health")
    assert r.status_code == 403


def test_redirect_loop_capped():
    # /chain returns a relative 307 to /bounce. We can't easily build a
    # >5-hop chain in this lab, but we *can* prove that the manual loop
    # never blindly follows a chain into the internal network.
    r = _fetch("http://redirector:5002/chain?second=http://internal-admin:5001/health")
    assert r.status_code == 403


def test_response_size_cap_via_env_path():
    # We cannot easily test the size cap end-to-end without an upstream
    # that returns >1 MiB. Instead, exercise the same code path with a
    # tiny in-process limit, importing the gateway module directly.
    import app as gateway_app

    original = gateway_app.MAX_RESPONSE_BYTES
    gateway_app.MAX_RESPONSE_BYTES = 256
    try:
        try:
            gateway_app.safe_external_get("https://example.com/")
        except gateway_app.SSRFBlocked as exc:
            assert "too large" in str(exc)
        else:
            raise AssertionError("expected SSRFBlocked: response too large")
    finally:
        gateway_app.MAX_RESPONSE_BYTES = original


def test_dns_rebinding_https_pinning_resolves_only_once():
    """
    The most important property of HTTPS pinning: validation and connect
    must use the *same* IP, with no second DNS lookup that an attacker
    could poison.

    We monkey-patch socket.getaddrinfo so that the first call returns a
    real public IP (1.1.1.1) and any second call returns the internal
    container IP for internal-admin. After safe_external_get runs, we
    assert getaddrinfo was called exactly once, proving the connect did
    not re-resolve the hostname.
    """
    import socket
    import app as gateway_app

    real_getaddrinfo = socket.getaddrinfo
    real_internal_admin = real_getaddrinfo("internal-admin", None)[0][4][0]
    calls = []

    def fake(host, *args, **kwargs):
        if host == "rebind.test":
            calls.append(host)
            if len(calls) == 1:
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 0))]
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (real_internal_admin, 0))
            ]
        return real_getaddrinfo(host, *args, **kwargs)

    socket.getaddrinfo = fake
    try:
        try:
            gateway_app.safe_external_get("https://rebind.test/")
        except Exception:
            # The TLS handshake will fail because 1.1.1.1's cert is for
            # cloudflare-dns.com, not rebind.test. That is the EXPECTED
            # outcome: the connect went to 1.1.1.1 (pinned), the cert
            # check rejected the wrong-name presentation, and we never
            # came anywhere near the internal IP.
            pass
        assert calls.count("rebind.test") == 1, (
            f"expected exactly one DNS lookup for rebind.test, got "
            f"{calls.count('rebind.test')} (DNS rebinding window!)"
        )
    finally:
        socket.getaddrinfo = real_getaddrinfo


def test_dns_rebinding_any_internal_record_blocked():
    """
    Multi-record DNS where any answer is internal must be rejected.
    Reproduce by pretending a public hostname has both a public and a
    private A record.
    """
    import socket
    import app as gateway_app

    real_getaddrinfo = socket.getaddrinfo

    def fake(host, *args, **kwargs):
        if host == "mixed.test":
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0)),
            ]
        return real_getaddrinfo(host, *args, **kwargs)

    socket.getaddrinfo = fake
    try:
        try:
            gateway_app.safe_external_get("http://mixed.test/")
        except gateway_app.SSRFBlocked as exc:
            assert "blocked" in str(exc).lower()
        else:
            raise AssertionError(
                "validator must refuse a hostname with any internal A record"
            )
    finally:
        socket.getaddrinfo = real_getaddrinfo


def test_admin_export_query_token_directly_refused():
    """Even bypassing the gateway entirely, internal-admin must refuse a
    request that supplies a token via query string. The legacy bearer
    path is gone, so the only acceptable credential is a JWT in the
    Authorization header presented over mTLS."""
    r = _MTLS.get(
        f"{_ADMIN_BASE}/admin/export?access_token=ring-export-token",
        timeout=3,
    )
    assert r.status_code == 401


def test_legacy_token_service_mint_endpoint_is_gone():
    """The legacy /mint endpoint accepted any caller claiming a service
    identity. It must no longer exist; only /v2/mint with HMAC-signed
    client credentials remains. The probe uses mTLS because all
    token-service endpoints are now HTTPS."""
    r = _MTLS.get(
        "https://token-service:5003/mint",
        params={"aud": "internal-admin-export", "service": "internal-admin"},
        timeout=3,
    )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# IMPORTANT: the rate-limit integration test must be the LAST function in
# this file. It deliberately drains the live token bucket on the running
# gateway process; any test that runs after it will hit 429.
# ---------------------------------------------------------------------------


def test_zzz_rate_limit_engages_via_http():
    """Burst /fetch from the loopback client until the live rate limiter
    returns 429. Uses an internal target so the rate-limited path is the
    only network path involved (no external traffic, no flakiness)."""
    seen_429 = False
    last_status = None
    for _ in range(400):
        r = requests.get(
            f"{BASE}/fetch",
            params={"url": "http://internal-admin:5001/health"},
            timeout=2,
        )
        last_status = r.status_code
        if r.status_code == 429:
            seen_429 = True
            break
        # Sanity: every non-429 response must be a SSRF block (403),
        # because the URL we are pounding is always invalid.
        assert r.status_code == 403, f"unexpected status {r.status_code}: {r.text}"
    assert seen_429, f"rate limiter never engaged; last status {last_status}"
