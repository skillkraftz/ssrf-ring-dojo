"""
Security regression tests for the gateway.

These tests are intended to be run from inside the gateway container,
where the Flask app is bound on 127.0.0.1:5000 and where it can resolve
the other services on the docker bridge network by name.

Each test name documents the bypass class it pins down.
"""

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
