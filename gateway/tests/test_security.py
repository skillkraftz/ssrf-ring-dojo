import requests

BASE = "http://127.0.0.1:5000"


def _fetch(url: str):
    return requests.get(f"{BASE}/fetch", params={"url": url}, timeout=5)


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
        params={"target": "http://internal-admin:5001/admin/export?access_token=ring-export-token"},
        timeout=5,
    )
    assert r.status_code == 403
