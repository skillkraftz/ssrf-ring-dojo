import ipaddress
import socket
import sys
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app as gateway_app

BASE = "http://127.0.0.1:5000"
INTERNAL_ADMIN_BASE = "http://internal-admin:5001"
TOKEN_SERVICE_BASE = "http://token-service:5003"


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


def test_direct_token_mint_blocked():
    r = _fetch(
        "http://token-service:5003/mint?aud=internal-admin&scope=admin.export.read"
    )
    assert r.status_code in (400, 403)


def test_token_service_discovery_blocked():
    r = _fetch("http://token-service:5003/.well-known/mesh")
    assert r.status_code in (400, 403)


def test_container_ip_targets_blocked():
    internal_admin_ip = socket.gethostbyname("internal-admin")
    assert ipaddress.ip_address(internal_admin_ip).is_private

    r = _fetch(f"http://{internal_admin_ip}:5001/health")
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


def test_token_service_discovery_requires_assertion_directly():
    r = requests.get(f"{TOKEN_SERVICE_BASE}/.well-known/mesh", timeout=5)
    assert r.status_code == 403


def test_token_service_mint_requires_service_assertion_directly():
    r = requests.get(
        f"{TOKEN_SERVICE_BASE}/mint",
        params={"aud": "internal-admin", "scope": "admin.export.read"},
        timeout=5,
    )
    assert r.status_code == 403


def test_token_service_rejects_forged_service_assertion_directly():
    r = requests.get(
        f"{TOKEN_SERVICE_BASE}/mint",
        params={"aud": "internal-admin", "scope": "admin.export.read"},
        headers={"X-Service-Assertion": "bogus"},
        timeout=5,
    )
    assert r.status_code == 403


def test_internal_metrics_require_bearer_token_directly():
    r = requests.get(f"{INTERNAL_ADMIN_BASE}/internal/metrics", timeout=5)
    assert r.status_code == 403


def test_debug_config_requires_bearer_token_directly():
    r = requests.get(f"{INTERNAL_ADMIN_BASE}/debug/config", timeout=5)
    assert r.status_code == 403


def test_legacy_query_token_export_rejected_directly():
    r = requests.get(
        f"{INTERNAL_ADMIN_BASE}/admin/export",
        params={"access_token": "ring-export-token"},
        timeout=5,
    )
    assert r.status_code == 403


def test_safe_fetch_revalidates_redirect_targets(monkeypatch):
    class FakeResponse:
        def __init__(self, url: str, location: str | None = None):
            self.url = url
            self.headers = {"Location": location} if location else {}
            self.is_redirect = location is not None

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, url, timeout, allow_redirects):
            assert timeout == gateway_app.REQUEST_TIMEOUT
            assert allow_redirects is False
            if url == "http://public.example/start":
                return FakeResponse(url, "http://internal-admin:5001/health")
            raise AssertionError(f"unexpected url {url}")

    def fake_resolve(host: str):
        if host == "public.example":
            return {ipaddress.ip_address("93.184.216.34")}
        if host == "internal-admin":
            return {ipaddress.ip_address("172.21.0.4")}
        raise AssertionError(f"unexpected host {host}")

    monkeypatch.setattr(gateway_app, "resolve_addresses", fake_resolve)
    monkeypatch.setattr(gateway_app.requests, "Session", lambda: FakeSession())

    with pytest.raises(gateway_app.UnsafeTargetError, match="blocked internal address"):
        gateway_app.safe_fetch("http://public.example/start")
