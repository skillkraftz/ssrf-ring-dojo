import requests

BASE = "http://127.0.0.1:5000"


def test_health():
    r = requests.get(f"{BASE}/health", timeout=3)
    assert r.status_code == 200
    assert r.json()["service"] == "gateway"


def test_proxy_health_still_works():
    r = requests.get(f"{BASE}/proxy-health", timeout=3)
    assert r.status_code == 200
    payload = r.json()
    assert payload["upstream_status"] == 200
    assert payload["body"]["service"] == "internal-admin"


def test_allowlisted_proxy_health_still_works():
    # Internal mesh is mTLS-only now, so the allowlisted URL is https://.
    r = requests.get(
        f"{BASE}/proxy-allowlisted",
        params={"target": "https://internal-admin:5001/health"},
        timeout=3,
    )
    assert r.status_code == 200
    payload = r.json()
    assert payload["upstream_status"] == 200
    assert payload["body"]["service"] == "internal-admin"
