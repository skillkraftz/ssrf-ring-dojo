import requests

BASE = "http://127.0.0.1:5000"
INTERNAL_ADMIN_BASE = "http://internal-admin:5001"
TOKEN_SERVICE_BASE = "http://token-service:5003"
INTERNAL_API_KEY = "super-secret-internal-key"
SERVICE_SHARED_SECRET = "dojo-shared-secret"


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
    r = requests.get(
        f"{BASE}/proxy-allowlisted",
        params={"target": "http://internal-admin:5001/health"},
        timeout=3,
    )
    assert r.status_code == 200
    payload = r.json()
    assert payload["upstream_status"] == 200
    assert payload["body"]["service"] == "internal-admin"


def test_authenticated_export_flow_still_works():
    mint = requests.get(
        f"{TOKEN_SERVICE_BASE}/mint",
        params={"aud": "internal-admin-export", "service": "internal-admin"},
        headers={"X-Service-Secret": SERVICE_SHARED_SECRET},
        timeout=3,
    )
    assert mint.status_code == 200

    access_token = mint.json()["access_token"]
    export = requests.get(
        f"{INTERNAL_ADMIN_BASE}/admin/export",
        headers={"X-Export-Token": access_token},
        timeout=3,
    )
    assert export.status_code == 200
    payload = export.json()
    assert payload["records"] == 2
    assert payload["users"][0]["email"] == "alice@example.internal"


def test_internal_metrics_still_work_for_authorized_clients():
    r = requests.get(
        f"{INTERNAL_ADMIN_BASE}/internal/metrics",
        headers={"X-Internal-Api-Key": INTERNAL_API_KEY},
        timeout=3,
    )
    assert r.status_code == 200
    payload = r.json()
    assert payload["service"] == "internal-admin"
    assert payload["legacy_mode"] is False
