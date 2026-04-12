#!/usr/bin/env bash
set -euo pipefail

BASE="http://localhost:18080"

echo "[*] Health still works"
curl -s "$BASE/health" | jq .

echo
echo "[*] Legitimate internal proxy path still works"
curl -s "$BASE/proxy-health" | jq .

echo
echo "[*] Explicit allowlisted proxy still works for the single intended URL"
curl -s "$BASE/proxy-allowlisted?target=http://internal-admin:5001/health" | jq .

echo
echo "[*] Direct SSRF should now be blocked"
status=$(curl -s -o /tmp/out1.json -w "%{http_code}" \
  "$BASE/fetch?url=http://internal-admin:5001/health")
echo "status=$status"
cat /tmp/out1.json | jq .

echo
echo "[*] Userinfo SSRF should now be blocked"
status=$(curl -s -o /tmp/out2.json -w "%{http_code}" \
  "$BASE/fetch?url=http://gateway@internal-admin:5001/health")
echo "status=$status"
cat /tmp/out2.json | jq .

echo
echo "[*] Redirect SSRF to internal health should now be blocked"
status=$(curl -s -o /tmp/out3.json -w "%{http_code}" \
  "$BASE/fetch?url=http://redirector:5002/to-admin-health")
echo "status=$status"
cat /tmp/out3.json | jq .

echo
echo "[*] Token-service discovery should now be blocked"
status=$(curl -s -o /tmp/out4.json -w "%{http_code}" \
  "$BASE/fetch?url=http://token-service:5003/.well-known/mesh")
echo "status=$status"
cat /tmp/out4.json | jq .

echo
echo "[*] Redirect SSRF to token mint should now be blocked"
status=$(curl -s -o /tmp/out5.json -w "%{http_code}" \
  "$BASE/fetch?url=http://redirector:5002/to-token-mint")
echo "status=$status"
cat /tmp/out5.json | jq .

echo
echo "[*] Legacy query-token export should no longer be usable through the gateway"
status=$(curl -s -o /tmp/out6.json -w "%{http_code}" \
  "$BASE/fetch?url=http://gateway@internal-admin:5001/admin/export?access_token=ring-export-token")
echo "status=$status"
cat /tmp/out6.json | jq .
