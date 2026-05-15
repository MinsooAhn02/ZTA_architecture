#!/usr/bin/env bash
set -euo pipefail

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:18080}"
REALM="${REALM:-myrealm}"
CLIENT_ID="${CLIENT_ID:-zta-client}"
CLIENT_SECRET="${CLIENT_SECRET:-zta-secret}"
USERNAME="${USERNAME:-testuser}"
PASSWORD="${PASSWORD:-testpass}"

echo "=== Device Posture Simulation ==="
echo "Scenario: stolen valid credential + unhealthy device posture"

TOKEN="$(curl -s -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "username=${USERNAME}" \
  -d "password=${PASSWORD}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))")"

if [[ -z "${TOKEN}" ]]; then
  echo "ERROR: could not obtain token. Start Keycloak port-forward first: make port-keycloak"
  exit 1
fi

echo
echo "[Attempt 1] Healthy device posture (X-Device-Firewall: enabled)"
kubectl delete pod attack-posture-ok --ignore-not-found >/dev/null 2>&1 || true
kubectl run attack-posture-ok --image=curlimages/curl --restart=Never --rm -i \
  -- curl -s -o /dev/null -w "HTTP: %{http_code}\n" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "X-Device-Firewall: enabled" \
  http://frontend/api/admin || true

echo
echo "[Attempt 2] Unhealthy posture (X-Device-Firewall: disabled)"
kubectl delete pod attack-posture-block --ignore-not-found >/dev/null 2>&1 || true
kubectl run attack-posture-block --image=curlimages/curl --restart=Never --rm -i \
  -- curl -s -o /dev/null -w "HTTP: %{http_code}\n" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "X-Device-Firewall: disabled" \
  http://frontend/api/admin || true

echo
echo "[Result] enabled should be 200, disabled should be 403."
