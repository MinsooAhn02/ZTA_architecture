#!/usr/bin/env bash
set -euo pipefail

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="${REALM:-myrealm}"
CLIENT_ID="${CLIENT_ID:-zta-client}"
CLIENT_SECRET="${CLIENT_SECRET:-zta-secret}"
USERNAME="${USERNAME:-testuser}"
PASSWORD="${PASSWORD:-testpass}"

echo "=== JWT Forgery / Tampering Simulation ==="
echo "[Phase 1] Obtain a real JWT from Keycloak"

REAL_TOKEN="$(curl -s -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "username=${USERNAME}" \
  -d "password=${PASSWORD}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))")"

if [[ -z "${REAL_TOKEN}" ]]; then
  echo "ERROR: could not obtain token. Start Keycloak port-forward first: make port-keycloak"
  exit 1
fi

echo
echo "[Phase 2] Show real JWT header/payload"
TOKEN="${REAL_TOKEN}" python3 - <<'PY'
import os, json, base64

def b64d(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4)).decode()

token = os.environ['TOKEN']
h, p, _ = token.split('.')
print('Header :', b64d(h))
print('Payload:', b64d(p))
PY

echo
echo "[Phase 3] Tamper payload but keep original signature"
TAMPERED_TOKEN="$(TOKEN="${REAL_TOKEN}" python3 - <<'PY'
import os, json, base64

def b64d(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4)).decode()

def b64e(obj):
    raw = json.dumps(obj, separators=(',', ':')).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')

token = os.environ['TOKEN']
h, p, s = token.split('.')
payload = json.loads(b64d(p))
roles = payload.get('realm_access', {}).get('roles', [])
if 'admin' not in roles:
    roles.append('admin')
payload.setdefault('realm_access', {})['roles'] = roles
payload['sub'] = 'tampered-user'
print(f"{h}.{b64e(payload)}.{s}")
PY
)"

echo "Tampered token prepared. Sending request to /api/admin ..."
kubectl delete pod attack-jwt-tampered --ignore-not-found >/dev/null 2>&1 || true
kubectl run attack-jwt-tampered --image=curlimages/curl --restart=Never --rm -i \
  -- curl -s -o /dev/null -w "Tampered token HTTP: %{http_code}\n" \
  -H "Authorization: Bearer ${TAMPERED_TOKEN}" \
  http://frontend/api/admin || true

echo
echo "[Control] Real token request"
kubectl delete pod attack-jwt-real --ignore-not-found >/dev/null 2>&1 || true
kubectl run attack-jwt-real --image=curlimages/curl --restart=Never --rm -i \
  -- curl -s -o /dev/null -w "Real token HTTP: %{http_code}\n" \
  -H "Authorization: Bearer ${REAL_TOKEN}" \
  http://frontend/api/admin || true

echo
echo "[Result] Tampered token should return 401 if JWT signature validation is active."
