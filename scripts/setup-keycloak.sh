#!/usr/bin/env bash
# Keycloak Realm Auto-Setup (idempotent).
# Creates: realm myrealm, client zta-client, role admin, user testuser/testpass.
# Re-invocations are no-ops once entities exist.
#
# Env:
#   KEYCLOAK_URL    (default http://localhost:18080)
#   KEYCLOAK_REALM  (default myrealm)
#   ADMIN_USER      (default admin)
#   ADMIN_PASS      (default admin)
set -uo pipefail

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:18080}"
REALM="${KEYCLOAK_REALM:-myrealm}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"

PY_JSON_FIELD='import sys,json
try: d=json.load(sys.stdin)
except: d={}
print(d.get(sys.argv[1],"") if isinstance(d,dict) else "")'

PY_JSON_FIRST_ID='import sys,json
try: d=json.load(sys.stdin)
except: d=[]
print(d[0]["id"] if isinstance(d,list) and d else "")'

echo ">>> Keycloak setup — URL: $KEYCLOAK_URL realm: $REALM"

# Idempotency: skip everything if realm already exists.
if curl -sf "$KEYCLOAK_URL/realms/$REALM" >/dev/null 2>&1; then
    echo "    Realm '$REALM' already exists — skipping."
    echo "    Run setup-keycloak-viewer (Makefile) to add viewer user for Scenario D."
    exit 0
fi

# 1. Admin token
ADMIN_TOKEN=$(curl -s -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
    -d "grant_type=password" -d "client_id=admin-cli" \
    -d "username=$ADMIN_USER" -d "password=$ADMIN_PASS" \
    | python3 -c "$PY_JSON_FIELD" access_token)

if [ -z "$ADMIN_TOKEN" ]; then
    echo "    ERROR: cannot reach Keycloak. Run 'make port-keycloak'." >&2
    exit 1
fi

H_AUTH=(-H "Authorization: Bearer $ADMIN_TOKEN")
H_JSON=(-H "Content-Type: application/json")

# 2. Realm
echo "    Creating realm..."
curl -s -X POST "$KEYCLOAK_URL/admin/realms" \
    "${H_AUTH[@]}" "${H_JSON[@]}" \
    -d "{\"realm\":\"$REALM\",\"enabled\":true}" >/dev/null

# 3. Client
echo "    Creating client zta-client..."
curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM/clients" \
    "${H_AUTH[@]}" "${H_JSON[@]}" \
    -d '{"clientId":"zta-client","enabled":true,"publicClient":false,"secret":"zta-secret","directAccessGrantsEnabled":true}' >/dev/null

# 4. Role admin
echo "    Creating role admin..."
curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM/roles" \
    "${H_AUTH[@]}" "${H_JSON[@]}" -d '{"name":"admin"}' >/dev/null

# 5. User testuser
echo "    Creating user testuser..."
curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM/users" \
    "${H_AUTH[@]}" "${H_JSON[@]}" \
    -d '{"username":"testuser","enabled":true,"credentials":[{"type":"password","value":"testpass","temporary":false}]}' >/dev/null

# 6. Assign admin role
USER_ID=$(curl -s "$KEYCLOAK_URL/admin/realms/$REALM/users?username=testuser" \
    "${H_AUTH[@]}" | python3 -c "$PY_JSON_FIRST_ID")
ROLE_REPR=$(curl -s "$KEYCLOAK_URL/admin/realms/$REALM/roles/admin" "${H_AUTH[@]}")
if [ -n "$USER_ID" ] && [ -n "$ROLE_REPR" ]; then
    curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM/users/$USER_ID/role-mappings/realm" \
        "${H_AUTH[@]}" "${H_JSON[@]}" -d "[$ROLE_REPR]" >/dev/null
    echo "    Assigned admin role to testuser."
fi

echo ""
echo "    Setup complete: testuser / testpass (role admin)"
echo "    Next: make setup-keycloak-viewer (for Scenario D viewer user)"
