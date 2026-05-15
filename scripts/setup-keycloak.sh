#!/bin/bash
# ============================================================
#  Keycloak Realm Auto-Setup Script
#  Creates: myrealm, zta-client, testuser (role: admin)
# ============================================================

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:18080}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"

echo ">>> Keycloak Auto-Setup Starting..."
echo "    URL: $KEYCLOAK_URL"

# 1. Get Admin Token
echo ">>> Getting admin token..."
ADMIN_TOKEN=$(curl -s -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" \
  -d "username=$ADMIN_USER" \
  -d "password=$ADMIN_PASS" | jq -r '.access_token')

if [ "$ADMIN_TOKEN" == "null" ] || [ -z "$ADMIN_TOKEN" ]; then
  echo "    ❌ Failed to get admin token"
  exit 1
fi
echo "    ✔ Admin token obtained"

# 2. Create Realm: myrealm
echo ">>> Creating realm: myrealm..."
curl -s -X POST "$KEYCLOAK_URL/admin/realms" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "realm": "myrealm",
    "enabled": true,
    "registrationAllowed": false
  }' && echo "    ✔ Realm created" || echo "    (Realm may already exist)"

# 3. Create Client: zta-client
echo ">>> Creating client: zta-client..."
curl -s -X POST "$KEYCLOAK_URL/admin/realms/myrealm/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "zta-client",
    "enabled": true,
    "publicClient": false,
    "secret": "zta-secret",
    "directAccessGrantsEnabled": true,
    "serviceAccountsEnabled": false,
    "standardFlowEnabled": true,
    "redirectUris": ["*"],
    "webOrigins": ["*"]
  }' && echo "    ✔ Client created"

# 4. Create Role: admin
echo ">>> Creating realm role: admin..."
curl -s -X POST "$KEYCLOAK_URL/admin/realms/myrealm/roles" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "admin",
    "description": "Admin role for ZTA"
  }' && echo "    ✔ Role created"

# 5. Create User: testuser
echo ">>> Creating user: testuser..."
curl -s -X POST "$KEYCLOAK_URL/admin/realms/myrealm/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "enabled": true,
    "emailVerified": true,
    "credentials": [{
      "type": "password",
      "value": "testpass",
      "temporary": false
    }]
  }' && echo "    ✔ User created"

# 6. Get User ID
USER_ID=$(curl -s "$KEYCLOAK_URL/admin/realms/myrealm/users?username=testuser" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')

# 7. Assign admin role to testuser
echo ">>> Assigning admin role to testuser..."
ROLE_REPR=$(curl -s "$KEYCLOAK_URL/admin/realms/myrealm/roles/admin" \
  -H "Authorization: Bearer $ADMIN_TOKEN")

curl -s -X POST "$KEYCLOAK_URL/admin/realms/myrealm/users/$USER_ID/role-mappings/realm" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "[$ROLE_REPR]" && echo "    ✔ Role assigned"

echo ""
echo "=============================================="
echo "  ✅ Keycloak Setup Complete!"
echo "=============================================="
echo ""
echo "  Realm:    myrealm"
echo "  Client:   zta-client (secret: zta-secret)"
echo "  User:     testuser / testpass (role: admin)"
echo ""
echo "  Test token:"
echo "    curl -s -X POST '$KEYCLOAK_URL/realms/myrealm/protocol/openid-connect/token' \\"
echo "      -d 'grant_type=password' \\"
echo "      -d 'client_id=zta-client' \\"
echo "      -d 'client_secret=zta-secret' \\"
echo "      -d 'username=testuser' \\"
echo "      -d 'password=testpass'"
echo ""
