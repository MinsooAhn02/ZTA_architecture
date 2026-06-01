#!/usr/bin/env bash
# Fetch Keycloak JWT, caching per-user in .token-cache/ for 5 min.
# Usage: get-token.sh <username> <password>
# Prints raw access_token to stdout (no newline) and exits 0 on success.
set -euo pipefail

USER="${1:?usage: get-token.sh <user> <password>}"
PASS="${2:?usage: get-token.sh <user> <password>}"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:18080}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-myrealm}"
CACHE_DIR="${CACHE_DIR:-.token-cache}"
TTL_SEC=300

mkdir -p "$CACHE_DIR"
CACHE_FILE="$CACHE_DIR/${USER}.jwt"

if [ -s "$CACHE_FILE" ]; then
    # mtime-based TTL; portable across GNU/BSD stat via python3.
    AGE=$(python3 -c "import os,sys,time; print(int(time.time()-os.path.getmtime(sys.argv[1])))" "$CACHE_FILE")
    if [ "$AGE" -lt "$TTL_SEC" ]; then
        cat "$CACHE_FILE"
        exit 0
    fi
fi

TOKEN=$(curl -sf -X POST "$KEYCLOAK_URL/realms/$KEYCLOAK_REALM/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password" \
    -d "client_id=zta-client" \
    -d "client_secret=zta-secret" \
    -d "username=$USER" \
    -d "password=$PASS" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''),end='')")

if [ -z "$TOKEN" ]; then
    echo "ERROR: failed to obtain token for $USER" >&2
    exit 1
fi

printf '%s' "$TOKEN" > "$CACHE_FILE"
printf '%s' "$TOKEN"
