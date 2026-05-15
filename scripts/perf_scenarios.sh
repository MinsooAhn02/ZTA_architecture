#!/usr/bin/env sh
set -e

cd /mnt/c/Users/dksal/zta-project

make port-keycloak >/dev/null
make setup-keycloak-viewer >/dev/null

for i in $(seq 1 20); do
  if curl -s "http://localhost:18080/realms/myrealm" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

ADMIN_TOKEN=$(curl -s -X POST "http://localhost:18080/realms/myrealm/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" -d "client_id=zta-client" -d "client_secret=zta-secret" \
  -d "username=testuser" -d "password=testpass" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))")

VIEWER_TOKEN=$(curl -s -X POST "http://localhost:18080/realms/myrealm/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" -d "client_id=zta-client" -d "client_secret=zta-secret" \
  -d "username=vieweruser" -d "password=viewerpass" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))")

if [ -z "$ADMIN_TOKEN" ] || [ -z "$VIEWER_TOKEN" ]; then
  echo "ERROR: failed to retrieve JWTs from Keycloak"
  exit 1
fi

FORGED="eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmYWtlIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDoxODA4MC9yZWFsbXMvbXlyZWFsbSJ9.invalid"

if [ -n "$ADMIN_TOKEN" ]; then
  HEADER=$(echo "$ADMIN_TOKEN" | cut -d. -f1)
  SIG=$(echo "$ADMIN_TOKEN" | cut -d. -f3)
  TAMPERED_PAYLOAD=$(python3 -c "import base64,json; p={'sub':'tampered-user','realm_access':{'roles':['admin']}}; print(base64.urlsafe_b64encode(json.dumps(p,separators=(',',':')).encode()).decode().rstrip('='))")
  TAMPERED="$HEADER.$TAMPERED_PAYLOAD.$SIG"
else
  TAMPERED=""
fi

OUTCSV="evidence/perf-scenarios-latest.csv"
echo "case,category,method,path,expect,code,avg_ms,p99_ms,qps" > "$OUTCSV"

run_case() {
  name="$1"; category="$2"; method="$3"; path="$4"; expect="$5"; shift 5
  cmd="kubectl run fortio-$name --image=fortio/fortio --restart=Never --rm -i -- load -c 1 -qps 0 -n 200 -X $method"
  for h in "$@"; do
    cmd="$cmd -H \"$h\""
  done
  if [ "$method" = "POST" ]; then
    cmd="$cmd -payload '{\"data\":\"test\"}' -content-type \"application/json\""
  fi
  cmd="$cmd http://frontend$path"

  out=$(sh -c "$cmd" 2>&1 || true)
  echo "$out" > "evidence/perf-$name.txt"
  avg=$(echo "$out" | awk '/All done/ {print $8; exit}')
  qps=$(echo "$out" | awk '/All done/ {print $11; exit}')
  p99=$(echo "$out" | awk '/target 99%/ {print $4; exit}')
  p99_ms=$(awk -v s="$p99" 'BEGIN{if(s=="") printf ""; else printf "%.2f", s*1000}')
  code=$(echo "$out" | awk '/^Code/ {print $2; exit}')
  echo "$name,$category,$method,$path,$expect,$code,$avg,$p99_ms,$qps" >> "$OUTCSV"
}

run_case allow-admin-jwt allow GET /api/admin 200 "Authorization: Bearer $ADMIN_TOKEN"
run_case allow-viewer-jwt-data allow GET /api/data 200 "Authorization: Bearer $VIEWER_TOKEN"
run_case allow-role-user-data allow GET /api/data 200 "role: user"
run_case allow-posture-enabled allow GET /api/admin 200 "Authorization: Bearer $ADMIN_TOKEN" "X-Device-Firewall: enabled"

run_case block-no-identity block GET /api/admin 403
run_case block-forged-jwt block GET /api/admin 403 "Authorization: Bearer $FORGED"
run_case block-tampered-jwt block GET /api/admin 401 "Authorization: Bearer $TAMPERED"
run_case block-posture-disabled block GET /api/admin 403 "Authorization: Bearer $ADMIN_TOKEN" "X-Device-Firewall: disabled"

echo "Saved: $OUTCSV"
