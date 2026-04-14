#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

JWKS_URL="http://localhost:8080/realms/myrealm/protocol/openid-connect/certs"
ISSUER="http://localhost:8080/realms/myrealm"

JWKS_JSON="$(curl -s "$JWKS_URL")"
if [[ -z "$JWKS_JSON" ]]; then
  echo "ERROR: failed to fetch JWKS from $JWKS_URL"
  exit 1
fi

cat > /tmp/jwt-auth-inline.yaml <<EOF
apiVersion: security.istio.io/v1
kind: RequestAuthentication
metadata:
  name: jwt-auth
  namespace: default
spec:
  selector:
    matchLabels:
      app: frontend
  jwtRules:
    - issuer: "$ISSUER"
      jwks: '$JWKS_JSON'
      forwardOriginalToken: true
EOF

kubectl apply -f /tmp/jwt-auth-inline.yaml
kubectl rollout restart deployment/frontend
kubectl rollout status deployment/frontend --timeout=180s

echo "Applied inline JWKS and restarted frontend."
