#!/usr/bin/env bash
set -euo pipefail

echo "=== Lateral Movement Attack Simulation ==="
echo "[Phase 1] Reconnaissance: discover backend service"

kubectl delete pod rogue-pod --ignore-not-found >/dev/null 2>&1 || true
kubectl run rogue-pod --image=curlimages/curl --restart=Never \
	--overrides='{"metadata":{"annotations":{"sidecar.istio.io/inject":"false"}}}' \
	--command -- sh -c "sleep 3600" >/dev/null
kubectl wait --for=condition=Ready pod/rogue-pod --timeout=90s >/dev/null

kubectl exec rogue-pod -- nslookup backend.default.svc.cluster.local || true

echo
echo "[Phase 2] Direct service access attempt"
kubectl exec rogue-pod -- curl -sv --max-time 5 http://backend/ || true

echo
echo "[Phase 3] Direct pod IP bypass attempt"
BACKEND_IP="$(kubectl get pod -l app=backend -o jsonpath='{.items[0].status.podIP}')"
echo "Backend pod IP: ${BACKEND_IP}"
kubectl exec rogue-pod -- sh -c "curl -sv --max-time 5 http://${BACKEND_IP}:8080" || true

echo
echo "[Result] If ZTA policies are active, both attempts should be blocked (403/refused)."

kubectl delete pod rogue-pod --ignore-not-found >/dev/null 2>&1 || true
