# ============================================================
#  ZTA (Zero Trust Architecture) Project - Makefile
#  Based on NIST SP 800-207 | Keycloak + OPA + Istio
# ============================================================
#
#  Full Setup:      make setup
#  Step-by-Step:    make step1 / make step2 / make step3 / make step4
#  Individual:      make minikube-start / make minikube-stop / make istio-install / make istio-addons / make build-image / make rebuild-image / make deploy-app / make deploy-keycloak / make deploy-opa / make wait-pods / make patch-istio-mesh / make apply-authz / make apply-jwt-auth / make apply-microseg / make open-keycloak
#  Testing:         make test / make test-block / make test-pass / make get-token / make test-jwt / make test-fake / make test-lateral / make test-lateral-block / make test-lateral-sidecar / make test-all / make test-perf / make test-perf-baseline / make test-perf-zta
#  Monitoring:      make status / make dashboard / make grafana / make logs-frontend / make logs-backend / make logs-opa / make logs-keycloak
#  Cleanup:         make clean / make clean-all / make restart / make restart-app / make restart-opa /
#  System Check:    make check-status
#
# ============================================================

# ---------- Configuration Variables ----------
APP_IMAGE      := minsoo-app:v1
MINIKUBE_CPUS  := 4
MINIKUBE_MEM   := 8192
ISTIOCTL       := ./istio-1.28.3/bin/istioctl
NAMESPACE      := default
KEYCLOAK_REALM := myrealm

.PHONY: help setup step1 step2 step3 step4 \
        minikube-start minikube-stop istio-install istio-addons build-image rebuild-image \
        deploy-app deploy-keycloak deploy-opa wait-pods \
        patch-istio-mesh apply-authz apply-jwt-auth apply-microseg open-keycloak \
        test test-block test-pass get-token test-jwt test-fake \
        test-lateral test-lateral-block test-lateral-sidecar test-all \
        test-perf test-perf-baseline test-perf-zta \
        status dashboard grafana \
        logs-frontend logs-backend logs-opa logs-keycloak \
        clean clean-all restart restart-app restart-opa

# ============================================================
#  Help Menu
# ============================================================
help:
	@echo ""
	@echo "================================================================"
	@echo "  ZTA Project - Command List"
	@echo "================================================================"
	@echo ""
	@echo "  ▶ Full Automation"
	@echo "    make setup            Complete installation + deployment + policy (Phase 1~6)"
	@echo ""
	@echo "  ▶ Step-by-Step (Manual)"
	@echo "    make step1            Minikube + Istio + Addons + Build Image"
	@echo "    make step2            App + Keycloak + OPA Deployment"
	@echo "    make step3            Enable North-South Security Policies"
	@echo "    make step4            Enable East-West Micro-segmentation (Phase 6)"
	@echo ""
	@echo "  ▶ Individual Commands"
	@echo "    make minikube-start   Start Minikube only"
	@echo "    make istio-install    Install Istio (skip if exists)"
	@echo "    make istio-addons     Install Kiali/Prometheus/Grafana"
	@echo "    make build-image      Build App Docker image (skip if exists)"
	@echo "    make rebuild-image    Force rebuild App Docker image"
	@echo "    make deploy-app       Deploy Frontend + Backend"
	@echo "    make deploy-keycloak  Deploy Keycloak"
	@echo "    make deploy-opa       Deploy OPA"
	@echo "    make patch-istio-mesh Register OPA ext-authz in Istio mesh"
	@echo "    make apply-authz      Apply AuthorizationPolicy (Frontend)"
	@echo "    make apply-jwt-auth   Apply JWT Authentication Policy"
	@echo "    make apply-microseg   Apply Micro-segmentation Policies (Phase 6)"
	@echo ""
	@echo "  ▶ Testing - North-South (External → Internal)"
	@echo "    make test             Basic Block(403) + Pass(200) tests"
	@echo "    make test-block       Access without token → Expect 403"
	@echo "    make test-pass        Access with role:admin header → Expect 200"
	@echo "    make get-token        Issue JWT token from Keycloak"
	@echo "    make test-jwt         JWT + role:admin → Expect 200 (Requires TOKEN=<val>)"
	@echo "    make test-fake        Manipulated JWT → Expect 401"
	@echo ""
	@echo "  ▶ Testing - East-West (Lateral Movement Defense)"
	@echo "    make test-lateral          Full lateral movement defense test"
	@echo "    make test-lateral-block    Rogue Pod → Direct Backend access → Expect 403"
	@echo "    make test-lateral-sidecar  Sidecar Pod (wrong SA) → Backend → Expect 403"
	@echo ""
	@echo "  ▶ Testing - Full"
	@echo "    make test-all         North-South + East-West comprehensive test"
	@echo ""
	@echo "  ▶ Performance Measurement (Phase 7)"
	@echo "    make test-perf             Measure performance with policies ON (fortio)"
	@echo "    make test-perf-baseline    Measure Baseline performance (policies OFF)"
	@echo "    make test-perf-zta         Measure ZTA performance (policies ON)"
	@echo ""
	@echo "  ▶ Monitoring"
	@echo "    make status           Check Pod/Service status"
	@echo "    make dashboard        Launch Kiali Dashboard"
	@echo "    make grafana          Launch Grafana Dashboard"
	@echo "    make logs-frontend    Frontend logs"
	@echo "    make logs-backend     Backend logs"
	@echo "    make logs-opa         OPA logs"
	@echo "    make logs-keycloak    Keycloak logs"
	@echo ""
	@echo "  ▶ Cleanup"
	@echo "    make clean            Delete K8s resources (keep Istio/Minikube)"
	@echo "    make clean-all        Delete everything including Minikube"
	@echo ""
	@echo "================================================================"
	@echo ""
	@echo "  ▶ Intuitive System Check"
	@echo "    make check-status     One-glance check of URL, Kiali, Pod status, etc."

# ============================================================
#  Full Automation (One-shot setup)
# ============================================================
setup: step1 step2 step3 step4
	@echo ""
	@echo "=============================================="
	@echo "  ✅ ZTA Environment Setup Complete! (Phase 1~6)"
	@echo "=============================================="
	@echo ""
	@echo "  Next Steps:"
	@echo "    1. Configure Keycloak Realm (See Verification Guide)"
	@echo "       make open-keycloak"
	@echo "    2. Full Test"
	@echo "       make test-all"
	@echo "    3. Check Dashboard"
	@echo "       make dashboard"
	@echo ""

# ============================================================
#  Step 1: Environment Preparation
# ============================================================
step1: minikube-start istio-install istio-addons build-image
	@echo ""
	@echo ">>> [Step 1 Done] Minikube + Istio + Addons + Image Ready"
	@echo ""

minikube-start:
	@echo ">>> Checking Minikube status..."
	@if minikube status --format='{{.Host}}' 2>/dev/null | grep -q "Running" && \
	    minikube status --format='{{.APIServer}}' 2>/dev/null | grep -q "Running"; then \
		minikube update-context >/dev/null 2>&1 || true; \
		echo "    ✔ Minikube is already running (Skipping)"; \
	else \
		echo "    Starting Minikube..."; \
		minikube start --cpus $(MINIKUBE_CPUS) --memory $(MINIKUBE_MEM); \
		echo "    ✔ Minikube started successfully"; \
	fi

minikube-stop:
	@echo ">>> Stopping Minikube..."
	@minikube stop
	@echo "    ✔ Minikube stopped"

istio-install:
	@echo ">>> Checking Istio installation..."
	@if kubectl get deployment istiod -n istio-system >/dev/null 2>&1; then \
		echo "    ✔ Istio is already installed (Skipping)"; \
	else \
		echo "    Installing Istio (demo profile)..."; \
		$(ISTIOCTL) install --set profile=demo -y; \
		echo "    ✔ Istio installed successfully"; \
	fi
	@kubectl label namespace $(NAMESPACE) istio-injection=enabled --overwrite 2>/dev/null
	@echo "    ✔ Sidecar auto-injection enabled for namespace: $(NAMESPACE)"

istio-addons:
	@echo ">>> Checking Istio Addons (Kiali, Prometheus, Grafana)..."
	@if kubectl get deployment kiali -n istio-system >/dev/null 2>&1; then \
		echo "    ✔ Addons are already installed (Skipping)"; \
	else \
		echo "    Installing addons..."; \
		kubectl apply -f istio-1.28.3/samples/addons/prometheus.yaml 2>/dev/null || true; \
		kubectl apply -f istio-1.28.3/samples/addons/grafana.yaml 2>/dev/null || true; \
		kubectl apply -f istio-1.28.3/samples/addons/kiali.yaml 2>/dev/null || true; \
		echo "    ✔ Addons installed successfully"; \
	fi

build-image:
	@echo ">>> Checking App Docker image..."
	@eval $$(minikube docker-env) && \
	if docker image inspect $(APP_IMAGE) >/dev/null 2>&1; then \
		echo "    ✔ $(APP_IMAGE) image already exists (Skipping)"; \
		echo "      (Force rebuild: make rebuild-image)"; \
	else \
		echo "    Building image..."; \
		docker build -t $(APP_IMAGE) ./app/; \
		echo "    ✔ $(APP_IMAGE) image built successfully"; \
	fi

rebuild-image:
	@echo ">>> Force rebuilding App Docker image..."
	@eval $$(minikube docker-env) && docker build -t $(APP_IMAGE) ./app/
	@echo "    ✔ $(APP_IMAGE) image rebuilt successfully"

# ============================================================
#  Step 2: Service Deployment
# ============================================================
step2: deploy-app deploy-keycloak deploy-opa wait-pods
	@echo ""
	@echo ">>> [Step 2 Done] All services deployed"
	@echo ""

deploy-app:
	@echo ">>> Deploying Frontend + Backend..."
	@kubectl apply -f k8s/k8s-manifest.yaml
	@echo "    ✔ App deployment complete"

deploy-keycloak:
	@echo ">>> Deploying Keycloak (IdP)..."
	@kubectl apply -f k8s/keycloak.yaml
	@echo "    ✔ Keycloak deployment complete"

deploy-opa:
	@echo ">>> Deploying OPA (PDP)..."
	@kubectl apply -f k8s/opa-k8s.yaml
	@echo "    ✔ OPA deployment complete"

wait-pods:
	@echo ">>> Waiting for Pods to be ready (Max 3m)..."
	@kubectl wait --for=condition=Ready pod -l app=backend --timeout=180s 2>/dev/null || true
	@kubectl wait --for=condition=Ready pod -l app=frontend --timeout=180s 2>/dev/null || true
	@kubectl wait --for=condition=Ready pod -l app=keycloak --timeout=180s 2>/dev/null || true
	@kubectl wait --for=condition=Ready pod -l app=opa --timeout=180s 2>/dev/null || true
	@echo "    ✔ All Pods Ready"

# ============================================================
#  Step 3: Enable Security Policies
# ============================================================
step3: patch-istio-mesh apply-authz
	@echo ""
	@echo ">>> [Step 3 Done] North-South security policies enabled"
	@echo "    ⚠️  Access to Frontend without token/header will now be blocked (403)."
	@echo ""

# ============================================================
#  Step 4: East-West Micro-segmentation (Phase 6)
# ============================================================
step4: apply-microseg
	@echo ""
	@echo ">>> [Step 4 Done] Micro-segmentation enabled"
	@echo "    ✔ mTLS STRICT: Plaintext access from pods without sidecars blocked"
	@echo "    ✔ Backend RBAC: Only frontend-sa allowed to access backend"
	@echo "    ⚠️  Internal lateral movement is now restricted."
	@echo ""

apply-microseg:
	@echo ">>> Applying Micro-segmentation policies..."
	@kubectl apply -f k8s/peer-auth.yaml
	@echo "    ✔ PeerAuthentication (mTLS STRICT) applied"
	@kubectl apply -f k8s/authz-policy-backend.yaml
	@echo "    ✔ Backend AuthorizationPolicy applied"
	@echo "    ✔ Micro-segmentation policies applied successfully"

patch-istio-mesh:
	@echo ">>> Checking OPA ext-authz registration in Istio mesh config..."
	@if kubectl get configmap istio -n istio-system -o yaml 2>/dev/null | grep -q "opa-provider"; then \
		echo "    ✔ OPA provider is already registered (Skipping)"; \
	else \
		echo "    Registering OPA ext-authz provider..."; \
		kubectl get configmap istio -n istio-system -o json | \
		python3 -c "import sys,json,yaml; cm=json.load(sys.stdin); mesh=yaml.safe_load(cm['data']['mesh']); prov=[p for p in mesh.get('extensionProviders',[]) if p.get('name')!='opa-provider']; prov.append({'name':'opa-provider','envoyExtAuthzGrpc':{'service':'opa.default.svc.cluster.local','port':'9191'}}); mesh['extensionProviders']=prov; cm['data']['mesh']=yaml.dump(mesh,default_flow_style=False); json.dump(cm,sys.stdout)" \
		| kubectl replace -f -; \
		kubectl rollout restart deployment/istiod -n istio-system; \
		echo "    ⏳ Waiting for Istiod restart..."; \
		kubectl rollout status deployment/istiod -n istio-system --timeout=120s; \
		sleep 10; \
		echo "    ✔ OPA ext-authz provider registered successfully"; \
	fi

apply-authz:
	@echo ">>> Applying AuthorizationPolicy..."
	@kubectl wait --for=condition=Ready pod -l app=istiod -n istio-system --timeout=60s 2>/dev/null || true
	@kubectl apply -f k8s/authz-policy.yaml
	@echo "    ✔ AuthorizationPolicy applied successfully"

# ============================================================
#  JWT Related (Use after Keycloak Realm Setup)
# ============================================================
apply-jwt-auth:
	@echo ">>> Applying Keycloak JWT Authentication Policy..."
	@kubectl apply -f k8s/jwt-auth.yaml
	@echo "    ✔ RequestAuthentication applied successfully"
	@echo ""
	@echo "    ⚠️  Keycloak Realm '$(KEYCLOAK_REALM)' must be configured"
	@echo "       for JWT verification to work correctly."

open-keycloak:
	@echo ">>> Keycloak Admin Console URL:"
	@echo "    ID: admin / PW: admin"
	@minikube service keycloak --url

# ============================================================
#  Testing (Internal curl tests)
# ============================================================
test: test-block test-pass
	@echo ""
	@echo "=============================================="
	@echo "  ✅ Basic Tests Complete"
	@echo "=============================================="

test-block:
	@echo ""
	@echo ">>> [Test 1] Access without token → Expect 403 Forbidden"
	@echo "----------------------------------------------"
	@kubectl delete pod test-block --ignore-not-found 2>/dev/null || true
	@kubectl run test-block --image=curlimages/curl --restart=Never --rm -it \
		-- curl -s -o /dev/null -w "    Response Code: %{http_code}\n" http://frontend/ 2>/dev/null || true

test-pass:
	@echo ""
	@echo ">>> [Test 2] role:admin header → Expect 200 OK"
	@echo "----------------------------------------------"
	@kubectl delete pod test-pass --ignore-not-found 2>/dev/null || true
	@kubectl run test-pass --image=curlimages/curl --restart=Never --rm -it \
		-- curl -s -w "\n    Response Code: %{http_code}\n" -H "role: admin" http://frontend/ 2>/dev/null || true

get-token:
	@echo ""
	@echo ">>> Issuing JWT Token from Keycloak"
	@echo "----------------------------------------------"
	@kubectl delete pod get-token --ignore-not-found 2>/dev/null || true
	@kubectl run get-token --image=curlimages/curl --restart=Never --rm -it \
		-- curl -s -X POST \
		   http://keycloak:8080/realms/$(KEYCLOAK_REALM)/protocol/openid-connect/token \
		   -H "Content-Type: application/x-www-form-urlencoded" \
		   -d "grant_type=password" \
		   -d "client_id=zta-client" \
		   -d "username=testuser" \
		   -d "password=testpassword" 2>/dev/null || true
	@echo ""
	@echo "    Copy the 'access_token' value from the response above."
	@echo "    Usage: TOKEN=<token_value> make test-jwt"

test-jwt:
	@echo ""
	@echo ">>> [Test] JWT + role:admin → Expect 200 OK"
	@echo "----------------------------------------------"
	@if [ -z "$$TOKEN" ]; then \
		echo "    ❌ TOKEN environment variable is missing."; \
		echo "    Usage: TOKEN=eyJhbG... make test-jwt"; \
		exit 1; \
	fi
	@kubectl delete pod test-jwt --ignore-not-found 2>/dev/null || true
	@kubectl run test-jwt --image=curlimages/curl --restart=Never --rm -it \
		-- curl -s -w "\n    Response Code: %{http_code}\n" \
		   -H "Authorization: Bearer $$TOKEN" \
		   -H "role: admin" \
		   http://frontend/ 2>/dev/null || true

test-fake:
	@echo ""
	@echo ">>> [Test] Manipulated JWT → Expect 401 Unauthorized"
	@echo "----------------------------------------------"
	@kubectl delete pod test-fake --ignore-not-found 2>/dev/null || true
	@kubectl run test-fake --image=curlimages/curl --restart=Never --rm -it \
		-- curl -s -o /dev/null -w "    Response Code: %{http_code}\n" \
		   -H "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.invalid" \
		   -H "role: admin" \
		   http://frontend/ 2>/dev/null || true

# ============================================================
#  Testing - East-West Lateral Movement Defense (Phase 6)
# ============================================================
test-lateral: test-lateral-block test-lateral-sidecar
	@echo ""
	@echo "=============================================="
	@echo "  ✅ East-West Defense Tests Complete"
	@echo "=============================================="

test-lateral-block:
	@echo ""
	@echo ">>> [Lateral 1] Rogue Pod → Direct Backend access → Expect 403"
	@echo "----------------------------------------------"
	@kubectl delete pod test-lateral-block --ignore-not-found 2>/dev/null || true
	@kubectl run test-lateral-block --image=curlimages/curl --restart=Never --rm -it \
		-- curl -s -w "\n    Response Code: %{http_code}" --max-time 5 http://backend/ 2>/dev/null || true

test-lateral-sidecar:
	@echo ""
	@echo ">>> [Lateral 2] Sidecar Pod (wrong SA) → Backend → Expect 403"
	@echo "----------------------------------------------"
	@kubectl delete pod test-lateral-sidecar --ignore-not-found 2>/dev/null || true
	@kubectl run test-lateral-sidecar --image=curlimages/curl --restart=Never --rm -it \
		--overrides='{"spec":{"serviceAccountName":"backend-sa"}}' \
		-- curl -s -w "\n    Response Code: %{http_code}" --max-time 10 http://backend/ 2>/dev/null || true

# ============================================================
#  Full Test (North-South + East-West)
# ============================================================
test-all: test test-lateral
	@echo ""
	@echo "=============================================="
	@echo "  ✅ All Tests Complete (North-South + East-West)"
	@echo "=============================================="

# ============================================================
#  Performance Measurement (Phase 7) - Using fortio
# ============================================================
test-perf:
	@echo ""
	@echo ">>> Performance Test (ZTA Policies ON)"
	@echo "=============================================="
	@kubectl delete pod fortio-test --ignore-not-found 2>/dev/null || true
	@kubectl run fortio-test --image=fortio/fortio --restart=Never --rm -it \
		-- fortio load -c 1 -qps 0 -n 200 -H "role: admin" http://frontend/ 2>/dev/null || true

test-perf-baseline:
	@echo ""
	@echo ">>> Baseline Performance Test (Policies OFF)"
	@echo "    ⚠️  Run this in a clean state (after make clean)"
	@echo "=============================================="
	@kubectl delete pod fortio-baseline --ignore-not-found 2>/dev/null || true
	@kubectl run fortio-baseline --image=fortio/fortio --restart=Never --rm -it \
		-- fortio load -c 1 -qps 0 -n 200 http://frontend/ 2>/dev/null || true

test-perf-zta:
	@echo ""
	@echo ">>> ZTA Performance Test (Policies ON)"
	@echo "    ⚠️  Run this after applying policies (make step3 && make step4)"
	@echo "=============================================="
	@kubectl delete pod fortio-zta --image=fortio/fortio --restart=Never --rm -it \
		-- fortio load -c 1 -qps 0 -n 200 -H "role: admin" http://frontend/ 2>/dev/null || true

# ============================================================
#  Monitoring
# ============================================================
status:
	@echo ""
	@echo ">>> Cluster Status"
	@echo "=============================================="
	@echo ""
	@echo "[Pods]"
	@kubectl get pods -n $(NAMESPACE) -o wide
	@echo ""
	@echo "[Services]"
	@kubectl get svc -n $(NAMESPACE)
	@echo ""
	@echo "[Istio Sidecar Verification]"
	@kubectl get pods -n $(NAMESPACE) -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{range .spec.containers[*]}{.name}{" "}{end}{"\n"}{end}'
	@echo ""

dashboard:
	@echo ">>> Launching Kiali Dashboard (using istioctl)..."
	@$(ISTIOCTL) dashboard kiali

grafana:
	@echo ">>> Launching Grafana Dashboard (using istioctl)..."
	@$(ISTIOCTL) dashboard grafana

logs-frontend:
	@kubectl logs -l app=frontend -c frontend --tail=50 -f

logs-backend:
	@kubectl logs -l app=backend -c backend --tail=50 -f

logs-opa:
	@kubectl logs -l app=opa --tail=50 -f

logs-keycloak:
	@kubectl logs -l app=keycloak --tail=50 -f

# ============================================================
#  Cleanup
# ============================================================
clean:
	@echo ">>> Deleting K8s resources..."
	@kubectl delete -f k8s/authz-policy-backend.yaml --ignore-not-found
	@kubectl delete -f k8s/peer-auth.yaml --ignore-not-found
	@kubectl delete -f k8s/authz-policy.yaml --ignore-not-found
	@kubectl delete -f k8s/jwt-auth.yaml --ignore-not-found
	@kubectl delete -f k8s/opa-k8s.yaml --ignore-not-found
	@kubectl delete -f k8s/keycloak.yaml --ignore-not-found
	@kubectl delete -f k8s/k8s-manifest.yaml --ignore-not-found
	@echo "    ✔ Resources deleted (Istio/Minikube retained)"

clean-all: clean
	@echo ">>> Uninstalling Istio..."
	@$(ISTIOCTL) uninstall --purge -y 2>/dev/null || true
	@kubectl delete namespace istio-system --ignore-not-found 2>/dev/null || true
	@echo ">>> Deleting Minikube..."
	@minikube delete
	@echo "    ✔ Full environment deleted"

# ============================================================
#  Utilities
# ============================================================
restart: restart-app restart-opa

restart-app:
	@echo ">>> Restarting apps..."
	@kubectl rollout restart deployment/frontend deployment/backend
	@kubectl rollout status deployment/frontend --timeout=60s
	@kubectl rollout status deployment/backend --timeout=60s

restart-opa:
	@echo ">>> Restarting OPA..."
	@kubectl rollout restart deployment/opa
	@kubectl rollout status deployment/opa --timeout=60s

# ============================================================
#  System Check (Intuitive Glance)
# ============================================================
check-status:
	@echo "\n==============================="
	@echo "[Kiali Dashboard Launch Command]"
	@echo "-------------------------------"
	@echo "  make dashboard"
	@echo "  (Or run directly: $(ISTIOCTL) dashboard kiali)"

	@echo "\n[2] All Pods Running Status"
	@echo "-------------------------------"
	@kubectl get pods -n $(NAMESPACE) -o wide

	@echo "\n[3] Istio Sidecar Injection Verification"
	@echo "-------------------------------"
	@kubectl get pods -n $(NAMESPACE) -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{range .spec.containers[*]}{.name}{" "}{end}{"\n"}{end}' | grep istio-proxy || echo "    (Some pods missing sidecars)"

	@echo "\n[4] Grafana Dashboard Launch Command"
	@echo "-------------------------------"
	@echo "  make grafana"
	@echo "  (Or run directly: $(ISTIOCTL) dashboard grafana)"

	@echo "\n[5] Check Complete"
	@echo "-------------------------------"
	@echo "  ✅ System check finished"
