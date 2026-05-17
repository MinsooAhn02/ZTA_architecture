# ============================================================
#  ZTA (Zero Trust Architecture) Project - Makefile
#  Based on NIST SP 800-207 | Keycloak + OPA + Istio
# ============================================================
#
#  Quick Start
#  ─────────────────────────────────────
#    make all        → Full install + deploy + policies (first time)
#    make test-all   → Run all security tests (A, B, C, D, E)
#    make demo       → Run storytelling demo flow (A~E)
#    make ports      → Start all port-forwards (background)
#    make status     → Check current status
#
#  Test Scenarios
#  ─────────────────────────────────────
#    make test           Scenario A/B: North-South (block/pass)
#    make test-lateral   Scenario A: Lateral Movement defense
#    make test-fake      Scenario B: JWT forgery → 403
#    make test-jwt-tampered  Scenario B: Real JWT payload tamper → 401
#    make test-jwt-auto  Scenario B: Valid JWT → 200
#    make test-context   Scenario C: Context-based (role+method+path)
#    make test-jwt-role  Scenario D: JWT role claim access control
#    make test-posture   Scenario E: Device posture check
#    make test-all       All scenarios A+B+C+D+E
#
#  Monitoring Helpers
#  ─────────────────────────────────────
#    make logs          Raw OPA decision logs
#    make logs-pretty   Parsed OPA decision summary
#
# ============================================================

# ---------- Configuration ----------
APP_IMAGE      := minsoo-app:v1
MINIKUBE_CPUS  := 4
MINIKUBE_MEM   := 8192
ISTIOCTL       := ./istio-1.28.3/bin/istioctl
NAMESPACE      := default
KEYCLOAK_REALM := myrealm
KEYCLOAK_URL   := http://localhost:18080
TEST_SUMMARY_FILE := .test-summary.log

.PHONY: for_pdf \
        all help status test-all clean \
        setup step1 step2 step3 step4 \
        minikube-start minikube-stop \
        istio-install istio-addons \
        build-image rebuild-image \
	prepare-summary print-summary \
        deploy-app deploy-keycloak deploy-opa deploy-all wait-pods \
        patch-istio-mesh apply-authz apply-jwt apply-microseg jwt-refresh \
        setup-keycloak setup-keycloak-viewer open-keycloak open-kiali open-grafana \
        get-token get-token-viewer \
	test test-block test-pass test-jwt test-jwt-auto test-fake test-jwt-tampered \
        test-lateral test-lateral-block test-lateral-sidecar test-lateral-podip \
        test-context test-context-user-get test-context-user-admin \
        test-context-user-post test-context-admin-post \
        test-jwt-role test-jwt-admin-all test-jwt-viewer-read \
        test-jwt-viewer-admin test-jwt-viewer-post \
	test-posture test-posture-ok test-posture-block \
	demo demo-lateral demo-jwt demo-context demo-jwt-role demo-posture demo-compare \
        test-perf test-perf-baseline test-perf-zta \
        ports ports-win ensure-ports port-keycloak port-kiali port-grafana ports-stop \
	dashboard grafana logs logs-opa logs-frontend logs-backend logs-keycloak logs-pretty \
        clean-all restart \
	visualizer view viz _viz-inner

# ============================================================
#  Quick Start Commands
# ============================================================

all: setup ports
	@echo ""
	@echo "=============================================="
	@echo "  ZTA Environment Setup Complete!"
	@echo "=============================================="
	@echo ""
	@echo "  Port-forwards started in background:"
	@echo "    - Keycloak: http://localhost:18080"
	@echo "    - Kiali:    http://localhost:20000"
	@echo "    - Grafana:  http://localhost:20002"
	@echo ""
	@echo "  Next steps:"
	@echo "    make setup-keycloak-viewer  -> Add viewer user (for Scenario D)"
	@echo "    make test-all               -> Run all tests (Scenario A~E)"
	@echo "    make status                 -> Check status"
	@echo ""

# All tests: Scenario A + B + C + D + E(device posture)
test-all: ensure-ports prepare-summary jwt-refresh setup-keycloak-viewer
	@echo ""
	@echo "=============================================================="
	@echo "RUNNING ALL TESTS (A~E)"
	@echo "- Each test prints REQUEST / EXPECT / RESULT / STATUS"
	@echo "- Final section prints consolidated summary table"
	@echo "=============================================================="
	@FAIL=0; \
	for t in test test-lateral test-fake test-jwt-tampered test-jwt-auto test-context test-jwt-role test-posture; do \
		echo ""; \
		echo ">>> Running $$t"; \
		if ! $(MAKE) --no-print-directory $$t; then \
			FAIL=$$((FAIL+1)); \
		fi; \
	done; \
	$(MAKE) --no-print-directory print-summary; \
	echo ""; \
	if [ $$FAIL -gt 0 ]; then \
		echo "FINAL: FAIL ($$FAIL group/step failed)"; \
		exit 1; \
	else \
		echo "FINAL: PASS (all groups matched expected result)"; \
	fi

status:
	@echo ""
	@echo "=============================================="
	@echo "  ZTA Cluster Status"
	@echo "=============================================="
	@echo ""
	@echo "[Pods]"
	@kubectl get pods -o wide 2>/dev/null || echo "  (Cluster not connected)"
	@echo ""
	@echo "[Services]"
	@kubectl get svc 2>/dev/null || true
	@echo ""
	@echo "[Security Policies]"
	@kubectl get authorizationpolicy,peerauthentication,requestauthentication 2>/dev/null || true
	@echo ""

prepare-summary:
	@rm -f $(TEST_SUMMARY_FILE)
	@touch $(TEST_SUMMARY_FILE)

print-summary:
	@echo ""
	@echo "=============================================================="
	@echo "FINAL SUMMARY (EXPECT vs RESULT)"
	@echo "=============================================================="
	@if [ ! -s $(TEST_SUMMARY_FILE) ]; then \
		echo "No test records found in $(TEST_SUMMARY_FILE)"; \
		exit 0; \
	fi
	@printf "%-36s | %-10s | %-10s | %-6s\n" "CASE" "EXPECT" "RESULT" "STATUS"
	@echo "--------------------------------------------------------------------------"
	@while IFS='|' read -r CASE EXPECT RESULT STATUS DETAIL; do \
		printf "%-36s | %-10s | %-10s | %-6s\n" "$$CASE" "$$EXPECT" "$$RESULT" "$$STATUS"; \
		echo "  detail: $$DETAIL"; \
	done < $(TEST_SUMMARY_FILE)
	@echo "--------------------------------------------------------------------------"

# ============================================================
#  Help
# ============================================================
help:
	@echo ""
	@echo "=============================================="
	@echo "  ZTA Project - Command Reference"
	@echo "=============================================="
	@echo ""
	@echo "  Quick Start"
	@echo "  ─────────────────────────────────────"
	@echo "    make all              Full install + deploy + policies + ports"
	@echo "    make test-all         Run ALL tests (Scenario A ~ E)"
	@echo "    make status           Check current status"
	@echo ""
	@echo "  Installation"
	@echo "  ─────────────────────────────────────"
	@echo "    make step1            Minikube + Istio + Addons + Image"
	@echo "    make step2            Deploy App + Keycloak + OPA"
	@echo "    make step3            Apply North-South policies"
	@echo "    make step4            Apply East-West micro-segmentation"
	@echo ""
	@echo "  Scenario A: North-South + Lateral Movement"
	@echo "  ─────────────────────────────────────"
	@echo "    make test-block           No token -> 403"
	@echo "    make test-pass            role:admin header -> 200"
	@echo "    make test-lateral-block   Rogue pod -> backend -> 403"
	@echo "    make test-lateral-sidecar Wrong SA -> backend -> 403"
	@echo "    make test-lateral-podip   Rogue pod -> backend podIP:8080 -> 403/000"
	@echo ""
	@echo "  Scenario B: JWT Authentication"
	@echo "  ─────────────────────────────────────"
	@echo "    make jwt-refresh         Force JWKS sync + verifier refresh"
	@echo "    make test-fake            Forged JWT -> 403"
	@echo "    make test-jwt-tampered    Real JWT payload tampered -> 401"
	@echo "    make test-jwt-auto        Valid Keycloak JWT -> 200"
	@echo "    make test-jwt             Manual token: TOKEN=xxx make test-jwt"
	@echo ""
	@echo "  Scenario C: Context-Based Access Control [NEW]"
	@echo "  ─────────────────────────────────────"
	@echo "    make test-context             Run all context tests"
	@echo "    make test-context-user-get    role:user + GET /api/data -> 200"
	@echo "    make test-context-user-admin  role:user + GET /api/admin -> 403"
	@echo "    make test-context-user-post   role:user + POST /api/write -> 403"
	@echo "    make test-context-admin-post  role:admin + POST /api/write -> 200"
	@echo ""
	@echo "  Scenario D: JWT Role Claim Access Control [NEW]"
	@echo "  ─────────────────────────────────────"
	@echo "    make test-jwt-role            Run all JWT role tests"
	@echo "    make test-jwt-admin-all       Admin JWT -> /api/admin -> 200"
	@echo "    make test-jwt-viewer-read     Viewer JWT -> /api/data -> 200"
	@echo "    make test-jwt-viewer-admin    Viewer JWT -> /api/admin -> 403"
	@echo "    make test-jwt-viewer-post     Viewer JWT -> POST /api/write -> 403"
	@echo ""
	@echo "  Scenario E: Device Posture (PDF gap close)"
	@echo "  ─────────────────────────────────────"
	@echo "    make test-posture          Run posture tests"
	@echo "    make test-posture-ok       admin JWT + firewall=enabled -> 200"
	@echo "    make test-posture-block    admin JWT + firewall=disabled -> 403"
	@echo ""
	@echo "  Demo (Storytelling)"
	@echo "  ─────────────────────────────────────"
	@echo "    make demo                  Full scenario demo (A~E)"
	@echo "    make demo-lateral          Lateral movement only"
	@echo "    make demo-jwt              JWT fake+tampers+valid"
	@echo "    make demo-context          Context-based only"
	@echo "    make demo-jwt-role         JWT role-claim only"
	@echo "    make demo-posture          Device posture only"
	@echo "    make demo-compare          Print ZTA vs baseline evidence"
	@echo ""
	@echo "  Keycloak"
	@echo "  ─────────────────────────────────────"
	@echo "    make setup-keycloak        Create Realm/Client/testuser (admin)"
	@echo "    make setup-keycloak-viewer Add vieweruser (viewer role)"
	@echo "    make get-token             JWT for testuser (admin)"
	@echo "    make get-token-viewer      JWT for vieweruser (viewer)"
	@echo ""
	@echo "  Performance"
	@echo "  ─────────────────────────────────────"
	@echo "    make test-perf            Performance with ZTA ON"
	@echo "    make test-perf-baseline   Baseline (run make clean first)"
	@echo ""
	@echo "  Monitoring"
	@echo "  ─────────────────────────────────────"
	@echo "    make open-kiali       Kiali service graph"
	@echo "    make open-grafana     Grafana latency dashboard"
	@echo "    make open-keycloak    Keycloak admin console"
	@echo "    make logs             OPA decision logs (live)"
	@echo ""
	@echo "  Cleanup"
	@echo "  ─────────────────────────────────────"
	@echo "    make clean            Delete K8s resources (keep Istio)"
	@echo "    make clean-all        Delete everything including Minikube"
	@echo "    make ports-stop       Stop all port-forwards"
	@echo ""

# ============================================================
#  Installation Steps
# ============================================================
setup: step1 step2 step3 step4

step1: minikube-start istio-install istio-addons build-image
	@echo ">>> [Step 1] Infrastructure ready"

step2: deploy-all wait-pods
	@echo ">>> [Step 2] Services deployed"

step3: patch-istio-mesh apply-authz
	@echo ">>> [Step 3] North-South policies applied"

step4: apply-microseg apply-jwt ensure-ports setup-keycloak
	@echo ">>> [Step 4] East-West + JWT policies applied (Keycloak configured)"

# ---------- Step 1 Details ----------
minikube-start:
	@echo ">>> Starting Minikube..."
	@if minikube status --format='{{.Host}}' 2>/dev/null | grep -q "Running"; then \
		if kubectl version --request-timeout=5s >/dev/null 2>&1; then \
			echo "    Already running (Skip)"; \
		else \
			echo "    Minikube is running but Kubernetes API is unreachable. Restarting..."; \
			minikube stop || true; \
			minikube start --cpus $(MINIKUBE_CPUS) --memory $(MINIKUBE_MEM); \
		fi; \
	else \
		minikube start --cpus $(MINIKUBE_CPUS) --memory $(MINIKUBE_MEM); \
	fi
	@minikube update-context

minikube-stop:
	@minikube stop

istio-install:
	@echo ">>> Installing Istio..."
	@if kubectl get deployment istiod -n istio-system >/dev/null 2>&1; then \
		echo "    Already installed (Skip)"; \
	else \
		$(ISTIOCTL) install --set profile=demo -y; \
	fi
	@kubectl label namespace $(NAMESPACE) istio-injection=enabled --overwrite 2>/dev/null || true

istio-addons:
	@echo ">>> Installing Istio Addons (Kiali, Prometheus, Grafana)..."
	@if kubectl get deployment kiali -n istio-system >/dev/null 2>&1; then \
		echo "    Already installed (Skip)"; \
	else \
		kubectl apply -f istio-1.28.3/samples/addons/ 2>/dev/null || true; \
	fi

build-image:
	@echo ">>> Building Docker image..."
	@eval $$(minikube docker-env) && \
	if docker image inspect $(APP_IMAGE) >/dev/null 2>&1; then \
		echo "    Image exists (Skip, force: make rebuild-image)"; \
	else \
		docker build -t $(APP_IMAGE) ./app/; \
	fi

rebuild-image:
	@eval $$(minikube docker-env) && docker build -t $(APP_IMAGE) ./app/

# ---------- Step 2 Details ----------
deploy-all: deploy-app deploy-keycloak deploy-opa

deploy-app:
	@echo ">>> Deploying Frontend + Backend..."
	@kubectl apply -f k8s/k8s-manifest.yaml

deploy-keycloak:
	@echo ">>> Deploying Keycloak..."
	@kubectl apply -f k8s/keycloak.yaml

deploy-opa:
	@echo ">>> Deploying OPA..."
	@kubectl apply -f k8s/opa-k8s.yaml

wait-pods:
	@echo ">>> Waiting for Pods to be ready (max 3min)..."
	@kubectl wait --for=condition=Ready pod -l app=backend --timeout=180s 2>/dev/null || true
	@kubectl wait --for=condition=Ready pod -l app=frontend --timeout=180s 2>/dev/null || true
	@kubectl wait --for=condition=Ready pod -l app=keycloak --timeout=180s 2>/dev/null || true
	@kubectl wait --for=condition=Ready pod -l app=opa --timeout=180s 2>/dev/null || true
	@echo "    All Pods ready"

# ---------- Step 3 Details ----------
patch-istio-mesh:
	@echo ">>> Registering OPA ext-authz..."
	@if kubectl get configmap istio -n istio-system -o yaml 2>/dev/null | grep -q "opa-provider"; then \
		echo "    Already registered (Skip)"; \
	else \
		kubectl get configmap istio -n istio-system -o json | \
		python3 -c "import sys,json,yaml; cm=json.load(sys.stdin); mesh=yaml.safe_load(cm['data']['mesh']); prov=[p for p in mesh.get('extensionProviders',[]) if p.get('name')!='opa-provider']; prov.append({'name':'opa-provider','envoyExtAuthzGrpc':{'service':'opa.default.svc.cluster.local','port':'9191'}}); mesh['extensionProviders']=prov; cm['data']['mesh']=yaml.dump(mesh,default_flow_style=False); json.dump(cm,sys.stdout)" \
		| kubectl replace -f -; \
		kubectl rollout restart deployment/istiod -n istio-system; \
		kubectl rollout status deployment/istiod -n istio-system --timeout=120s; \
	fi

apply-authz:
	@echo ">>> Applying AuthorizationPolicy..."
	@kubectl apply -f k8s/authz-policy.yaml

# ---------- Step 4 Details ----------
apply-microseg:
	@echo ">>> Applying Micro-segmentation..."
	@kubectl apply -f k8s/peer-auth.yaml
	@kubectl apply -f k8s/authz-policy-backend.yaml

apply-opa-network-policy:
	@echo ">>> Applying OPA NetworkPolicy (restricts gRPC port 9191 to mesh-internal only)..."
	@echo "    Note: requires CNI with NetworkPolicy support (Calico). Skipped on default Minikube."
	@kubectl apply -f k8s/opa-network-policy.yaml 2>/dev/null || echo "    NetworkPolicy not applied (CNI may not support it)"

apply-jwt:
	@echo ">>> Applying JWT authentication policy..."
	@kubectl apply -f k8s/jwt-auth.yaml
	@-kubectl apply -f k8s/jwt-require-policy.yaml 2>/dev/null || true

jwt-refresh:
	@echo ">>> Refreshing JWT verifier state (JWKS sync + Istio/frontend restart)..."
	@bash scripts/apply-jwt-inline-jwks.sh
	@kubectl rollout restart deployment/istiod -n istio-system
	@kubectl rollout status deployment/istiod -n istio-system --timeout=240s

# ============================================================
#  Keycloak
# ============================================================

setup-keycloak:
	@echo ">>> Keycloak Auto-Setup (myrealm, zta-client, testuser/admin)..."
	@REALM_CHECK=$$(curl -s "$(KEYCLOAK_URL)/realms/$(KEYCLOAK_REALM)" 2>/dev/null | grep -o '"realm":"$(KEYCLOAK_REALM)"' | wc -l); \
	if [ "$$REALM_CHECK" != "0" ]; then \
		echo "    Realm '$(KEYCLOAK_REALM)' already exists (Skip)"; \
		echo "    Run 'make setup-keycloak-viewer' to add viewer user for Scenario D"; \
	else \
		echo "    Creating realm..."; \
		ADMIN_TOKEN=$$(curl -s -X POST "$(KEYCLOAK_URL)/realms/master/protocol/openid-connect/token" \
			-d "grant_type=password" -d "client_id=admin-cli" -d "username=admin" -d "password=admin" \
			| python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))"); \
		if [ -z "$$ADMIN_TOKEN" ]; then \
			echo "    ERROR: Failed to get admin token. Is Keycloak running?"; \
			echo "    Run: kubectl port-forward svc/keycloak 8080:8080"; \
			exit 1; \
		fi; \
		curl -s -X POST "$(KEYCLOAK_URL)/admin/realms" \
			-H "Authorization: Bearer $$ADMIN_TOKEN" -H "Content-Type: application/json" \
			-d '{"realm":"$(KEYCLOAK_REALM)","enabled":true}'; \
		curl -s -X POST "$(KEYCLOAK_URL)/admin/realms/$(KEYCLOAK_REALM)/clients" \
			-H "Authorization: Bearer $$ADMIN_TOKEN" -H "Content-Type: application/json" \
			-d '{"clientId":"zta-client","enabled":true,"publicClient":false,"secret":"zta-secret","directAccessGrantsEnabled":true}'; \
		curl -s -X POST "$(KEYCLOAK_URL)/admin/realms/$(KEYCLOAK_REALM)/roles" \
			-H "Authorization: Bearer $$ADMIN_TOKEN" -H "Content-Type: application/json" \
			-d '{"name":"admin"}'; \
		curl -s -X POST "$(KEYCLOAK_URL)/admin/realms/$(KEYCLOAK_REALM)/users" \
			-H "Authorization: Bearer $$ADMIN_TOKEN" -H "Content-Type: application/json" \
			-d '{"username":"testuser","enabled":true,"credentials":[{"type":"password","value":"testpass","temporary":false}]}'; \
		USER_ID=$$(curl -s "$(KEYCLOAK_URL)/admin/realms/$(KEYCLOAK_REALM)/users?username=testuser" \
			-H "Authorization: Bearer $$ADMIN_TOKEN" | python3 -c "import sys,json; u=json.load(sys.stdin); print(u[0]['id'] if u else '')"); \
		ROLE=$$(curl -s "$(KEYCLOAK_URL)/admin/realms/$(KEYCLOAK_REALM)/roles/admin" -H "Authorization: Bearer $$ADMIN_TOKEN"); \
		curl -s -X POST "$(KEYCLOAK_URL)/admin/realms/$(KEYCLOAK_REALM)/users/$$USER_ID/role-mappings/realm" \
			-H "Authorization: Bearer $$ADMIN_TOKEN" -H "Content-Type: application/json" \
			-d "[$$ROLE]"; \
		echo ""; \
		echo "    Setup complete: testuser / testpass (role: admin)"; \
		echo "    Next: make setup-keycloak-viewer (for Scenario D)"; \
	fi

# Add viewer role + vieweruser for Scenario D JWT Role Claim tests
setup-keycloak-viewer:
	@echo ">>> Adding viewer role + vieweruser to Keycloak (Scenario D)..."
	@ADMIN_TOKEN=$$(curl -s -X POST "$(KEYCLOAK_URL)/realms/master/protocol/openid-connect/token" \
		-d "grant_type=password" -d "client_id=admin-cli" -d "username=admin" -d "password=admin" \
		| python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))"); \
	if [ -z "$$ADMIN_TOKEN" ]; then \
		echo "    ERROR: Keycloak not reachable. Run: make port-keycloak"; exit 1; \
	fi; \
	VIEWER_CHECK=$$(curl -s "$(KEYCLOAK_URL)/admin/realms/$(KEYCLOAK_REALM)/roles/viewer" \
		-H "Authorization: Bearer $$ADMIN_TOKEN" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('name',''))"); \
	if [ "$$VIEWER_CHECK" = "viewer" ]; then \
		echo "    viewer role already exists (Skip)"; \
	else \
		curl -s -X POST "$(KEYCLOAK_URL)/admin/realms/$(KEYCLOAK_REALM)/roles" \
			-H "Authorization: Bearer $$ADMIN_TOKEN" -H "Content-Type: application/json" \
			-d '{"name":"viewer","description":"Read-only access, no admin paths, no write ops"}'; \
		echo "    Created role: viewer"; \
	fi; \
	VU_ID=$$(curl -s "$(KEYCLOAK_URL)/admin/realms/$(KEYCLOAK_REALM)/users?username=vieweruser" \
		-H "Authorization: Bearer $$ADMIN_TOKEN" | python3 -c "import sys,json; u=json.load(sys.stdin); print(u[0]['id'] if u else '')"); \
	if [ -n "$$VU_ID" ]; then \
		echo "    vieweruser already exists (id: $$VU_ID)"; \
	else \
		curl -s -X POST "$(KEYCLOAK_URL)/admin/realms/$(KEYCLOAK_REALM)/users" \
			-H "Authorization: Bearer $$ADMIN_TOKEN" -H "Content-Type: application/json" \
			-d '{"username":"vieweruser","enabled":true,"credentials":[{"type":"password","value":"viewerpass","temporary":false}]}'; \
		VU_ID=$$(curl -s "$(KEYCLOAK_URL)/admin/realms/$(KEYCLOAK_REALM)/users?username=vieweruser" \
			-H "Authorization: Bearer $$ADMIN_TOKEN" | python3 -c "import sys,json; u=json.load(sys.stdin); print(u[0]['id'] if u else '')"); \
		echo "    Created: vieweruser / viewerpass (id: $$VU_ID)"; \
	fi; \
	if [ -z "$$VU_ID" ]; then echo "    ERROR: Failed to get/create vieweruser"; exit 1; fi; \
	ROLE_CHECK=$$(curl -s "$(KEYCLOAK_URL)/admin/realms/$(KEYCLOAK_REALM)/users/$$VU_ID/role-mappings/realm" \
		-H "Authorization: Bearer $$ADMIN_TOKEN" | python3 -c "import sys,json; roles=json.load(sys.stdin); print('viewer' if isinstance(roles,list) and any(r.get('name')=='viewer' for r in roles) else '')"); \
	if [ "$$ROLE_CHECK" = "viewer" ]; then \
		echo "    viewer role already assigned to vieweruser (Skip)"; \
	else \
		VROLE=$$(curl -s "$(KEYCLOAK_URL)/admin/realms/$(KEYCLOAK_REALM)/roles/viewer" -H "Authorization: Bearer $$ADMIN_TOKEN"); \
		curl -s -X POST "$(KEYCLOAK_URL)/admin/realms/$(KEYCLOAK_REALM)/users/$$VU_ID/role-mappings/realm" \
			-H "Authorization: Bearer $$ADMIN_TOKEN" -H "Content-Type: application/json" \
			-d "[$$VROLE]"; \
		echo "    Assigned viewer role to vieweruser"; \
	fi; \
	echo ""; \
	echo "    Keycloak users:"; \
	echo "      testuser  / testpass  (role: admin)  -> make get-token"; \
	echo "      vieweruser / viewerpass (role: viewer) -> make get-token-viewer"

open-keycloak:
	@echo ">>> Keycloak Admin Console: http://localhost:18080"
	@python3 -c "import webbrowser; webbrowser.open('http://localhost:18080')" 2>/dev/null || \
		xdg-open "http://localhost:18080" 2>/dev/null || \
		echo "    Please open http://localhost:18080 manually"

open-kiali:
	@echo ">>> Kiali Dashboard: http://localhost:20000"
	@python3 -c "import webbrowser; webbrowser.open('http://localhost:20000')" 2>/dev/null || \
		xdg-open "http://localhost:20000" 2>/dev/null || \
		echo "    Please open http://localhost:20000 manually"

open-grafana:
	@echo ">>> Grafana Dashboard: http://localhost:20002"
	@python3 -c "import webbrowser; webbrowser.open('http://localhost:20002')" 2>/dev/null || \
		xdg-open "http://localhost:20002" 2>/dev/null || \
		echo "    Please open http://localhost:20002 manually"

get-token:
	@echo ">>> Issuing JWT token for testuser (role: admin)..."
	@curl -s -X POST "$(KEYCLOAK_URL)/realms/$(KEYCLOAK_REALM)/protocol/openid-connect/token" \
		-H "Content-Type: application/x-www-form-urlencoded" \
		-d "grant_type=password" \
		-d "client_id=zta-client" \
		-d "client_secret=zta-secret" \
		-d "username=testuser" \
		-d "password=testpass" | python3 -c "import sys,json; d=json.load(sys.stdin); print('access_token:', d.get('access_token','ERROR: '+str(d)))"

get-token-viewer:
	@echo ">>> Issuing JWT token for vieweruser (role: viewer)..."
	@curl -s -X POST "$(KEYCLOAK_URL)/realms/$(KEYCLOAK_REALM)/protocol/openid-connect/token" \
		-H "Content-Type: application/x-www-form-urlencoded" \
		-d "grant_type=password" \
		-d "client_id=zta-client" \
		-d "client_secret=zta-secret" \
		-d "username=vieweruser" \
		-d "password=viewerpass" | python3 -c "import sys,json; d=json.load(sys.stdin); print('access_token:', d.get('access_token','ERROR: '+str(d)))"

# ============================================================
#  Scenario A~E Tests (Detailed Signal Tracing)
#  Output format: REQUEST SIGNALS -> EXPECT -> RESULT -> STATUS
# ============================================================
test:
	@echo ""
	@echo "=============================================================="
	@echo "SCENARIO A (North-South baseline checks)"
	@echo "=============================================================="
	@FAIL=0; \
	for t in test-block test-pass; do \
		if ! $(MAKE) --no-print-directory $$t; then FAIL=$$((FAIL+1)); fi; \
	done; \
	if [ $$FAIL -gt 0 ]; then echo "SCENARIO A (NS): FAIL ($$FAIL failed)"; exit 1; fi; \
	echo "SCENARIO A (NS): PASS"

test-block:
	@echo ""
	@echo "[A-NS-1] No identity -> Frontend must deny"
	@echo "REQUEST SIGNALS:"
	@echo "  - method=GET path=/api/admin"
	@echo "  - headers: (none)"
	@echo "  - flow: client -> Istio PEP -> OPA PDP -> deny"
	@touch $(TEST_SUMMARY_FILE)
	@echo "[ZTA:FLOW] node=client state=active"
	@EXPECTED=403; \
	RESULT=$$(kubectl delete pod test-block --force --grace-period=0 --ignore-not-found >/dev/null 2>&1 || true; \
		kubectl run test-block --image=curlimages/curl --restart=Never -i \
		-- curl -s -o /dev/null -w "%{http_code}" http://frontend/api/admin 2>/dev/null | tr -d '\r' | grep -Eo '[0-9]{3}' | tail -n1); \
	[ -z "$$RESULT" ] && RESULT="ERR"; \
	STATUS="FAIL"; [ "$$RESULT" = "$$EXPECTED" ] && STATUS="PASS"; \
	echo "EXPECT: $$EXPECTED"; \
	echo "RESULT: $$RESULT"; \
	echo "STATUS: $$STATUS"; \
	if [ "$$STATUS" = "PASS" ]; then \
		echo "[ZTA:FLOW] node=istio-jwt state=passed"; \
		echo "[ZTA:FLOW] node=istio-deny state=blocked"; \
		echo "[ZTA:FLOW] node=opa state=unreachable"; \
		echo "[ZTA:FLOW] node=app state=unreachable"; \
	fi; \
	echo "A-NS-1 no-identity deny|$$EXPECTED|$$RESULT|$$STATUS|GET /api/admin without Authorization/role headers" >> $(TEST_SUMMARY_FILE); \
	[ "$$STATUS" = "PASS" ]

test-pass:
	@echo ""
	@echo "[A-NS-2] role:admin header -> Frontend allow (demo baseline)"
	@echo "NOTE: Uses demo-scaffolding header rule (DEMO SCAFFOLDING block in opa-k8s.yaml)"
	@echo "      This rule is intentionally weak — Scenario D (JWT) is the production-valid path"
	@echo "REQUEST SIGNALS:"
	@echo "  - method=GET path=/api/admin"
	@echo "  - headers: role=admin"
	@echo "  - flow: client -> Istio PEP -> OPA PDP(header rule) -> allow"
	@touch $(TEST_SUMMARY_FILE)
	@echo "[ZTA:FLOW] node=client state=active"
	@EXPECTED=200; \
	RESULT=$$(kubectl delete pod test-pass --force --grace-period=0 --ignore-not-found >/dev/null 2>&1 || true; \
		kubectl run test-pass --image=curlimages/curl --restart=Never -i \
		-- curl -s -o /dev/null -w "%{http_code}" -H "role: admin" http://frontend/api/admin 2>/dev/null | tr -d '\r' | grep -Eo '[0-9]{3}' | tail -n1); \
	[ -z "$$RESULT" ] && RESULT="ERR"; \
	STATUS="FAIL"; [ "$$RESULT" = "$$EXPECTED" ] && STATUS="PASS"; \
	echo "EXPECT: $$EXPECTED"; \
	echo "RESULT: $$RESULT"; \
	echo "STATUS: $$STATUS"; \
	if [ "$$STATUS" = "PASS" ]; then \
		echo "[ZTA:FLOW] node=istio-jwt state=passed"; \
		echo "[ZTA:FLOW] node=istio-deny state=passed"; \
		echo "[ZTA:FLOW] node=opa state=passed"; \
		echo "[ZTA:FLOW] node=app state=allowed"; \
	fi; \
	echo "A-NS-2 role-header allow|$$EXPECTED|$$RESULT|$$STATUS|GET /api/admin with role:admin header" >> $(TEST_SUMMARY_FILE); \
	[ "$$STATUS" = "PASS" ]

test-jwt:
	@echo ""
	@echo "[B-3] Manual valid JWT -> allow"
	@echo "REQUEST SIGNALS:"
	@echo "  - method=GET path=/api/admin"
	@echo "  - headers: Authorization=Bearer <TOKEN>"
	@echo "  - flow: Istio RequestAuthentication(JWKS verify) -> OPA claim check -> allow"
	@if [ -z "$$TOKEN" ]; then echo "ERROR: TOKEN required. Usage: TOKEN=xxx make test-jwt"; exit 1; fi
	@touch $(TEST_SUMMARY_FILE)
	@EXPECTED=200; \
	RESULT=$$(kubectl delete pod test-jwt --force --grace-period=0 --ignore-not-found >/dev/null 2>&1 || true; \
		kubectl run test-jwt --image=curlimages/curl --restart=Never -i \
		-- curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $$TOKEN" http://frontend/api/admin 2>/dev/null | tr -d '\r' | grep -Eo '[0-9]{3}' | tail -n1); \
	[ -z "$$RESULT" ] && RESULT="ERR"; \
	STATUS="FAIL"; [ "$$RESULT" = "$$EXPECTED" ] && STATUS="PASS"; \
	echo "EXPECT: $$EXPECTED"; \
	echo "RESULT: $$RESULT"; \
	echo "STATUS: $$STATUS"; \
	echo "B-3 manual valid jwt|$$EXPECTED|$$RESULT|$$STATUS|GET /api/admin with user-provided JWT" >> $(TEST_SUMMARY_FILE); \
	[ "$$STATUS" = "PASS" ]

test-fake:
	@echo ""
	@echo "[B-1] Forged JWT signature -> must fail authentication"
	@echo "REQUEST SIGNALS:"
	@echo "  - method=GET path=/api/admin"
	@echo "  - forged token with invalid signature"
	@echo "  - flow: invalid token -> no valid principal -> require-jwt deny (403)"
	@touch $(TEST_SUMMARY_FILE)
	@echo "[ZTA:FLOW] node=client state=active"
	@EXPECTED=403; \
	RESULT=$$(kubectl delete pod test-fake --force --grace-period=0 --ignore-not-found >/dev/null 2>&1 || true; \
		kubectl run test-fake --image=curlimages/curl --restart=Never -i \
		-- curl -s -o /dev/null -w "%{http_code}" \
		   -H "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmYWtlIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9teXJlYWxtIn0.invalid" \
		   http://frontend/api/admin 2>/dev/null | tr -d '\r' | grep -Eo '[0-9]{3}' | tail -n1); \
	[ -z "$$RESULT" ] && RESULT="ERR"; \
	STATUS="FAIL"; [ "$$RESULT" = "$$EXPECTED" ] && STATUS="PASS"; \
	echo "EXPECT: $$EXPECTED"; \
	echo "RESULT: $$RESULT"; \
	echo "STATUS: $$STATUS"; \
	if [ "$$STATUS" = "PASS" ]; then \
		echo "[ZTA:FLOW] node=istio-jwt state=blocked"; \
		echo "[ZTA:FLOW] node=istio-deny state=unreachable"; \
		echo "[ZTA:FLOW] node=opa state=unreachable"; \
		echo "[ZTA:FLOW] node=app state=unreachable"; \
	fi; \
	echo "B-1 forged jwt reject|$$EXPECTED|$$RESULT|$$STATUS|invalid signature token to /api/admin" >> $(TEST_SUMMARY_FILE); \
	[ "$$STATUS" = "PASS" ]

test-jwt-tampered:
	@echo ""
	@echo "[B-2] Tampered real JWT payload -> must fail authentication"
	@echo "REQUEST SIGNALS:"
	@echo "  - start from real token"
	@echo "  - modify payload, keep original signature"
	@echo "  - flow: Istio verifies signature against new payload -> mismatch -> 401"
	@touch $(TEST_SUMMARY_FILE)
	@echo "[ZTA:FLOW] node=client state=active"
	@EXPECTED=401; \
	TOKEN=$$(curl -s -X POST "$(KEYCLOAK_URL)/realms/$(KEYCLOAK_REALM)/protocol/openid-connect/token" \
		-H "Content-Type: application/x-www-form-urlencoded" \
		-d "grant_type=password" -d "client_id=zta-client" -d "client_secret=zta-secret" \
		-d "username=testuser" -d "password=testpass" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null); \
	if [ -z "$$TOKEN" ]; then \
		RESULT="NO_TOKEN"; \
	else \
		HEADER=$$(echo "$$TOKEN" | cut -d. -f1); \
		SIG=$$(echo "$$TOKEN" | cut -d. -f3); \
		TAMPERED_PAYLOAD=$$(python3 -c "import base64,json; p={'sub':'tampered-user','realm_access':{'roles':['admin']}}; print(base64.urlsafe_b64encode(json.dumps(p,separators=(',',':')).encode()).decode().rstrip('='))"); \
		TAMPERED="$$HEADER.$$TAMPERED_PAYLOAD.$$SIG"; \
		RESULT=$$(kubectl delete pod test-jwt-tampered --force --grace-period=0 --ignore-not-found >/dev/null 2>&1 || true; \
			kubectl run test-jwt-tampered --image=curlimages/curl --restart=Never -i \
			-- curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $$TAMPERED" \
			   http://frontend/api/admin 2>/dev/null | tr -d '\r' | grep -Eo '[0-9]{3}' | tail -n1); \
	fi; \
	[ -z "$$RESULT" ] && RESULT="ERR"; \
	STATUS="FAIL"; [ "$$RESULT" = "$$EXPECTED" ] && STATUS="PASS"; \
	echo "EXPECT: $$EXPECTED"; \
	echo "RESULT: $$RESULT"; \
	echo "STATUS: $$STATUS"; \
	if [ "$$STATUS" = "PASS" ]; then \
		echo "[ZTA:FLOW] node=istio-jwt state=blocked"; \
		echo "[ZTA:FLOW] node=istio-deny state=unreachable"; \
		echo "[ZTA:FLOW] node=opa state=unreachable"; \
		echo "[ZTA:FLOW] node=app state=unreachable"; \
	fi; \
	echo "B-2 tampered jwt reject|$$EXPECTED|$$RESULT|$$STATUS|real JWT payload modified then reused signature" >> $(TEST_SUMMARY_FILE); \
	[ "$$STATUS" = "PASS" ]

test-jwt-auto:
	@echo ""
	@echo "[B-4] Valid Keycloak JWT -> allow"
	@echo "REQUEST SIGNALS:"
	@echo "  - obtain token from Keycloak realm=$(KEYCLOAK_REALM)"
	@echo "  - send Authorization: Bearer <valid token>"
	@echo "  - flow: Istio authn pass -> OPA authz pass -> 200"
	@touch $(TEST_SUMMARY_FILE)
	@echo "[ZTA:FLOW] node=client state=active"
	@EXPECTED=200; \
	TOKEN=$$(curl -s -X POST "$(KEYCLOAK_URL)/realms/$(KEYCLOAK_REALM)/protocol/openid-connect/token" \
		-H "Content-Type: application/x-www-form-urlencoded" \
		-d "grant_type=password" -d "client_id=zta-client" -d "client_secret=zta-secret" \
		-d "username=testuser" -d "password=testpass" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null); \
	if [ -z "$$TOKEN" ]; then \
		RESULT="NO_TOKEN"; \
	else \
		RESULT=$$(kubectl delete pod test-jwt-auto --force --grace-period=0 --ignore-not-found >/dev/null 2>&1 || true; \
			kubectl run test-jwt-auto --image=curlimages/curl --restart=Never -i \
			-- curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $$TOKEN" \
			   http://frontend/api/admin 2>/dev/null | tr -d '\r' | grep -Eo '[0-9]{3}' | tail -n1); \
	fi; \
	[ -z "$$RESULT" ] && RESULT="ERR"; \
	STATUS="FAIL"; [ "$$RESULT" = "$$EXPECTED" ] && STATUS="PASS"; \
	echo "EXPECT: $$EXPECTED"; \
	echo "RESULT: $$RESULT"; \
	echo "STATUS: $$STATUS"; \
	if [ "$$STATUS" = "PASS" ]; then \
		echo "[ZTA:FLOW] node=istio-jwt state=passed"; \
		echo "[ZTA:FLOW] node=istio-deny state=passed"; \
		echo "[ZTA:FLOW] node=opa state=passed"; \
		echo "[ZTA:FLOW] node=app state=allowed"; \
	fi; \
	echo "B-4 valid jwt allow|$$EXPECTED|$$RESULT|$$STATUS|Keycloak issued token to /api/admin" >> $(TEST_SUMMARY_FILE); \
	[ "$$STATUS" = "PASS" ]

test-lateral:
	@echo ""
	@echo "=============================================================="
	@echo "SCENARIO A (East-West lateral movement)"
	@echo "=============================================================="
	@FAIL=0; \
	for t in test-lateral-block test-lateral-sidecar test-lateral-podip; do \
		if ! $(MAKE) --no-print-directory $$t; then FAIL=$$((FAIL+1)); fi; \
	done; \
	if [ $$FAIL -gt 0 ]; then echo "SCENARIO A (EW): FAIL ($$FAIL failed)"; exit 1; fi; \
	echo "SCENARIO A (EW): PASS"

test-lateral-block:
	@echo ""
	@echo "[A-EW-1] Rogue pod (no sidecar) -> backend direct"
	@echo "REQUEST SIGNALS:"
	@echo "  - source: pod without Istio sidecar/mTLS cert"
	@echo "  - method=GET path=/ (backend service)"
	@echo "  - flow: mTLS handshake expected to fail (or 403)"
	@touch $(TEST_SUMMARY_FILE)
	@echo "[ZTA:FLOW] node=rogue-pod state=active"
	@EXPECTED="403,000,503"; \
	RESULT=$$(kubectl delete pod test-rogue --force --grace-period=0 --ignore-not-found >/dev/null 2>&1 || true; \
		kubectl run test-rogue --image=curlimages/curl --restart=Never -i \
		-- curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://backend/ 2>/dev/null | tr -d '\r' | grep -Eo '[0-9]{3}' | tail -n1); \
	[ -z "$$RESULT" ] && RESULT="ERR"; \
	STATUS="FAIL"; \
	if [ "$$RESULT" = "403" ] || [ "$$RESULT" = "000" ] || [ "$$RESULT" = "503" ]; then STATUS="PASS"; fi; \
	echo "EXPECT: $$EXPECTED"; \
	echo "RESULT: $$RESULT"; \
	echo "STATUS: $$STATUS"; \
	if [ "$$STATUS" = "PASS" ]; then \
		echo "[ZTA:FLOW] node=mtls state=blocked"; \
		echo "[ZTA:FLOW] node=spiffe state=unreachable"; \
		echo "[ZTA:FLOW] node=backend state=unreachable"; \
	fi; \
	echo "A-EW-1 rogue no-sidecar block|$$EXPECTED|$$RESULT|$$STATUS|pod without sidecar to backend service" >> $(TEST_SUMMARY_FILE); \
	[ "$$STATUS" = "PASS" ]

test-lateral-sidecar:
	@echo ""
	@echo "[A-EW-2] Wrong ServiceAccount(sidecar 있음) -> backend"
	@echo "REQUEST SIGNALS:"
	@echo "  - source SA=backend-sa (expected frontend-sa only)"
	@echo "  - method=GET path=/"
	@echo "  - flow: mTLS pass -> AuthorizationPolicy(SPIFFE principal) deny"
	@touch $(TEST_SUMMARY_FILE)
	@echo "[ZTA:FLOW] node=rogue-pod state=active"
	@EXPECTED=403; \
	RESULT=$$(kubectl delete pod test-wrongsa --force --grace-period=0 --ignore-not-found >/dev/null 2>&1 || true; \
		kubectl run test-wrongsa --image=curlimages/curl --restart=Never -i \
		--overrides='{"spec":{"serviceAccountName":"backend-sa"}}' \
		-- curl -s -o /dev/null -w "%{http_code}" --max-time 10 http://backend/ 2>/dev/null | tr -d '\r' | grep -Eo '[0-9]{3}' | tail -n1); \
	[ -z "$$RESULT" ] && RESULT="ERR"; \
	STATUS="FAIL"; [ "$$RESULT" = "$$EXPECTED" ] && STATUS="PASS"; \
	echo "EXPECT: $$EXPECTED"; \
	echo "RESULT: $$RESULT"; \
	echo "STATUS: $$STATUS"; \
	if [ "$$STATUS" = "PASS" ]; then \
		echo "[ZTA:FLOW] node=mtls state=passed"; \
		echo "[ZTA:FLOW] node=spiffe state=blocked"; \
		echo "[ZTA:FLOW] node=backend state=unreachable"; \
	fi; \
	echo "A-EW-2 wrong-sa deny|$$EXPECTED|$$RESULT|$$STATUS|backend-sa principal rejected by backend policy" >> $(TEST_SUMMARY_FILE); \
	[ "$$STATUS" = "PASS" ]

test-lateral-podip:
	@echo ""
	@echo "[A-EW-3] Rogue pod (no sidecar) -> backend podIP:8080 direct"
	@echo "REQUEST SIGNALS:"
	@echo "  - source: pod without Istio sidecar"
	@echo "  - target: backend pod IP:8080 (service name bypass attempt)"
	@echo "  - flow: inbound Envoy/policy chain should still block"
	@touch $(TEST_SUMMARY_FILE)
	@echo "[ZTA:FLOW] node=rogue-pod state=active"
	@EXPECTED="403,000,503"; \
	BACKEND_IP=$$(kubectl get pod -l app=backend -o jsonpath='{.items[0].status.podIP}' 2>/dev/null); \
	if [ -z "$$BACKEND_IP" ]; then \
		RESULT="NO_BACKEND_IP"; \
	else \
		RESULT=$$(kubectl delete pod test-rogue-podip --force --grace-period=0 --ignore-not-found >/dev/null 2>&1 || true; \
			kubectl run test-rogue-podip --image=curlimages/curl --restart=Never -i \
			-- curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://$$BACKEND_IP:8080/ 2>/dev/null | tr -d '\r' | grep -Eo '[0-9]{3}' | tail -n1); \
	fi; \
	[ -z "$$RESULT" ] && RESULT="ERR"; \
	STATUS="FAIL"; \
	if [ "$$RESULT" = "403" ] || [ "$$RESULT" = "000" ] || [ "$$RESULT" = "503" ]; then STATUS="PASS"; fi; \
	echo "EXPECT: $$EXPECTED"; \
	echo "RESULT: $$RESULT"; \
	echo "STATUS: $$STATUS"; \
	if [ "$$STATUS" = "PASS" ]; then \
		echo "[ZTA:FLOW] node=mtls state=blocked"; \
		echo "[ZTA:FLOW] node=spiffe state=unreachable"; \
		echo "[ZTA:FLOW] node=backend state=unreachable"; \
	fi; \
	echo "A-EW-3 podip bypass deny|$$EXPECTED|$$RESULT|$$STATUS|rogue pod direct podIP call to backend:8080" >> $(TEST_SUMMARY_FILE); \
	[ "$$STATUS" = "PASS" ]

# ============================================================
#  Scenario C: Context-Based Access Control
# ============================================================
test-context:
	@echo ""
	@echo "=============================================================="
	@echo "SCENARIO C (Context = role + method + path)"
	@echo "=============================================================="
	@FAIL=0; \
	for t in test-context-user-get test-context-user-admin test-context-user-post test-context-admin-post; do \
		if ! $(MAKE) --no-print-directory $$t; then FAIL=$$((FAIL+1)); fi; \
	done; \
	if [ $$FAIL -gt 0 ]; then echo "SCENARIO C: FAIL ($$FAIL failed)"; exit 1; fi; \
	echo "SCENARIO C: PASS"

test-context-user-get:
	@echo ""
	@echo "[C-1] role=user, GET /api/data"
	@echo "REQUEST SIGNALS: allow expected (read + non-admin path)"
	@touch $(TEST_SUMMARY_FILE)
	@echo "[ZTA:FLOW] node=client state=active"
	@EXPECTED=200; \
	RESULT=$$(kubectl delete pod test-ctx-1 --force --grace-period=0 --ignore-not-found >/dev/null 2>&1 || true; \
		kubectl run test-ctx-1 --image=curlimages/curl --restart=Never -i \
		-- curl -s -o /dev/null -w "%{http_code}" -H "role: user" http://frontend/api/data 2>/dev/null | tr -d '\r' | grep -Eo '[0-9]{3}' | tail -n1); \
	[ -z "$$RESULT" ] && RESULT="ERR"; \
	STATUS="FAIL"; [ "$$RESULT" = "$$EXPECTED" ] && STATUS="PASS"; \
	echo "EXPECT: $$EXPECTED"; echo "RESULT: $$RESULT"; echo "STATUS: $$STATUS"; \
	if [ "$$STATUS" = "PASS" ]; then \
		echo "[ZTA:FLOW] node=istio-jwt state=passed"; \
		echo "[ZTA:FLOW] node=istio-deny state=passed"; \
		echo "[ZTA:FLOW] node=opa state=passed"; \
		echo "[ZTA:FLOW] node=app state=allowed"; \
	fi; \
	echo "C-1 user get data allow|$$EXPECTED|$$RESULT|$$STATUS|role:user GET /api/data" >> $(TEST_SUMMARY_FILE); \
	[ "$$STATUS" = "PASS" ]

test-context-user-admin:
	@echo ""
	@echo "[C-2] role=user, GET /api/admin"
	@echo "REQUEST SIGNALS: deny expected (admin path restriction)"
	@touch $(TEST_SUMMARY_FILE)
	@echo "[ZTA:FLOW] node=client state=active"
	@EXPECTED=403; \
	RESULT=$$(kubectl delete pod test-ctx-2 --force --grace-period=0 --ignore-not-found >/dev/null 2>&1 || true; \
		kubectl run test-ctx-2 --image=curlimages/curl --restart=Never -i \
		-- curl -s -o /dev/null -w "%{http_code}" -H "role: user" http://frontend/api/admin 2>/dev/null | tr -d '\r' | grep -Eo '[0-9]{3}' | tail -n1); \
	[ -z "$$RESULT" ] && RESULT="ERR"; \
	STATUS="FAIL"; [ "$$RESULT" = "$$EXPECTED" ] && STATUS="PASS"; \
	echo "EXPECT: $$EXPECTED"; echo "RESULT: $$RESULT"; echo "STATUS: $$STATUS"; \
	if [ "$$STATUS" = "PASS" ]; then \
		echo "[ZTA:FLOW] node=istio-jwt state=passed"; \
		echo "[ZTA:FLOW] node=istio-deny state=passed"; \
		echo "[ZTA:FLOW] node=opa state=blocked"; \
		echo "[ZTA:FLOW] node=app state=unreachable"; \
	fi; \
	echo "C-2 user get admin deny|$$EXPECTED|$$RESULT|$$STATUS|role:user GET /api/admin" >> $(TEST_SUMMARY_FILE); \
	[ "$$STATUS" = "PASS" ]

test-context-user-post:
	@echo ""
	@echo "[C-3] role=user, POST /api/write"
	@echo "REQUEST SIGNALS: deny expected (write requires admin)"
	@touch $(TEST_SUMMARY_FILE)
	@echo "[ZTA:FLOW] node=client state=active"
	@EXPECTED=403; \
	RESULT=$$(kubectl delete pod test-ctx-3 --force --grace-period=0 --ignore-not-found >/dev/null 2>&1 || true; \
		kubectl run test-ctx-3 --image=curlimages/curl --restart=Never -i \
		-- curl -s -o /dev/null -w "%{http_code}" -X POST -H "role: user" \
		   -H "Content-Type: application/json" -d '{"data":"test"}' \
		   http://frontend/api/write 2>/dev/null | tr -d '\r' | grep -Eo '[0-9]{3}' | tail -n1); \
	[ -z "$$RESULT" ] && RESULT="ERR"; \
	STATUS="FAIL"; [ "$$RESULT" = "$$EXPECTED" ] && STATUS="PASS"; \
	echo "EXPECT: $$EXPECTED"; echo "RESULT: $$RESULT"; echo "STATUS: $$STATUS"; \
	if [ "$$STATUS" = "PASS" ]; then \
		echo "[ZTA:FLOW] node=istio-jwt state=passed"; \
		echo "[ZTA:FLOW] node=istio-deny state=passed"; \
		echo "[ZTA:FLOW] node=opa state=blocked"; \
		echo "[ZTA:FLOW] node=app state=unreachable"; \
	fi; \
	echo "C-3 user post write deny|$$EXPECTED|$$RESULT|$$STATUS|role:user POST /api/write" >> $(TEST_SUMMARY_FILE); \
	[ "$$STATUS" = "PASS" ]

test-context-admin-post:
	@echo ""
	@echo "[C-4] role=admin, POST /api/write"
	@echo "REQUEST SIGNALS: allow expected (admin write privilege)"
	@touch $(TEST_SUMMARY_FILE)
	@echo "[ZTA:FLOW] node=client state=active"
	@EXPECTED=200; \
	RESULT=$$(kubectl delete pod test-ctx-4 --force --grace-period=0 --ignore-not-found >/dev/null 2>&1 || true; \
		kubectl run test-ctx-4 --image=curlimages/curl --restart=Never -i \
		-- curl -s -o /dev/null -w "%{http_code}" -X POST -H "role: admin" \
		   -H "Content-Type: application/json" -d '{"data":"admin-write"}' \
		   http://frontend/api/write 2>/dev/null | tr -d '\r' | grep -Eo '[0-9]{3}' | tail -n1); \
	[ -z "$$RESULT" ] && RESULT="ERR"; \
	STATUS="FAIL"; [ "$$RESULT" = "$$EXPECTED" ] && STATUS="PASS"; \
	echo "EXPECT: $$EXPECTED"; echo "RESULT: $$RESULT"; echo "STATUS: $$STATUS"; \
	if [ "$$STATUS" = "PASS" ]; then \
		echo "[ZTA:FLOW] node=istio-jwt state=passed"; \
		echo "[ZTA:FLOW] node=istio-deny state=passed"; \
		echo "[ZTA:FLOW] node=opa state=passed"; \
		echo "[ZTA:FLOW] node=app state=allowed"; \
	fi; \
	echo "C-4 admin post write allow|$$EXPECTED|$$RESULT|$$STATUS|role:admin POST /api/write" >> $(TEST_SUMMARY_FILE); \
	[ "$$STATUS" = "PASS" ]

# ============================================================
#  Scenario D: JWT Role Claim Access Control
# ============================================================
test-jwt-role:
	@echo ""
	@echo "=============================================================="
	@echo "SCENARIO D (JWT claim-based authorization)"
	@echo "=============================================================="
	@FAIL=0; \
	for t in test-jwt-admin-all test-jwt-viewer-read test-jwt-viewer-admin test-jwt-viewer-post; do \
		if ! $(MAKE) --no-print-directory $$t; then FAIL=$$((FAIL+1)); fi; \
	done; \
	if [ $$FAIL -gt 0 ]; then echo "SCENARIO D: FAIL ($$FAIL failed)"; exit 1; fi; \
	echo "SCENARIO D: PASS"

test-jwt-admin-all:
	@echo ""
	@echo "[D-1] admin JWT -> GET /api/admin"
	@echo "REQUEST SIGNALS: Istio JWT verify pass + OPA claim(admin) allow"
	@touch $(TEST_SUMMARY_FILE)
	@echo "[ZTA:FLOW] node=client state=active"
	@EXPECTED=200; \
	TOKEN=$$(curl -s -X POST "$(KEYCLOAK_URL)/realms/$(KEYCLOAK_REALM)/protocol/openid-connect/token" \
		-H "Content-Type: application/x-www-form-urlencoded" \
		-d "grant_type=password" -d "client_id=zta-client" -d "client_secret=zta-secret" \
		-d "username=testuser" -d "password=testpass" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null); \
	if [ -z "$$TOKEN" ]; then RESULT="NO_TOKEN"; else \
		RESULT=$$(kubectl delete pod test-d1 --force --grace-period=0 --ignore-not-found >/dev/null 2>&1 || true; \
			kubectl run test-d1 --image=curlimages/curl --restart=Never -i \
			-- curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $$TOKEN" \
			   http://frontend/api/admin 2>/dev/null | tr -d '\r' | grep -Eo '[0-9]{3}' | tail -n1); \
	fi; \
	[ -z "$$RESULT" ] && RESULT="ERR"; \
	STATUS="FAIL"; [ "$$RESULT" = "$$EXPECTED" ] && STATUS="PASS"; \
	echo "EXPECT: $$EXPECTED"; echo "RESULT: $$RESULT"; echo "STATUS: $$STATUS"; \
	if [ "$$STATUS" = "PASS" ]; then \
		echo "[ZTA:FLOW] node=istio-jwt state=passed"; \
		echo "[ZTA:FLOW] node=istio-deny state=passed"; \
		echo "[ZTA:FLOW] node=opa state=passed"; \
		echo "[ZTA:FLOW] node=app state=allowed"; \
	fi; \
	echo "D-1 admin jwt admin path|$$EXPECTED|$$RESULT|$$STATUS|admin token GET /api/admin" >> $(TEST_SUMMARY_FILE); \
	[ "$$STATUS" = "PASS" ]

test-jwt-viewer-read:
	@echo ""
	@echo "[D-2] viewer JWT -> GET /api/data"
	@echo "REQUEST SIGNALS: Istio JWT verify pass + OPA viewer read allow"
	@touch $(TEST_SUMMARY_FILE)
	@echo "[ZTA:FLOW] node=client state=active"
	@EXPECTED=200; \
	TOKEN=$$(curl -s -X POST "$(KEYCLOAK_URL)/realms/$(KEYCLOAK_REALM)/protocol/openid-connect/token" \
		-H "Content-Type: application/x-www-form-urlencoded" \
		-d "grant_type=password" -d "client_id=zta-client" -d "client_secret=zta-secret" \
		-d "username=vieweruser" -d "password=viewerpass" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null); \
	if [ -z "$$TOKEN" ]; then RESULT="NO_TOKEN"; else \
		RESULT=$$(kubectl delete pod test-d2 --force --grace-period=0 --ignore-not-found >/dev/null 2>&1 || true; \
			kubectl run test-d2 --image=curlimages/curl --restart=Never -i \
			-- curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $$TOKEN" \
			   http://frontend/api/data 2>/dev/null | tr -d '\r' | grep -Eo '[0-9]{3}' | tail -n1); \
	fi; \
	[ -z "$$RESULT" ] && RESULT="ERR"; \
	STATUS="FAIL"; [ "$$RESULT" = "$$EXPECTED" ] && STATUS="PASS"; \
	echo "EXPECT: $$EXPECTED"; echo "RESULT: $$RESULT"; echo "STATUS: $$STATUS"; \
	if [ "$$STATUS" = "PASS" ]; then \
		echo "[ZTA:FLOW] node=istio-jwt state=passed"; \
		echo "[ZTA:FLOW] node=istio-deny state=passed"; \
		echo "[ZTA:FLOW] node=opa state=passed"; \
		echo "[ZTA:FLOW] node=app state=allowed"; \
	fi; \
	echo "D-2 viewer jwt read allow|$$EXPECTED|$$RESULT|$$STATUS|viewer token GET /api/data" >> $(TEST_SUMMARY_FILE); \
	[ "$$STATUS" = "PASS" ]

test-jwt-viewer-admin:
	@echo ""
	@echo "[D-3] viewer JWT -> GET /api/admin"
	@echo "REQUEST SIGNALS: Istio JWT verify pass + OPA viewer admin path deny"
	@touch $(TEST_SUMMARY_FILE)
	@echo "[ZTA:FLOW] node=client state=active"
	@EXPECTED=403; \
	TOKEN=$$(curl -s -X POST "$(KEYCLOAK_URL)/realms/$(KEYCLOAK_REALM)/protocol/openid-connect/token" \
		-H "Content-Type: application/x-www-form-urlencoded" \
		-d "grant_type=password" -d "client_id=zta-client" -d "client_secret=zta-secret" \
		-d "username=vieweruser" -d "password=viewerpass" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null); \
	if [ -z "$$TOKEN" ]; then RESULT="NO_TOKEN"; else \
		RESULT=$$(kubectl delete pod test-d3 --force --grace-period=0 --ignore-not-found >/dev/null 2>&1 || true; \
			kubectl run test-d3 --image=curlimages/curl --restart=Never -i \
			-- curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $$TOKEN" \
			   http://frontend/api/admin 2>/dev/null | tr -d '\r' | grep -Eo '[0-9]{3}' | tail -n1); \
	fi; \
	[ -z "$$RESULT" ] && RESULT="ERR"; \
	STATUS="FAIL"; [ "$$RESULT" = "$$EXPECTED" ] && STATUS="PASS"; \
	echo "EXPECT: $$EXPECTED"; echo "RESULT: $$RESULT"; echo "STATUS: $$STATUS"; \
	if [ "$$STATUS" = "PASS" ]; then \
		echo "[ZTA:FLOW] node=istio-jwt state=passed"; \
		echo "[ZTA:FLOW] node=istio-deny state=passed"; \
		echo "[ZTA:FLOW] node=opa state=blocked"; \
		echo "[ZTA:FLOW] node=app state=unreachable"; \
	fi; \
	echo "D-3 viewer jwt admin deny|$$EXPECTED|$$RESULT|$$STATUS|viewer token GET /api/admin" >> $(TEST_SUMMARY_FILE); \
	[ "$$STATUS" = "PASS" ]

test-jwt-viewer-post:
	@echo ""
	@echo "[D-4] viewer JWT -> POST /api/write"
	@echo "REQUEST SIGNALS: Istio JWT verify pass + OPA viewer write deny"
	@touch $(TEST_SUMMARY_FILE)
	@echo "[ZTA:FLOW] node=client state=active"
	@EXPECTED=403; \
	TOKEN=$$(curl -s -X POST "$(KEYCLOAK_URL)/realms/$(KEYCLOAK_REALM)/protocol/openid-connect/token" \
		-H "Content-Type: application/x-www-form-urlencoded" \
		-d "grant_type=password" -d "client_id=zta-client" -d "client_secret=zta-secret" \
		-d "username=vieweruser" -d "password=viewerpass" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null); \
	if [ -z "$$TOKEN" ]; then RESULT="NO_TOKEN"; else \
		RESULT=$$(kubectl delete pod test-d4 --force --grace-period=0 --ignore-not-found >/dev/null 2>&1 || true; \
			kubectl run test-d4 --image=curlimages/curl --restart=Never -i \
			-- curl -s -o /dev/null -w "%{http_code}" -X POST -H "Authorization: Bearer $$TOKEN" \
			   -H "Content-Type: application/json" -d '{"data":"inject"}' \
			   http://frontend/api/write 2>/dev/null | tr -d '\r' | grep -Eo '[0-9]{3}' | tail -n1); \
	fi; \
	[ -z "$$RESULT" ] && RESULT="ERR"; \
	STATUS="FAIL"; [ "$$RESULT" = "$$EXPECTED" ] && STATUS="PASS"; \
	echo "EXPECT: $$EXPECTED"; echo "RESULT: $$RESULT"; echo "STATUS: $$STATUS"; \
	if [ "$$STATUS" = "PASS" ]; then \
		echo "[ZTA:FLOW] node=istio-jwt state=passed"; \
		echo "[ZTA:FLOW] node=istio-deny state=passed"; \
		echo "[ZTA:FLOW] node=opa state=blocked"; \
		echo "[ZTA:FLOW] node=app state=unreachable"; \
	fi; \
	echo "D-4 viewer jwt post deny|$$EXPECTED|$$RESULT|$$STATUS|viewer token POST /api/write" >> $(TEST_SUMMARY_FILE); \
	[ "$$STATUS" = "PASS" ]

# ============================================================
#  Scenario E: Device Posture / Extended Context
# ============================================================
test-posture:
	@echo ""
	@echo "=============================================================="
	@echo "SCENARIO E (Device posture gate)"
	@echo "=============================================================="
	@FAIL=0; \
	for t in test-posture-ok test-posture-block; do \
		if ! $(MAKE) --no-print-directory $$t; then FAIL=$$((FAIL+1)); fi; \
	done; \
	if [ $$FAIL -gt 0 ]; then echo "SCENARIO E: FAIL ($$FAIL failed)"; exit 1; fi; \
	echo "SCENARIO E: PASS"

test-posture-ok:
	@echo ""
	@echo "[E-1] admin JWT + X-Device-Firewall=enabled"
	@echo "REQUEST SIGNALS: valid identity + healthy posture => allow"
	@touch $(TEST_SUMMARY_FILE)
	@echo "[ZTA:FLOW] node=client state=active"
	@EXPECTED=200; \
	TOKEN=$$(curl -s -X POST "$(KEYCLOAK_URL)/realms/$(KEYCLOAK_REALM)/protocol/openid-connect/token" \
		-H "Content-Type: application/x-www-form-urlencoded" \
		-d "grant_type=password" -d "client_id=zta-client" -d "client_secret=zta-secret" \
		-d "username=testuser" -d "password=testpass" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null); \
	if [ -z "$$TOKEN" ]; then RESULT="NO_TOKEN"; else \
		RESULT=$$(kubectl delete pod test-posture-ok --force --grace-period=0 --ignore-not-found >/dev/null 2>&1 || true; \
			kubectl run test-posture-ok --image=curlimages/curl --restart=Never -i \
			-- curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $$TOKEN" \
			   -H "X-Device-Firewall: enabled" http://frontend/api/admin 2>/dev/null | tr -d '\r' | grep -Eo '[0-9]{3}' | tail -n1); \
	fi; \
	[ -z "$$RESULT" ] && RESULT="ERR"; \
	STATUS="FAIL"; [ "$$RESULT" = "$$EXPECTED" ] && STATUS="PASS"; \
	echo "EXPECT: $$EXPECTED"; echo "RESULT: $$RESULT"; echo "STATUS: $$STATUS"; \
	if [ "$$STATUS" = "PASS" ]; then \
		echo "[ZTA:FLOW] node=istio-jwt state=passed"; \
		echo "[ZTA:FLOW] node=istio-deny state=passed"; \
		echo "[ZTA:FLOW] node=opa state=passed"; \
		echo "[ZTA:FLOW] node=app state=allowed"; \
	fi; \
	echo "E-1 posture enabled allow|$$EXPECTED|$$RESULT|$$STATUS|admin JWT + firewall enabled" >> $(TEST_SUMMARY_FILE); \
	[ "$$STATUS" = "PASS" ]

test-posture-block:
	@echo ""
	@echo "[E-2] admin JWT + X-Device-Firewall=disabled"
	@echo "REQUEST SIGNALS: valid identity + risky posture => deny"
	@touch $(TEST_SUMMARY_FILE)
	@echo "[ZTA:FLOW] node=client state=active"
	@EXPECTED=403; \
	TOKEN=$$(curl -s -X POST "$(KEYCLOAK_URL)/realms/$(KEYCLOAK_REALM)/protocol/openid-connect/token" \
		-H "Content-Type: application/x-www-form-urlencoded" \
		-d "grant_type=password" -d "client_id=zta-client" -d "client_secret=zta-secret" \
		-d "username=testuser" -d "password=testpass" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null); \
	if [ -z "$$TOKEN" ]; then RESULT="NO_TOKEN"; else \
		RESULT=$$(kubectl delete pod test-posture-block --force --grace-period=0 --ignore-not-found >/dev/null 2>&1 || true; \
			kubectl run test-posture-block --image=curlimages/curl --restart=Never -i \
			-- curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $$TOKEN" \
			   -H "X-Device-Firewall: disabled" http://frontend/api/admin 2>/dev/null | tr -d '\r' | grep -Eo '[0-9]{3}' | tail -n1); \
	fi; \
	[ -z "$$RESULT" ] && RESULT="ERR"; \
	STATUS="FAIL"; [ "$$RESULT" = "$$EXPECTED" ] && STATUS="PASS"; \
	echo "EXPECT: $$EXPECTED"; echo "RESULT: $$RESULT"; echo "STATUS: $$STATUS"; \
	if [ "$$STATUS" = "PASS" ]; then \
		echo "[ZTA:FLOW] node=istio-jwt state=passed"; \
		echo "[ZTA:FLOW] node=istio-deny state=passed"; \
		echo "[ZTA:FLOW] node=opa state=blocked"; \
		echo "[ZTA:FLOW] node=app state=unreachable"; \
	fi; \
	echo "E-2 posture disabled deny|$$EXPECTED|$$RESULT|$$STATUS|admin JWT + firewall disabled" >> $(TEST_SUMMARY_FILE); \
	[ "$$STATUS" = "PASS" ]

# ============================================================
#  Demo Targets (storytelling output)
# ============================================================
demo: demo-lateral demo-jwt demo-context demo-jwt-role demo-posture
	@echo ""
	@echo "=============================================="
	@echo "  Story Demo Complete (Scenario A ~ E)"
	@echo "=============================================="

demo-lateral: ensure-ports
	@echo ""
	@echo "=== SCENARIO 1: Lateral Movement Attack ==="
	@echo "[상황] 내부 침투 후 backend 직접 접근 시도"
	@$(MAKE) test-lateral

demo-jwt: ensure-ports
	@echo ""
	@echo "=== SCENARIO 2: Token Forgery / Tampering ==="
	@echo "[상황] 토큰 없이 접근, 가짜 토큰, 변조 토큰, 정상 토큰 비교"
	@$(MAKE) test-block
	@$(MAKE) test-fake
	@$(MAKE) test-jwt-tampered
	@$(MAKE) test-jwt-auto

demo-context: ensure-ports
	@echo ""
	@echo "=== SCENARIO 3: Context-Based Access Control ==="
	@echo "[상황] 같은 사용자라도 method/path 컨텍스트에 따라 결과가 달라짐"
	@$(MAKE) test-context

demo-jwt-role: ensure-ports
	@echo ""
	@echo "=== SCENARIO 4: JWT Claim-Based Access ==="
	@echo "[상황] 헤더가 아닌 Keycloak 서명 JWT claim 기반 인가"
	@$(MAKE) test-jwt-role

demo-posture: ensure-ports
	@echo ""
	@echo "=== SCENARIO 5: Device Posture ==="
	@echo "[상황] 유효한 admin 자격증명 + 불량 디바이스 상태는 차단"
	@$(MAKE) test-posture

demo-compare:
	@echo ""
	@echo "=== ZTA vs Baseline Comparison ==="
	@if [ -f evidence/zta-vs-baseline-comparison.txt ]; then \
		cat evidence/zta-vs-baseline-comparison.txt; \
	else \
		echo "evidence/zta-vs-baseline-comparison.txt 파일이 없습니다."; \
	fi

# ============================================================
#  Performance Tests
# ============================================================
test-perf: test-perf-zta

test-perf-zta:
	@echo ""
	@echo ">>> Performance Test (ZTA ON) - 200 requests"
	@echo "=============================================="
	@kubectl delete pod fortio-zta --ignore-not-found 2>/dev/null || true
	@kubectl run fortio-zta --image=fortio/fortio --restart=Never --rm -it \
		-- load -c 1 -qps 0 -n 200 -H "role:admin" http://frontend/ 2>/dev/null || true

test-perf-baseline:
	@echo ""
	@echo ">>> Baseline Performance Test (Policies OFF)"
	@echo "=============================================="
	@echo "WARNING: Run 'make clean' first to remove policies"
	@kubectl delete pod fortio-baseline --ignore-not-found 2>/dev/null || true
	@kubectl run fortio-baseline --image=fortio/fortio --restart=Never --rm -it \
		-- load -c 1 -qps 0 -n 200 http://frontend/ 2>/dev/null || true

# ============================================================
#  Port-Forward
# ============================================================
ports: port-keycloak port-kiali port-grafana
	@echo ""
	@echo ">>> All port-forwards started (background)"
	@echo "    Keycloak: http://localhost:18080"
	@echo "    Kiali:    http://localhost:20000"
	@echo "    Grafana:  http://localhost:20002"

ensure-ports:
	@if ! curl -s --connect-timeout 1 http://localhost:18080 >/dev/null 2>&1; then \
		echo ">>> Starting Keycloak port-forward..."; \
		nohup kubectl port-forward svc/keycloak 18080:8080 >/dev/null 2>&1 & \
		sleep 2; \
	fi

port-keycloak:
	@echo ">>> Starting Keycloak port-forward (18080)..."
	@pkill -f "[k]ubectl port-forward svc/keycloak" 2>/dev/null || true
	@nohup kubectl port-forward svc/keycloak 18080:8080 >/dev/null 2>&1 &
	@sleep 1
	@echo "    Started: http://localhost:18080"

port-kiali:
	@echo ">>> Starting Kiali port-forward (20000)..."
	@pkill -f "[k]ubectl port-forward.*kiali" 2>/dev/null || true
	@nohup kubectl port-forward svc/kiali -n istio-system 20000:20001 >/dev/null 2>&1 &
	@sleep 1
	@echo "    Started: http://localhost:20000"

port-grafana:
	@echo ">>> Starting Grafana port-forward (20002)..."
	@pkill -f "[k]ubectl port-forward.*grafana" 2>/dev/null || true
	@nohup kubectl port-forward svc/grafana -n istio-system 20002:3000 >/dev/null 2>&1 &
	@sleep 1
	@echo "    Started: http://localhost:20002"

ports-win:
	@echo ">>> Starting port-forwards in separate Windows (PowerShell)..."
	@powershell.exe -ExecutionPolicy Bypass -File scripts/ports.ps1

ports-stop:
	@echo ">>> Stopping all port-forwards..."
	@pkill -f "[k]ubectl port-forward" 2>/dev/null || true
	@echo "    All port-forwards stopped"

# ============================================================
#  Monitoring
# ============================================================
dashboard:
	@$(ISTIOCTL) dashboard kiali

grafana:
	@$(ISTIOCTL) dashboard grafana

logs: logs-opa

logs-opa:
	@echo ">>> OPA decision logs (Ctrl+C to exit)"
	@echo "    Each log entry shows: input, decision (allow/deny), rule matched"
	@kubectl logs -l app=opa --tail=100 -f

logs-pretty:
	@echo ">>> OPA decision logs (pretty, recent 200 lines)"
	@kubectl logs -l app=opa --tail=200 | python3 scripts/parse_opa_logs.py

logs-frontend:
	@kubectl logs -l app=frontend -c frontend --tail=50 -f

logs-backend:
	@kubectl logs -l app=backend -c backend --tail=50 -f

logs-keycloak:
	@kubectl logs -l app=keycloak -c keycloak --tail=50 -f

# ============================================================
#  Cleanup
# ============================================================
clean:
	@echo ">>> Deleting K8s resources (keeping Istio/Minikube)..."
	@kubectl delete -f k8s/jwt-require-policy.yaml --ignore-not-found 2>/dev/null || true
	@kubectl delete -f k8s/authz-policy-backend.yaml --ignore-not-found 2>/dev/null || true
	@kubectl delete -f k8s/peer-auth.yaml --ignore-not-found 2>/dev/null || true
	@kubectl delete -f k8s/authz-policy.yaml --ignore-not-found 2>/dev/null || true
	@kubectl delete -f k8s/jwt-auth.yaml --ignore-not-found 2>/dev/null || true
	@kubectl delete -f k8s/opa-k8s.yaml --ignore-not-found 2>/dev/null || true
	@kubectl delete -f k8s/keycloak.yaml --ignore-not-found 2>/dev/null || true
	@kubectl delete -f k8s/k8s-manifest.yaml --ignore-not-found 2>/dev/null || true
	@echo "    Done"

clean-all: clean
	@echo ">>> Uninstalling Istio..."
	@$(ISTIOCTL) uninstall --purge -y 2>/dev/null || true
	@kubectl delete namespace istio-system --ignore-not-found 2>/dev/null || true
	@echo ">>> Deleting Minikube..."
	@minikube delete
	@echo "    Full cleanup done"

restart:
	@kubectl rollout restart deployment/frontend deployment/backend deployment/opa
	@kubectl rollout status deployment/frontend deployment/backend deployment/opa --timeout=60s

# ============================================================
#  Visualizer (ZTA Security Dashboard)
# ============================================================
visualizer view viz:
	@if command -v wsl >/dev/null 2>&1; then \
	  wsl bash -c 'cd /mnt/c/Users/dksal/zta-project && make --no-print-directory _viz-inner'; \
	else \
	  $(MAKE) --no-print-directory _viz-inner; \
	fi

_viz-inner:
	@echo ">>> ZTA Security Dashboard"
	@if minikube status --format="{{.Host}}" 2>/dev/null | grep -q "Running" && \
	    kubectl get deployment frontend --no-headers 2>/dev/null | grep -q "frontend"; then \
	  echo "    Cluster already running — ensuring port-forwards..."; \
	  $(MAKE) --no-print-directory ensure-ports; \
	else \
	  echo "    Cluster not ready — running full setup first (this may take a few minutes)..."; \
	  $(MAKE) --no-print-directory all; \
	fi
	@fuser -k 5001/tcp 2>/dev/null || true
	@sleep 0.3
	@echo ""
	@echo ">>> Starting ZTA Security Dashboard on http://localhost:5001"
	@echo "    (Ctrl+C to stop)"
	@python3 visualizer/server.py

# ============================================================
#  PDF Evidence: one representative test per scenario (A~E)
#  Usage: make for_pdf
#  → Clears Prometheus history, runs A/B/C/D/E representative
#    tests, then prompts you to screenshot Kiali.
# ============================================================
for_pdf: ensure-ports jwt-refresh setup-keycloak-viewer
	@echo ""
	@echo "=============================================================="
	@echo "  for_pdf: clearing Prometheus and running A~E (1 test each)"
	@echo "=============================================================="
	@echo ""
	@echo ">>> [1/7] Restarting Prometheus to clear traffic history..."
	@kubectl rollout restart deployment/prometheus -n istio-system
	@kubectl rollout status deployment/prometheus -n istio-system --timeout=60s
	@echo ""
	@echo ">>> [2/7] Scenario A — lateral movement (rogue pod -> backend)"
	@$(MAKE) --no-print-directory test-lateral-block || true
	@echo ""
	@echo ">>> [3/7] Scenario B — JWT forgery (forged token -> frontend)"
	@$(MAKE) --no-print-directory test-fake || true
	@echo ""
	@echo ">>> [4/7] Scenario C — context access (role:user -> /api/admin)"
	@$(MAKE) --no-print-directory test-context-user-admin || true
	@echo ""
	@echo ">>> [5/7] Scenario D — role escalation (viewer JWT -> /api/admin)"
	@$(MAKE) --no-print-directory test-jwt-viewer-admin || true
	@echo ""
	@echo ">>> [6/7] Scenario E — device posture (admin JWT + firewall=disabled)"
	@$(MAKE) --no-print-directory test-posture-block || true
	@echo ""
	@echo ">>> [6.5/7] Allow pass — valid JWT end-to-end (generates frontend->backend mTLS edge)"
	@$(MAKE) --no-print-directory test-jwt-auto || true
	@echo "    Waiting 20s for Prometheus to scrape mTLS telemetry..."
	@sleep 20
	@echo ""
	@echo ">>> [7/7] Done. Open Kiali and screenshot:"
	@echo "    http://localhost:20000"
	@echo "    Graph -> Namespace: default -> Time range: Last 1m"
	@echo "    Save as: evidence/screenshots/kiali-topology.png"
	@echo ""
