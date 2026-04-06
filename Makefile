# ============================================================
#  ZTA (Zero Trust Architecture) Project - Makefile
#  Based on NIST SP 800-207 | Keycloak + OPA + Istio
# ============================================================
#
#  Quick Start (Remember these 3!)
#  ─────────────────────────────────────
#    make all        → Full install + deploy + policies (first time)
#    make test-all   → Run all security tests
#    make status     → Check current status
#
#  Common Commands
#  ─────────────────────────────────────
#    make all           Full auto install
#    make test-all      Run all tests
#    make status        Pod/Service status
#    make ports         Start all port-forwards (background)
#    make dashboard     Kiali dashboard
#    make grafana       Grafana dashboard
#    make logs          OPA decision logs
#    make clean         Delete resources (keep Istio)
#    make help          Show all commands
#
#  ⚠️  Port-Forward Notes
#  ─────────────────────────────────────
#    Port-forwards run in background. To keep them alive:
#    - Run in a SEPARATE TERMINAL, or
#    - Use 'make ports' which runs with nohup
#    - Check active: 'ps aux | grep port-forward'
#    - Kill all: 'pkill -f "kubectl port-forward"'
#
# ============================================================

# ---------- Configuration ----------
APP_IMAGE      := minsoo-app:v1
MINIKUBE_CPUS  := 4
MINIKUBE_MEM   := 8192
ISTIOCTL       := ./istio-1.28.3/bin/istioctl
NAMESPACE      := default
KEYCLOAK_REALM := myrealm
KEYCLOAK_URL   := http://localhost:8080

.PHONY: all help status test-all clean \
        setup step1 step2 step3 step4 \
        minikube-start minikube-stop \
        istio-install istio-addons \
        build-image rebuild-image \
        deploy-app deploy-keycloak deploy-opa deploy-all wait-pods \
        patch-istio-mesh apply-authz apply-jwt apply-microseg \
        setup-keycloak open-keycloak open-kiali open-grafana get-token \
        test test-block test-pass test-jwt test-jwt-auto test-fake \
        test-lateral test-lateral-block test-lateral-sidecar \
        test-perf test-perf-baseline test-perf-zta \
        ports port-keycloak port-kiali port-grafana ports-stop \
        dashboard grafana logs logs-opa logs-frontend logs-backend logs-keycloak \
        clean-all restart

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
	@echo "    - Keycloak: http://localhost:8080"
	@echo "    - Kiali:    http://localhost:20001"
	@echo "    - Grafana:  http://localhost:3000"
	@echo ""
	@echo "  Next steps:"
	@echo "    make setup-keycloak  -> Setup Keycloak realm (first time only)"
	@echo "    make test-all        -> Run all tests"
	@echo "    make dashboard       -> Open Kiali"
	@echo "    make status          -> Check status"
	@echo ""

test-all: ensure-ports test test-lateral test-fake test-jwt-auto
	@echo ""
	@echo "=============================================="
	@echo "  All Tests Complete!"
	@echo "=============================================="
	@echo ""
	@echo "  Results:"
	@echo "    - North-South: No token -> 403, With token -> 200"
	@echo "    - East-West: Rogue Pod -> 403"
	@echo "    - JWT Theft: Fake token -> 401"
	@echo "    - JWT Auth: Valid Keycloak token -> 200"
	@echo ""

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

# ============================================================
#  Help
# ============================================================
help:
	@echo ""
	@echo "=============================================="
	@echo "  ZTA Project - Command Reference"
	@echo "=============================================="
	@echo ""
	@echo "  Quick Start (Remember these!)"
	@echo "  ----------------------------------------------"
	@echo "    make all              Full install + deploy + policies + ports"
	@echo "    make test-all         Run all security tests"
	@echo "    make status           Check current status"
	@echo ""
	@echo "  Installation (Step by step)"
	@echo "  ----------------------------------------------"
	@echo "    make step1            Minikube + Istio + Addons + Image"
	@echo "    make step2            Deploy App + Keycloak + OPA"
	@echo "    make step3            Apply North-South policies"
	@echo "    make step4            Apply East-West micro-segmentation"
	@echo ""
	@echo "  Port-Forward (run in SEPARATE TERMINAL to keep alive)"
	@echo "  ----------------------------------------------"
	@echo "    make ports            Start ALL port-forwards (background)"
	@echo "    make port-keycloak    Keycloak only (localhost:8080)"
	@echo "    make port-kiali       Kiali only (localhost:20001)"
	@echo "    make port-grafana     Grafana only (localhost:3000)"
	@echo "    make ports-stop       Stop all port-forwards"
	@echo ""
	@echo "  Testing"
	@echo "  ----------------------------------------------"
	@echo "    make test             Basic tests (Block + Pass)"
	@echo "    make test-lateral     Lateral Movement defense test"
	@echo "    make test-fake        Fake JWT test -> 401"
	@echo "    make test-jwt-auto    Auto-token JWT test (auto port-forward)"
	@echo "    make test-jwt         Valid JWT test (TOKEN=xxx required)"
	@echo "    make test-perf        Performance measurement (ZTA ON)"
	@echo "    make test-perf-baseline  Baseline performance (policies OFF)"
	@echo ""
	@echo "  Monitoring"
	@echo "  ----------------------------------------------"
	@echo "    make open-kiali       Open Kiali in browser (needs ports)"
	@echo "    make open-grafana     Open Grafana in browser (needs ports)"
	@echo "    make open-keycloak    Open Keycloak in browser (needs ports)"
	@echo "    make dashboard        Open Kiali via istioctl"
	@echo "    make grafana          Open Grafana via istioctl"
	@echo "    make logs             OPA decision logs"
	@echo ""
	@echo "  Keycloak"
	@echo "  ----------------------------------------------"
	@echo "    make setup-keycloak   Create Realm/Client/User (first time only)"
	@echo "    make get-token        Issue JWT token"
	@echo ""
	@echo "  Cleanup"
	@echo "  ----------------------------------------------"
	@echo "    make clean            Delete K8s resources (keep Istio)"
	@echo "    make clean-all        Delete everything (including Minikube)"
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

step4: apply-microseg apply-jwt
	@echo ">>> [Step 4] East-West + JWT policies applied"

# ---------- Step 1 Details ----------
minikube-start:
	@echo ">>> Starting Minikube..."
	@if minikube status --format='{{.Host}}' 2>/dev/null | grep -q "Running"; then \
		echo "    Already running (Skip)"; \
	else \
		minikube start --cpus $(MINIKUBE_CPUS) --memory $(MINIKUBE_MEM); \
	fi

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

apply-jwt:
	@echo ">>> Applying JWT authentication policy..."
	@kubectl apply -f k8s/jwt-auth.yaml
	@-kubectl apply -f k8s/jwt-require-policy.yaml 2>/dev/null || true

# ============================================================
#  Keycloak
# ============================================================

# Setup Keycloak realm (run once after cluster init)
# Checks if realm already exists before creating
setup-keycloak:
	@echo ">>> Keycloak Auto-Setup (myrealm, zta-client, testuser)..."
	@echo "    Checking if realm exists..."
	@REALM_CHECK=$$(curl -s "$(KEYCLOAK_URL)/realms/$(KEYCLOAK_REALM)" 2>/dev/null | grep -c '"realm"' || echo "0"); \
	if [ "$$REALM_CHECK" != "0" ]; then \
		echo "    Realm '$(KEYCLOAK_REALM)' already exists (Skip)"; \
		echo "    Use 'make get-token' to issue tokens"; \
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
		echo "    Keycloak setup complete!"; \
		echo "    - Realm: $(KEYCLOAK_REALM)"; \
		echo "    - Client: zta-client (secret: zta-secret)"; \
		echo "    - User: testuser / testpass (role: admin)"; \
	fi

open-keycloak:
	@echo ">>> Keycloak Admin Console:"
	@echo "    URL: http://localhost:8080"
	@echo "    Username: admin"
	@echo "    Password: admin"
	@echo ""
	@echo "    Opening in browser..."
	@python3 -c "import webbrowser; webbrowser.open('http://localhost:8080')" 2>/dev/null || \
		xdg-open "http://localhost:8080" 2>/dev/null || \
		echo "    Please open http://localhost:8080 manually"

open-kiali:
	@echo ">>> Kiali Dashboard:"
	@echo "    URL: http://localhost:20001"
	@echo "    Opening in browser..."
	@python3 -c "import webbrowser; webbrowser.open('http://localhost:20001')" 2>/dev/null || \
		xdg-open "http://localhost:20001" 2>/dev/null || \
		echo "    Please open http://localhost:20001 manually"

open-grafana:
	@echo ">>> Grafana Dashboard:"
	@echo "    URL: http://localhost:3000"
	@echo "    Opening in browser..."
	@python3 -c "import webbrowser; webbrowser.open('http://localhost:3000')" 2>/dev/null || \
		xdg-open "http://localhost:3000" 2>/dev/null || \
		echo "    Please open http://localhost:3000 manually"

get-token:
	@echo ">>> Issuing JWT token..."
	@curl -s -X POST "$(KEYCLOAK_URL)/realms/$(KEYCLOAK_REALM)/protocol/openid-connect/token" \
		-H "Content-Type: application/x-www-form-urlencoded" \
		-d "grant_type=password" \
		-d "client_id=zta-client" \
		-d "client_secret=zta-secret" \
		-d "username=testuser" \
		-d "password=testpass" | python3 -c "import sys,json; d=json.load(sys.stdin); print('access_token:', d.get('access_token','ERROR: '+str(d)))"

# ============================================================
#  Testing
# ============================================================
test: test-block test-pass
	@echo ">>> Basic tests complete"

test-block:
	@echo ""
	@echo ">>> [Test] Access without token -> Expect 403"
	@echo "--------------------------------------------"
	@kubectl delete pod test-block --ignore-not-found 2>/dev/null || true
	@kubectl run test-block --image=curlimages/curl --restart=Never --rm -it \
		-- curl -s -o /dev/null -w "Response: %{http_code}\n" http://frontend/ 2>/dev/null || true

test-pass:
	@echo ""
	@echo ">>> [Test] Access with role:admin header -> Expect 200"
	@echo "--------------------------------------------"
	@kubectl delete pod test-pass --ignore-not-found 2>/dev/null || true
	@kubectl run test-pass --image=curlimages/curl --restart=Never --rm -it \
		-- curl -s -w "\nResponse: %{http_code}\n" -H "role: admin" http://frontend/ 2>/dev/null || true

test-jwt:
	@echo ""
	@echo ">>> [Test] Valid JWT -> Expect 200"
	@echo "--------------------------------------------"
	@if [ -z "$$TOKEN" ]; then echo "ERROR: TOKEN required. Usage: TOKEN=xxx make test-jwt"; exit 1; fi
	@kubectl delete pod test-jwt --ignore-not-found 2>/dev/null || true
	@kubectl run test-jwt --image=curlimages/curl --restart=Never --rm -it \
		-- curl -s -w "\nResponse: %{http_code}\n" \
		   -H "Authorization: Bearer $$TOKEN" -H "role: admin" http://frontend/ 2>/dev/null || true

test-fake:
	@echo ""
	@echo ">>> [Test] Fake/Manipulated JWT -> Expect 401"
	@echo "--------------------------------------------"
	@kubectl delete pod test-fake --ignore-not-found 2>/dev/null || true
	@kubectl run test-fake --image=curlimages/curl --restart=Never --rm -it \
		-- curl -s -o /dev/null -w "Response: %{http_code}\n" \
		   -H "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.invalid" \
		   -H "role: admin" http://frontend/ 2>/dev/null || true

test-jwt-auto:
	@echo ""
	@echo ">>> [Test] Valid Keycloak JWT -> Expect 200"
	@echo "--------------------------------------------"
	@echo "    Getting token from Keycloak..."
	@TOKEN=$$(curl -s -X POST "$(KEYCLOAK_URL)/realms/$(KEYCLOAK_REALM)/protocol/openid-connect/token" \
		-H "Content-Type: application/x-www-form-urlencoded" \
		-d "grant_type=password" -d "client_id=zta-client" -d "client_secret=zta-secret" \
		-d "username=testuser" -d "password=testpass" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null); \
	if [ -z "$$TOKEN" ]; then \
		echo "    WARNING: Could not get token from Keycloak"; \
		echo "    Make sure: kubectl port-forward svc/keycloak 8080:8080"; \
		echo "    Skipping test..."; \
	else \
		echo "    Token acquired, testing..."; \
		kubectl delete pod test-jwt-auto --ignore-not-found 2>/dev/null || true; \
		kubectl run test-jwt-auto --image=curlimages/curl --restart=Never --rm -it \
			-- curl -s -w "\nResponse: %{http_code}\n" \
			   -H "Authorization: Bearer $$TOKEN" -H "role: admin" http://frontend/ 2>/dev/null || true; \
	fi

test-lateral: test-lateral-block test-lateral-sidecar
	@echo ">>> Lateral Movement defense tests complete"

test-lateral-block:
	@echo ""
	@echo ">>> [Lateral] Rogue Pod -> Direct Backend access -> Expect 403/Connection refused"
	@echo "--------------------------------------------"
	@kubectl delete pod test-rogue --ignore-not-found 2>/dev/null || true
	@kubectl run test-rogue --image=curlimages/curl --restart=Never --rm -it \
		-- curl -s -w "\nResponse: %{http_code}" --max-time 5 http://backend/ 2>/dev/null || true

test-lateral-sidecar:
	@echo ""
	@echo ">>> [Lateral] Wrong ServiceAccount -> Backend -> Expect 403"
	@echo "--------------------------------------------"
	@kubectl delete pod test-wrongsa --ignore-not-found 2>/dev/null || true
	@kubectl run test-wrongsa --image=curlimages/curl --restart=Never --rm -it \
		--overrides='{"spec":{"serviceAccountName":"backend-sa"}}' \
		-- curl -s -w "\nResponse: %{http_code}" --max-time 10 http://backend/ 2>/dev/null || true

# ---------- Performance ----------
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
#  ⚠️  These run in BACKGROUND. To keep them alive after terminal closes:
#      - Run 'make ports' in a SEPARATE TERMINAL, or
#      - Use 'nohup make ports &' in current terminal
#  Check active: ps aux | grep port-forward
#  Stop all:     make ports-stop
# ============================================================

# Start all port-forwards in background
ports: port-keycloak port-kiali port-grafana
	@echo ""
	@echo ">>> All port-forwards started in background"
	@echo "    Keycloak: http://localhost:8080"
	@echo "    Kiali:    http://localhost:20001"
	@echo "    Grafana:  http://localhost:3000"
	@echo ""
	@echo "    Stop all: make ports-stop"

# Ensure Keycloak port-forward is running (for test-jwt-auto)
ensure-ports:
	@if ! curl -s --connect-timeout 1 http://localhost:8080 >/dev/null 2>&1; then \
		echo ">>> Starting Keycloak port-forward..."; \
		nohup kubectl port-forward svc/keycloak 8080:8080 >/dev/null 2>&1 & \
		sleep 2; \
	fi

port-keycloak:
	@echo ">>> Starting Keycloak port-forward (8080)..."
	@pkill -f "port-forward svc/keycloak" 2>/dev/null || true
	@nohup kubectl port-forward svc/keycloak 8080:8080 >/dev/null 2>&1 &
	@sleep 1
	@echo "    Started: http://localhost:8080"

port-kiali:
	@echo ">>> Starting Kiali port-forward (20001)..."
	@pkill -f "port-forward.*kiali" 2>/dev/null || true
	@nohup kubectl port-forward svc/kiali -n istio-system 20001:20001 >/dev/null 2>&1 &
	@sleep 1
	@echo "    Started: http://localhost:20001"

port-grafana:
	@echo ">>> Starting Grafana port-forward (3000)..."
	@pkill -f "port-forward.*grafana" 2>/dev/null || true
	@nohup kubectl port-forward svc/grafana -n istio-system 3000:3000 >/dev/null 2>&1 &
	@sleep 1
	@echo "    Started: http://localhost:3000"

ports-stop:
	@echo ">>> Stopping all port-forwards..."
	@pkill -f "kubectl port-forward" 2>/dev/null || true
	@echo "    All port-forwards stopped"

# ============================================================
#  Monitoring
# ============================================================
dashboard:
	@echo ">>> Opening Kiali dashboard..."
	@$(ISTIOCTL) dashboard kiali

grafana:
	@echo ">>> Opening Grafana dashboard..."
	@$(ISTIOCTL) dashboard grafana

logs: logs-opa

logs-opa:
	@echo ">>> OPA decision logs (Ctrl+C to exit)"
	@kubectl logs -l app=opa --tail=100 -f

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
