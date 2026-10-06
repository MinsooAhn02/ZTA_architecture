# ZTA v2 implementation contract

Approved implementation: W01-W10 and S01-S34. Baseline commit 49daa49; original repository/evidence preserved. Two GPT-6 Luna medium workers own policy/app and suite/performance. Main owns runtime/CLI/dashboard/Makefile/integration/docs. Cluster mutations are main-only.

## Environment

- Profile/context/namespace: zta-v2. Private MINIKUBE_HOME and KUBECONFIG, Kubernetes 1.34.0, Istio 1.28.3, containerd, Calico, 4 CPU/8192 MB. Stop original profile before v2 startup.
- Ports: dashboard 5002, Keycloak 18081, Kiali 20010, Grafana 20012; localhost only.
- Issuer http://localhost:18081/realms/zta-v2. Clients zta-app (zta-app-demo-secret) and zta-posture (zta-posture-demo-secret); access audiences zta-frontend/zta-backend, TTL300; posture audience zta-posture, TTL120, sub equal, admin-managed posture-healthy role, zero policy expiry grace.
- Users admin-user/adminpass, viewer-user/viewerpass, unhealthy-admin/unhealthypass, unhealthy-viewer/unhealthypass. Admin console admin/admin is sandbox-only.
- Protected GET / and /api/data: viewer/admin; GET /api/admin and POST /api/write: admin. Require both credentials in strict mode. Health GET /healthz returns no sensitive data. Ignore role and X-Device-Firewall as evidence of authorization.

## Owned interfaces

Runtime in scripts/runtime.py exposes source_root (Path), profile, namespace, keycloak_url, issuer, mode, env; run(argv,input=None,check=True,timeout=...)->CompletedProcess; kubectl_argv(*args)->list; kubectl_process(*args,input=None,check=False,timeout=...)->CompletedProcess; kubectl(*args,input=None,json_output=False,check=True,timeout=...)->str/dict; apply_mode(mode), wait_ready(), sync_jwks(), opa_query(query).

scripts/identity.py: provision(runtime); issue_tokens(runtime,username='admin-user',kind='healthy')->dict with access,posture,refresh_access,refresh_posture; fetch_jwks(runtime)->dict. No raw tokens in stdout/argv/evidence.

scripts/suite.py: request(runtime,url=None,path='/api/data',method='GET',headers=None,body=None,client='curl-client')->observation; run_suite(runtime,run_dir)->list of 33 rows (S32 excluded).

scripts/performance.py: run_performance(runtime,run_dir)->list of S32 rows; official five modes x concurrency1,4 x3 repeats x30s, 10s warmup each cell. Restore strict in finally; failed restoration invalidates run.

Canonical JSONL row: schema_version=1,run_id,case_id,level(unit/integration/experiment),request_id,status(PASS/FAIL/ERROR),expected(dict),observed(dict),evidence(list of sanitized relative paths). Observed includes kind(http/transport_denied/timeout/error),http_code,curl_exit,kubectl_exit,body_ok,layer where available. Unknown000/timeouts are ERROR. Process exits 0 success/1 assertions failed/2 infrastructure.

## Manifest and policy rendering

Worker A provides k8s/v2-resources.yaml with __APP_IMAGE__, __ISSUER__, __INLINE_JWKS__ placeholders; k8s/policy.rego; k8s/mask.rego. Main creates opa-policy ConfigMap containing both modules and jwt-trust ConfigMap containing jwt_trust.json: {"jwt_trust":{"issuer":issuer,"jwks":publicJwks,"mode":mode,"posture_max_age":120}}. Mount /policies and /trust with OPA --watch.

Deployments frontend/backend/opa/keycloak/curl-client/rogue-client/wrongsa-client/frontend-probe/fortio-client. frontend-probe uses frontend-sa; wrongsa-client uses backend-sa; rogue has no sidecar. Fortio uses sidecar. Labels app:<deployment-name>.

Modes sidecar,mtls,jwt,opa-role,strict. Sidecar removes JWT/CUSTOM/backendALLOW and uses PERMISSIVE+TLS DISABLE. mtls has STRICT+SPIFFE but no JWT/CUSTOM. jwt adds JWT mandatory; opa-role adds role CUSTOM without posture. strict is full authz+posture. All modes retain the same application/resources/network isolation. Main chooses generated policy deltas, not edits tracked files during experiments.

## Main CLI/UI

CLI actions check/start/test/perf/verify/dashboard/status/stop/restore-strict/jwt-refresh/case. One shared per-user lock; no concurrent cluster changes/tests. Dashboard POST /api/run/<allowlisted-id> ->202 run_id/events_url or409 busy. GET /api/runs/<uuid>/events only streams. GET start ->405; Host/Origin/CSRF required for POST; stdout rendered textContent.

No baseline test can be counted as v2 PASS; no unimplemented case may be substituted with a synthetic PASS. Evidence unit vs integration level stays explicit. Existing PDF is historical; v2 Markdown will describe verified differences and limits.
