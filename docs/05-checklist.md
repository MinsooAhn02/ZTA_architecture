# Project Checklist

## Implementation Status

### Core Infrastructure

| Component     | Status | Notes                                              |
| ------------- | ------ | -------------------------------------------------- |
| Minikube      | Done   | Configured for 4 CPU / 8 GB RAM                   |
| Istio 1.28.3  | Done   | Installed via `istioctl`, auto-downloaded if missing |
| Keycloak      | Done   | Deployed in cluster, realm `myrealm` configured    |
| OPA           | Done   | Deployed as ext-authz gRPC service, sidecar policy |
| Flask app     | Done   | Frontend + backend in one image, role-switched via env var |
| mTLS STRICT   | Done   | `k8s/peer-auth.yaml`                               |
| SPIFFE allowlist | Done | `k8s/authz-policy-backend.yaml`                  |
| JWT auth      | Done   | `k8s/jwt-auth.yaml` + `k8s/jwt-require-policy.yaml` |
| OPA Rego policy | Done | `k8s/opa-k8s.yaml`                               |

### Keycloak Users

| User         | Role     | Status | Used in    |
| ------------ | -------- | ------ | ---------- |
| `testuser`   | `admin`  | Done   | All scenarios |
| `vieweruser` | `viewer` | Done   | Scenario D |

> To add `vieweruser` if missing: `make setup-keycloak-viewer`

---

## Scenario Verification Results

All test cases run with `make test-all`. Final run: **ALL PASS**.
Full output: `evidence/test-results.txt`

### Scenario A — Lateral Movement Defense

| Test Case                         | Expected     | Result | Status |
| --------------------------------- | ------------ | ------ | ------ |
| No identity → deny                | 403          | 403    | PASS   |
| role:admin header → allow         | 200          | 200    | PASS   |
| Rogue pod (no sidecar) → backend  | 403/000/503  | 403    | PASS   |
| Wrong ServiceAccount → backend    | 403          | 403    | PASS   |
| Direct pod IP call → backend      | 403/000/503  | 503    | PASS   |

### Scenario B — JWT Authentication

| Test Case                         | Expected | Result | Status |
| --------------------------------- | -------- | ------ | ------ |
| Forged JWT (fake signature)       | 403      | 403    | PASS   |
| Tampered JWT (modified payload)   | 401      | 401    | PASS   |
| Valid Keycloak JWT                | 200      | 200    | PASS   |

### Scenario C — Context-Based Access Control

| Test Case                         | Expected | Result | Status |
| --------------------------------- | -------- | ------ | ------ |
| user + GET /api/data              | 200      | 200    | PASS   |
| user + GET /api/admin             | 403      | 403    | PASS   |
| user + POST /api/write            | 403      | 403    | PASS   |
| admin + POST /api/write           | 200      | 200    | PASS   |

### Scenario D — JWT Role Claim Access Control

| Test Case                         | Expected | Result | Status |
| --------------------------------- | -------- | ------ | ------ |
| admin JWT → GET /api/admin        | 200      | 200    | PASS   |
| viewer JWT → GET /api/data        | 200      | 200    | PASS   |
| viewer JWT → GET /api/admin       | 403      | 403    | PASS   |
| viewer JWT → POST /api/write      | 403      | 403    | PASS   |

### Scenario E — Device Posture Gate

| Test Case                         | Expected | Result | Status |
| --------------------------------- | -------- | ------ | ------ |
| admin JWT + firewall=enabled      | 200      | 200    | PASS   |
| admin JWT + firewall=disabled     | 403      | 403    | PASS   |

---

## Evidence Files

| File                                       | Contents                                      | Status |
| ------------------------------------------ | --------------------------------------------- | ------ |
| `evidence/test-results.txt`                | Full `make test-all` output with PASS/FAIL    | Done   |
| `evidence/opa-decision-logs.txt`           | Parsed OPA allow/deny decision log            | Done   |
| `evidence/attack-logs/lateral-movement.txt` | Lateral movement attack run output           | Done   |
| `evidence/attack-logs/jwt-forgery.txt`     | JWT forgery attack run output                 | Done   |
| `evidence/attack-logs/device-posture.txt`  | Device posture attack run output              | Done   |
| `evidence/vpn-zta-comparison.txt`          | WireGuard vs ZTA capability/performance table | Done   |
| `evidence/zta-vs-baseline-comparison.txt`  | Measured latency and QPS data                 | Done   |
| `evidence/screenshots/kiali-topology.png`  | Kiali service mesh graph                      | Done   |
| `evidence/screenshots/grafana-latency.png` | Grafana latency graph                         | Done   |
| `evidence/screenshots/keycloak-users.png`  | Keycloak users list                           | Done   |
| `evidence/screenshots/keycloak-realm.png`  | Keycloak realm config                         | Done   |

---

## Documentation Files

| File                           | Purpose                                                   | Status |
| ------------------------------ | --------------------------------------------------------- | ------ |
| `README.md`                    | Setup, quick start, dashboard guide, make commands        | Done   |
| `docs/what-it-can-do.md`       | Capabilities, scenarios, test commands, dashboards        | Done   |
| `docs/how-it-works.md`         | Architecture, request flow, defense layers, NIST mapping  | Done   |
| `docs/checklist.md`            | This file — implementation and verification status        | Done   |
| `docs/threat-model.md`         | Assets, adversaries, attack tree, bypass analysis         | Done   |
| `docs/final-report-draft.md`   | Compact final report with NIST mapping and scenario table | Done   |
| `docs/zta-unified-doc.md`      | Unified deep-dive architecture and analysis document      | Done   |

---

## What Changed from the Original Proposal (PDF → Current)

The original `Project_Proposal_ZTA_Implementation.pdf` outlined the goals.
Here is what was added or completed during implementation:

| Proposal Item                         | Status in PDF | Current Status | What was added                                    |
| ------------------------------------- | ------------- | -------------- | ------------------------------------------------- |
| Scenario A: Lateral movement defense  | Planned       | Complete       | pod-IP bypass test target added (`test-lateral-podip`) |
| Scenario B: JWT forgery defense       | Planned       | Complete       | Both forged (403) and tampered (401) test paths   |
| Scenario C: Context-based access      | Not specified | **New**        | OPA role + method + path policy + 4 test cases    |
| Scenario D: JWT claim authorization   | Not specified | **New**        | viewer user in Keycloak, JWT claim OPA rules      |
| Scenario E: Device posture            | Planned       | **Newly implemented** | X-Device-Firewall header simulation in OPA |
| Observability dashboards              | Planned       | Complete       | Kiali + Grafana + OPA logs all working            |
| VPN comparison (WireGuard)            | Planned       | Complete       | Benchmark-based comparison in evidence/           |
| Threat model documentation            | Not specified | **New**        | `docs/threat-model.md` with attack tree and NIST mapping |

---

## Known Limitations

| Limitation                                      | Scope                  | Production Path                               |
| ----------------------------------------------- | ---------------------- | --------------------------------------------- |
| Device posture header is client-controllable    | Scenario E demo only   | MDM / endpoint attestation signal injection   |
| role:admin header active alongside JWT path     | Scenarios A/C demo scaffolding | Remove header rules; enforce JWT-only (Scenario D) |
| Envoy ↔ OPA gRPC channel is plaintext           | Structural (circular dependency prevents sidecar injection) | NetworkPolicy restricting port 9191 to mesh-internal only (`k8s/opa-network-policy.yaml`) |
| VPN comparison is benchmark-based, not direct   | Performance section    | Same-host A/B measurement on cloud hardware   |
| Cluster-admin compromise breaks all controls    | Out of scope           | IAM hardening, audit, network policy          |
| Keycloak private key compromise invalidates JWT | Out of scope           | Key rotation policy, HSM storage              |
