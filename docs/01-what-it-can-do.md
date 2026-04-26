# What This Project Can Do

> Key terms used throughout this document (pod, mTLS, SPIFFE/SVID, East-West traffic, North-South traffic, Rego, gRPC) are defined in the [Introduction](00-intro.md).

## Overview

This sandbox proves that a Zero Trust Architecture (ZTA) can be built entirely from open-source tools
on a local Kubernetes cluster. Every incoming request — whether from an external user, an internal service,
or an automated script — is verified by three independent security layers before reaching any application.
No implicit trust is granted, regardless of where the request comes from.

---

## Security Capabilities

### What it blocks

| Threat                                      | How it's blocked                                   | Scenario |
| ------------------------------------------- | -------------------------------------------------- | -------- |
| Unauthenticated external access             | OPA denies requests with no identity               | A        |
| Pod-to-pod lateral movement (no sidecar)    | mTLS STRICT: pod without certificate is rejected   | A        |
| Lateral movement with wrong service account | SPIFFE allowlist: only frontend-sa can reach backend | A      |
| Forged JWT token (fake signature)           | Istio JWKS signature check: 403 returned           | B        |
| Tampered JWT payload                        | RSA verification fails: 401 returned               | B        |
| Over-privileged request (wrong method/path) | OPA role + method + path policy: 403 returned      | C        |
| Role escalation via JWT claim manipulation  | Istio verifies signature before OPA reads claims   | D        |
| Valid credential from unhealthy device      | OPA device posture check: 403 if firewall=disabled | E        |

---

## The Five Security Scenarios

### Scenario A — Lateral Movement Defense

**Why this matters:** Firewalls and VPNs stop traffic at the network boundary, but have no visibility into East-West traffic between internal services. Once an attacker is inside — via a compromised pod or stolen credential — nothing in a traditional setup prevents them from reaching other services freely.

**What it is:** An attacker compromises one pod inside the cluster and tries to reach other services.

**What it blocks:**
- A rogue pod without Istio sidecar cannot complete the mTLS handshake — connection dropped.
- A pod with a sidecar but the wrong ServiceAccount identity is rejected by the backend's allowlist.
- A direct call to the backend's pod IP is also blocked by the inbound policy.

**Test commands:**
```bash
make test-lateral-block      # rogue pod (no sidecar) → blocked
make test-lateral-sidecar    # wrong ServiceAccount → 403
make test-lateral-podip      # direct pod IP call → blocked
```

---

### Scenario B — JWT Forgery & Tampering Defense

**Why this matters:** Server-side token checks rely on each application implementing validation correctly. ZTA moves this to the infrastructure layer — Istio verifies the cryptographic signature before the request reaches any application code, making forgery impossible regardless of which service is targeted.

**What it is:** An attacker tries to bypass authentication by crafting a fake token or modifying a real one.

**What it blocks:**
- A completely fake JWT (random signature) → rejected as no valid principal.
- A real JWT with the payload changed (e.g., adding admin role) → RSA signature mismatch → 401.

**Test commands:**
```bash
make test-fake               # forged JWT → 403
make test-jwt-tampered       # tampered real JWT → 401
make test-jwt-auto           # valid Keycloak JWT → 200
```

---

### Scenario C — Context-Based Access Control

**Why this matters:** A valid identity is not sufficient authorization. A firewall or IDP only answers "is this user authenticated?" — not "should this user be allowed to POST to this admin endpoint right now?" OPA evaluates the full context of every request.

**What it is:** Even authenticated users are restricted based on *what they are doing*, not just *who they are*.
A `user` role can read general data but cannot write or access admin paths.

**Policy matrix:**

| Role    | Method | Path        | Decision |
| ------- | ------ | ----------- | -------- |
| `admin` | any    | any         | ALLOW    |
| `user`  | GET    | /api/data   | ALLOW    |
| `user`  | GET    | /api/admin  | DENY     |
| `user`  | POST   | any         | DENY     |
| none    | any    | any         | DENY     |

**Test commands:**
```bash
make test-context-user-get    # user + GET /api/data → 200
make test-context-user-admin  # user + GET /api/admin → 403
make test-context-user-post   # user + POST /api/write → 403
make test-context-admin-post  # admin + POST /api/write → 200
```

---

### Scenario D — JWT Role Claim Access Control

**Why this matters:** Scenario C shows that header-only role claims are client-controllable — any caller can set `role: admin`. This scenario closes that gap: the role is embedded in a JWT signed by Keycloak's private key, making it cryptographically tamper-proof.

**What it is:** Identity comes from Keycloak (signed JWT), not a manually set HTTP header.
Two users — `testuser` (admin) and `vieweruser` (viewer) — get different access based on their
cryptographically-bound role claims.

**Why this matters:** In Scenario C, any client can set `role: admin` header. Here, the role is
embedded in a JWT signed by Keycloak's private key — the client cannot change it.

**Test commands:**
```bash
make test-jwt-admin-all       # admin JWT → /api/admin → 200
make test-jwt-viewer-read     # viewer JWT → /api/data → 200
make test-jwt-viewer-admin    # viewer JWT → /api/admin → 403
make test-jwt-viewer-post     # viewer JWT → POST /api/write → 403
```

---

### Scenario E — Device Posture Gate

**Why this matters:** Neither firewalls nor application proxies can deny access based on the health of the requesting device. A user with a valid token on a machine running software with a known critical vulnerability should not have the same access as a user on a healthy, patched device. ZTA makes device state a first-class input to the authorization decision.

**What it is:** Even a user with a valid admin JWT is denied if their device is flagged as unhealthy.
Posture is signaled via `X-Device-Firewall` header (simulation model for this sandbox).

**What it demonstrates:** Access decisions consider *not just who you are* but also *the health of the
device you are using*.

> **Limitation:** In this sandbox, the posture header is client-controlled (demo only).
> In production, this signal would come from a trusted MDM or endpoint attestation system.

**Test commands:**
```bash
make test-posture-ok          # admin JWT + firewall=enabled → 200
make test-posture-block       # admin JWT + firewall=disabled → 403
make test-posture             # run both together
```

---

## Run All Scenarios at Once

```bash
make test-all
```

All 20 test cases across Scenarios A–E. Every case passed in the final validation run
(see `evidence/test-results.txt`).

---

## Observability Dashboards

Three dashboards are available for monitoring the running cluster.

### Start port-forwards first

```bash
make ports
```

### Kiali — Service Mesh Topology

```bash
make open-kiali    # http://localhost:20001
```

- Visualizes real-time traffic between services
- Shows mTLS lock icon on encrypted connections
- Red edges = errors (403, 401, 500)
- Confirms Envoy sidecar injection on all pods

### Grafana — Metrics and Performance

```bash
make open-grafana  # http://localhost:3000
```

- Istio Service Dashboard: request rate, error rate, latency (p50 / p90 / p99)
- Istio Mesh Dashboard: mTLS coverage percentage across the mesh
- Istio Workload Dashboard: per-service breakdown

### Keycloak — Identity Provider Admin

```bash
make open-keycloak  # http://localhost:8080  (admin / admin)
```

- View users: `testuser` (admin role) and `vieweruser` (viewer role)
- View realm roles, client config, and JWT settings
- `zta-client` is the OAuth2 client configured for this project

---

## Key Make Commands Summary

| Command              | What it does                                        |
| -------------------- | --------------------------------------------------- |
| `make setup`         | Full environment: minikube + Istio + app + policies |
| `make test-all`      | Run all 5 scenario tests                            |
| `make demo`          | Step-by-step storytelling demo (A → E)              |
| `make ports`         | Start all port-forwards in background               |
| `make ports-stop`    | Stop all port-forwards                              |
| `make open-kiali`    | Open Kiali in browser                               |
| `make open-grafana`  | Open Grafana in browser                             |
| `make open-keycloak` | Open Keycloak in browser                            |
| `make logs-pretty`   | Parsed OPA decision log summary                     |
| `make status`        | Cluster and service status overview                 |
| `make clean`         | Remove app and policy resources                     |
| `make clean-all`     | Full teardown including Istio and minikube          |
