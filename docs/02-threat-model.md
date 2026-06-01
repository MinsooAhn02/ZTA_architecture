# ZTA Threat Model and Attack Analysis

> Key terms used throughout this document (pod, mTLS, SPIFFE/SVID, East-West traffic, North-South traffic, Rego, gRPC) are defined in the [Introduction](00-intro.md).

**Date:** 2026-04-14
**Reference:** NIST SP 800-207

---

## 1. Scope

**In scope:** Protect backend read/write/admin operations from external attackers, credential abusers, token forgers, and lateral movement from inside the cluster. Decisions are made using identity, context, and policy.

**Out of scope:** Cluster-admin compromise, Keycloak private key theft, Istio CA root key theft, supply-chain compromise of container images.

---

## 2. Protected Assets

| ID | Asset |
|---|---|
| A1 | Backend API (read/write/admin endpoints) |
| A2 | Keycloak JWT signing key (trust anchor) |
| A3 | Istio mTLS trust chain (workload identity) |
| A4 | Admin credentials and tokens |
| A5 | Service-to-service trust boundary (frontend → backend) |

---

## 3. Adversary Model

**T1 — External unauthenticated attacker:** Sends HTTP requests to exposed entry points. Goal: access data or admin functions without identity.

**T2 — Credential theft / low-privilege attacker:** Holds a valid but low-privilege token. Goal: escalate to admin path or write operations.

**T3 — Token forgery attacker:** Understands JWT format, can alter base64 payload or header. Goal: bypass signature and claim checks.

**T4 — Lateral movement attacker:** Runs a rogue pod or compromises one workload inside the cluster. Goal: pivot to backend directly via the internal network.

**T5 (out of scope) — Super attacker:** Root-level cluster or IdP compromise. Bypasses all trust anchors directly.

---

## 4. Attack Tree

```
Backend sensitive CRUD
│
├── T1: Direct external call without identity
│   └── Blocked by JWT/authz gate (401/403)
│
├── T3: Forged or tampered JWT
│   ├── Fake signature token
│   │   └── Blocked by no-principal authz deny path (403)
│   └── Tampered real token payload
│       └── Blocked by signature mismatch (401)
│
├── T2: Valid low-privilege identity abusing privilege
│   ├── viewer → /api/admin
│   │   └── Blocked by OPA path+role policy (403)
│   └── viewer → POST /api/write
│       └── Blocked by OPA method+role policy (403)
│
├── T4: Internal lateral movement
│   ├── Rogue pod without sidecar
│   │   └── Blocked by mTLS STRICT / policy chain (403 or handshake failure)
│   ├── Sidecar pod with wrong ServiceAccount
│   │   └── Blocked by SPIFFE/SA authorization policy (403)
│   └── Direct pod-IP call attempt
│       └── Blocked by inbound Envoy + policy (503)
│
└── T2+T4: Valid admin token from unhealthy device
    └── Blocked by posture condition (X-Device-Firewall=disabled → 403)
```

---

## 5. Defense Layer Mapping

| Layer | Question answered | Control |
|---|---|---|
| 1 — mTLS workload identity | Is this workload cryptographically known? | PeerAuthentication STRICT + Istio cert |
| 2 — SPIFFE allowlist | Is this workload permitted to call the backend? | AuthorizationPolicy allowlist |
| 3 — JWT authenticity | Was this token issued by a trusted IdP? | RequestAuthentication + JWKS verification |
| 4 — OPA context policy | Should this identity do this action on this resource? | Rego: role + method + path + posture |

**Security property:** A single layer bypass is insufficient. An attacker must break multiple independent controls — unless they are already out of scope (T5).

---

## 6. Bypass Analysis by Scenario

**Scenario A (Lateral movement)**
A sidecar-less rogue pod cannot complete the mTLS handshake. A pod with the wrong ServiceAccount is rejected by the SPIFFE allowlist. Hard bypass requires cluster-level compromise (out of scope).

**Scenario B (JWT forgery/tampering)**
A fake token is denied at the no-principal authz path (403). A tampered real token fails signature verification (401). Hard bypass requires IdP private key compromise (out of scope).

**Scenario C (Header-based context)**
The role header model is intentionally weak by design — this scenario exists to demonstrate the limitation. Scenario D closes this gap with signed JWT claims. The header rules are gated behind the OPA `demo_mode` flag (`k8s/opa-k8s.yaml`); setting `demo_mode = false` removes the header-spoofing path entirely, leaving only signed-claim authorization active.

**Scenario D (JWT claim authorization)**
A viewer token on an admin or write path is blocked by OPA's claim+resource policy. Residual risk: a stolen admin token remains valid until expiry.

**Scenario E (Device posture)**
The posture signal is header-simulated in this sandbox — a known limitation. In production, the signal would be injected by a trusted MDM or endpoint attestation system at the gateway, making it non-forgeable by the client.

---

## 7. NIST SP 800-207 Tenet Mapping

| Tenet | Principle | Implementation | Evidence |
|---|---|---|---|
| 1 | All resources are protected | Frontend, backend, Keycloak, OPA all treated as protected assets | Policy files and scenario matrix |
| 2 | Secure all communication regardless of location | East-West uses mTLS STRICT + SPIFFE policy | Lateral movement tests |
| 3 | Per-session access grant | JWT per-request validation, short token TTL | JWT forgery/tamper/valid tests |
| 4 | Dynamic policy decisions | OPA evaluates role + method + path + posture | Context and JWT-role scenarios |
| 5 | Asset integrity monitoring | Device posture check demonstrates integrity signal concept | Posture allow/deny tests |
| 6 | Dynamic authn/authz | Every request re-evaluated; no pre-approved sessions | 401 vs 403 behavior and OPA logs |
| 7 | Collect telemetry | OPA decision logs, Kiali topology, Grafana metrics | `make logs-pretty`, dashboards |
