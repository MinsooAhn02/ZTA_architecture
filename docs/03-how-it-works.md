# How It Works

> Key terms used throughout this document (pod, mTLS, SPIFFE/SVID, East-West traffic, North-South traffic, Rego, gRPC) are defined in the [Introduction](00-intro.md).

## The Core Idea

Traditional security operates like a castle with a moat: once you're inside the walls, everything trusts you.
Zero Trust Architecture (ZTA) throws out that assumption — it treats *every request* as potentially hostile,
regardless of whether it comes from outside the network or from a pod sitting right next to the target.

**Every request must prove its identity and be authorized before it reaches the application.**
The application itself handles zero security logic.

---

## Three Core Components

| Component | Tool     | Role                                                                 |
| --------- | -------- | -------------------------------------------------------------------- |
| PEP (Policy Enforcement Point) | Istio / Envoy sidecar | Intercepts all traffic, enforces decisions |
| PDP (Policy Decision Point)    | OPA (Open Policy Agent) | Evaluates policy, returns allow or deny |
| IdP (Identity Provider)        | Keycloak | Issues signed JWT tokens, manages users and roles |

These map directly to NIST SP 800-207 Figure 1, the reference architecture for ZTA.

---

## How a Request Flows Through the System

Two traffic directions are relevant to this architecture:

- **North-South traffic** — requests entering the cluster from outside (external user → internal service). This is what firewalls traditionally guard. ZTA enforces JWT verification and OPA authorization on every inbound request.
- **East-West traffic** — requests between services inside the cluster (pod → pod). This is the direction firewalls have no visibility into. ZTA enforces mTLS workload identity and SPIFFE-based allowlists on every internal connection.

```
External Client
      │
      │  HTTP request
      ▼
┌─────────────────────────────────┐
│  Istio Ingress Gateway          │  ← Entry point for north-south traffic
│  (terminates external TLS)      │
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│  Envoy Sidecar (frontend pod)   │  ← Intercepts the request BEFORE the app sees it
│  1. Checks JWT signature        │     via Keycloak's public key (JWKS)
│  2. Calls OPA via gRPC          │
└────────────────┬────────────────┘
                 │  gRPC CheckRequest
                 ▼
┌─────────────────────────────────┐
│  OPA (Policy Decision Point)    │  ← Evaluates Rego policy rules
│  Inputs: JWT claims, HTTP       │     Outputs: allow / deny
│  method, path, device posture   │
└────────────────┬────────────────┘
                 │  CheckResponse
                 ▼
┌─────────────────────────────────┐
│  Envoy enforces the decision    │  ← allow → forward to app
│                                 │     deny  → return 403/401 to client
└────────────────┬────────────────┘
                 │  (if allowed)
                 ▼
┌─────────────────────────────────┐
│  Frontend App (Flask)           │  ← App only sees requests that passed all checks
│  Calls backend over mTLS        │
└────────────────┬────────────────┘
                 │  mTLS (SPIFFE/SVID)
                 ▼
┌─────────────────────────────────┐
│  Envoy Sidecar (backend pod)    │  ← East-west enforcement
│  Checks: mTLS cert + SPIFFE ID  │     Only frontend-sa is allowed
└────────────────┬────────────────┘
                 │  (if allowed)
                 ▼
┌─────────────────────────────────┐
│  Backend App (Flask)            │
└─────────────────────────────────┘
```

**Key point:** The Flask application never handles authentication or authorization.
If a request reaches the app, it has already passed every security layer.

---

## The Four Defense Layers

### Layer 1 — mTLS Identity (East-West)

Every pod-to-pod connection must use mutual TLS. Both sides present a certificate.
Certificates are in SPIFFE/SVID format, issued by Istio's built-in certificate authority.

- A pod without an Istio sidecar has no certificate → cannot connect.
- Configured in: `k8s/peer-auth.yaml` (`mode: STRICT`)

### Layer 2 — SPIFFE Allowlist (East-West)

Even if a pod *has* a sidecar, it must match the allowed ServiceAccount identity.
Only `frontend-sa` is allowed to reach the backend. Any other pod — even a legitimate
internal service — is denied.

- SPIFFE ID format: `cluster.local/ns/default/sa/frontend-sa`
- Configured in: `k8s/authz-policy-backend.yaml`

### Layer 3 — JWT Signature Verification (North-South)

Every external request carrying a JWT has its signature verified against Keycloak's public key.
Keycloak holds the private key (signs tokens); Istio uses the public key (verifies tokens).

- A fake token with a random signature → 403 (no valid principal established)
- A real token with a modified payload → 401 (signature mismatch)
- Configured in: `k8s/jwt-auth.yaml` + `k8s/jwt-require-policy.yaml`

### Layer 4 — OPA Context Authorization (All Traffic)

After identity is established, OPA evaluates the full context of the request:
role + HTTP method + request path + device posture. This is the "never just who you are,
but also what you're doing and from where" layer.

- Configured in: `k8s/opa-k8s.yaml` (Rego policy)
- OPA logs every allow/deny decision to stdout for audit purposes.

**Architectural note — OPA and the service mesh:**
OPA runs with sidecar injection disabled (`sidecar.istio.io/inject: "false"`). This is intentional: injecting an Envoy sidecar into OPA would cause a circular dependency — the sidecar would call OPA for authorization on OPA's own traffic. As a result, the Envoy ↔ OPA gRPC channel (port 9191) is not mTLS-encrypted in this sandbox. The production mitigation is a NetworkPolicy restricting port 9191 to mesh-internal traffic only (see `k8s/opa-network-policy.yaml`).

---

## How JWT Authentication and Authorization Work Together

This is important to understand: Istio handles *authentication* (is this token real?),
OPA handles *authorization* (is this identity allowed to do this?).

```
Client sends:  Authorization: Bearer <JWT>
                                      │
                        Istio verifies signature:
                          RSA_verify(payload, signature, Keycloak_pubkey)
                                      │
                    ┌─────────────────┴──────────────────┐
                 Invalid                               Valid
                    │                                     │
               401 / 403                         OPA receives request
               (before OPA                       with verified claims
                even runs)                               │
                                           OPA decodes JWT payload:
                                           realm_access.roles → ["admin"]
                                                         │
                                             Evaluates policy rules
                                             (role, method, path, posture)
                                                         │
                                             allow → 200 / deny → 403
```

OPA uses `io.jwt.decode()` which does NOT re-verify the signature — it just reads the claims.
This is intentional: Istio already verified it. Doing it twice would waste time with no added security.

---

## OPA Policy Logic (Simplified)

The Rego policy in `k8s/opa-k8s.yaml` covers these decision rules:

```
default allow = false

# Toggle: gates the header-based demo rules below.
# Production: set demo_mode = false → only the cryptographic JWT path (D/E) stays active.
demo_mode = true

# East-West: frontend-sa can GET non-admin paths
allow if source = frontend-sa AND method = GET AND path ≠ /api/admin

# ── DEMO SCAFFOLDING (Scenario A/C only — gated by demo_mode) ──
# role:admin header → allow  [client-controllable, not cryptographically bound]
allow if demo_mode AND role header = admin AND device is healthy

# role:user header → GET only, no /api/admin  [Scenario C: context control demo]
allow if demo_mode AND role header = user AND method = GET AND path ≠ /api/admin
# ─────────────────────────────────────────────────────────────────

# JWT claim admin: (Scenario D)
allow if JWT has role:admin AND device is healthy

# JWT claim viewer: read-only, no admin paths (Scenario D)
allow if JWT has role:viewer AND method = GET AND path ≠ /api/admin

# Device posture helper (Scenario E):
device_is_healthy if X-Device-Firewall header is missing or = "enabled"

# Audit-only (not used by `allow`): surfaces a reason in OPA decision logs so
# operators can distinguish missing / non_bearer / malformed_jwt / ok. View via `make logs-pretty`.
auth_reason = "missing" | "non_bearer" | "malformed_jwt" | "ok"
```

> **Note on enforcement vs. authentication:** `demo_mode` only gates the *header*-based
> rules. With `demo_mode = false`, Scenarios A/C header tests fail closed and only signed
> JWT claims (D/E) grant access — the intended production posture.

---

## NIST SP 800-207 Alignment

| NIST Tenet | Principle                                          | Implementation                                         |
| ---------- | -------------------------------------------------- | ------------------------------------------------------ |
| 1          | All resources are protected                        | Backend, Keycloak, OPA each treated as protected assets |
| 2          | All communication secured regardless of location   | Istio mTLS STRICT on all pod communication             |
| 3          | Access granted per-session                         | JWT per-request evaluation, short token TTL            |
| 4          | Access determined by dynamic policy                | OPA: role + method + path + posture per request        |
| 5          | Asset integrity monitored continuously             | Kiali topology, Grafana metrics, OPA decision logs     |
| 6          | Authentication and authorization are dynamic       | No pre-approved sessions; every request re-evaluated   |
| 7          | Collect as much information as possible            | Prometheus/Grafana metrics, OPA audit logs             |

---

## Performance Characteristics

Measured on local Minikube (Docker Desktop on WSL2), using Fortio with 200 requests on a
single persistent connection at maximum throughput (`-qps 0`). The single-connection
sequential load isolates pure policy-evaluation cost (OPA gRPC round-trip + JWT parsing)
from connection-establishment overhead and WSL2 scheduler contention. Throughput figures
therefore represent sequential-request capacity, not peak concurrency.

Baseline = Istio sidecar present but **no** AuthorizationPolicy or PeerAuthentication applied
(isolates the policy-enforcement cost, not the sidecar itself):

| Metric       | Baseline | ZTA Enabled (full stack) | Overhead          |
| ------------ | -------- | ------------------------ | ----------------- |
| Avg Latency  | 5.33 ms  | 6.86 ms                  | +1.53 ms (+28.6%) |
| QPS          | 187.5    | 145.7                    | −41.8 (−22.3%)    |
| p99 Latency  | 8.5 ms   | 10.5 ms                  | +2.0 ms (+23.5%)  |

**What causes the overhead:**
1. mTLS handshake — certificate exchange on each new connection (~2–3 ms)
2. OPA ext-authz gRPC call — policy evaluation per request (~2–3 ms)
3. Envoy sidecar processing — filter chain, telemetry (~0.5 ms)

**Is this acceptable?**
The absolute overhead of +1.53 ms is negligible for most applications (human-perceptible threshold ≈ 100 ms).
The 22.3% QPS drop matters only for high-throughput single-connection benchmarks.
In production with connection reuse, OPA caching, and horizontal scaling, real overhead is typically 1–3 ms.

---

## VPN vs ZTA: What's the Difference?

VPN secures the transport tunnel — once connected, internal traffic is trusted broadly. ZTA secures the individual request — every request is re-evaluated regardless of how the caller connected.

They are complementary. The recommended production configuration is WireGuard (or equivalent) for network-layer entry, combined with ZTA inside the cluster for per-request enforcement.

For a full capability comparison, see the [Introduction](00-intro.md#2-why-traditional-security-falls-short) and `evidence/vpn-zta-comparison.txt`.
