# How It Works

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

# East-West: frontend-sa can GET non-admin paths
allow if source = frontend-sa AND method = GET AND path ≠ /api/admin

# North-South basic: role:admin header (demo-level, Scenario A/B)
allow if role header = admin AND device is healthy

# Context-based: role:user can only GET non-admin (Scenario C)
allow if role header = user AND method = GET AND path ≠ /api/admin

# JWT claim admin: (Scenario D)
allow if JWT has role:admin AND device is healthy

# JWT claim viewer: read-only, no admin paths (Scenario D)
allow if JWT has role:viewer AND method = GET AND path ≠ /api/admin

# Device posture helper (Scenario E):
device_is_healthy if X-Device-Firewall header is missing or = "enabled"
```

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

Measured on local Minikube (not cloud), using Fortio load tester with 200 requests, single connection:

| Metric       | Baseline (no policy) | ZTA Enabled (full stack) | Overhead          |
| ------------ | -------------------- | ------------------------ | ----------------- |
| Avg Latency  | 5.95 ms              | 10.8 ms                  | +4.85 ms (+81.5%) |
| QPS          | 168.0                | 92.4                     | −75.6 (−45%)      |
| p50 Latency  | 5.77 ms              | ~10 ms                   | +73%              |
| p99 Latency  | 9.00 ms              | ~15 ms                   | +67%              |

**What causes the overhead:**
1. mTLS handshake — certificate exchange on each new connection (~2–3 ms)
2. OPA ext-authz gRPC call — policy evaluation per request (~2–3 ms)
3. Envoy sidecar processing — filter chain, telemetry (~0.5 ms)

**Is this acceptable?**
The absolute overhead of +4.85 ms is negligible for most applications (human-perceptible threshold ≈ 100 ms).
The 45% QPS drop is significant only for high-throughput single-connection benchmarks.
In production with connection reuse, OPA caching, and horizontal scaling, real overhead is typically 1–3 ms.

---

## VPN vs ZTA: What's the Difference?

| Capability                         | WireGuard VPN   | This ZTA Sandbox |
| ---------------------------------- | --------------- | ---------------- |
| Transport encryption               | Yes             | Yes              |
| Per-request authentication         | No              | Yes              |
| Role / method / path authorization | No              | Yes              |
| East-west lateral movement control | Limited         | Yes              |
| Device posture gating              | No              | Yes (simulated)  |
| Per-request audit logs             | No              | Yes              |
| Estimated latency overhead         | ~0.1–3 ms       | +4.85 ms         |

VPN secures the tunnel. ZTA secures the request. They are complementary, not alternatives.
The recommended production stack is: WireGuard for network entry + ZTA inside the cluster.
