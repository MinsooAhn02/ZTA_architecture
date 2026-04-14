# ZTA Unified Documentation

Generated: 2026-04-14

This document merges project planning, explanation, and execution checklist into one place for handoff to other AI agents.

## 1. Master Checklist (source: checklist.txt)

```text
================================================================
  ZTA Project - Master Checklist
  Researcher: Minsoo Ahn
  Last Updated: 2026-04-09
================================================================

[ Project Overview ]
Zero Trust Architecture (ZTA) implementation based on NIST SP 800-207.
- IdP (Identity Provider): Keycloak
- PDP (Policy Decision Point): OPA (Open Policy Agent)
- PEP (Policy Enforcement Point): Istio (Service Mesh)

================================================================
  PROGRESS SUMMARY
================================================================

  Phase 1: Research & Infrastructure     [x] DONE
  Phase 2: Service Deployment            [x] DONE
  Phase 3: North-South Security          [x] DONE
  Phase 4: East-West Micro-segmentation  [x] DONE
  Phase 5: JWT Authentication & IdP      [x] DONE
  Phase 6: Attack Scenarios & Perf       [x] DONE (A, B, C, D)
  Final Deliverables                     [~] IN PROGRESS

================================================================
  PHASE 1: Research & Infrastructure [DONE]
================================================================
[x] NIST SP 800-207 Standard Analysis
[x] Component Mapping (PDP/PEP/IdP)
[x] ZTA Architecture Design
[x] Minikube Cluster Setup (4 CPUs, 8GB RAM)
[x] Flask App Development (Frontend/Backend + API endpoints)
[x] Docker Image Building (minsoo-app:v1)
[x] Istio Installation (Demo Profile)
[x] Sidecar Auto-injection Setup (Namespace: default)
[x] Istio Addons (Kiali, Prometheus, Grafana)
[x] Automation via Makefile

================================================================
  PHASE 2: Service Deployment [DONE]
================================================================
[x] Frontend + Backend Deployment
[x] Keycloak (IdP) Deployment
[x] OPA (PDP) Deployment
[x] All Pods Ready (frontend, backend, keycloak, opa)

================================================================
  PHASE 3: North-South Security [DONE]
================================================================
[x] OPA ext-authz Registration in Istio Mesh Config
[x] AuthorizationPolicy (Frontend -> OPA)
[x] Validation:
    - [x] No Token -> 403 Forbidden (make test-block)
    - [x] role:admin Header -> 200 OK (make test-pass)

================================================================
  PHASE 4: East-West Micro-segmentation [DONE]
================================================================
[x] ServiceAccount Separation (frontend-sa / backend-sa)
[x] PeerAuthentication (mTLS STRICT Mode)
[x] Backend AuthorizationPolicy (Only frontend-sa allowed)
[x] OPA Rego Policy Refinement
[x] Validation:
    - [x] Normal Path (Frontend -> Backend) -> 200 OK
    - [x] Rogue Pod -> Backend -> 403 Forbidden (make test-lateral-block)
    - [x] Wrong SA -> Backend -> 403 Forbidden (make test-lateral-sidecar)

================================================================
  PHASE 5: JWT Authentication & IdP [DONE]
================================================================
[x] RequestAuthentication (Keycloak JWT Signature Verification)
[x] Keycloak Realm Setup (Auto: make setup-keycloak)
    - Realm: myrealm
    - Client: zta-client (secret: zta-secret)
    - User: testuser / testpass (role: admin)
[x] Viewer User Setup (make setup-keycloak-viewer)
    - User: vieweruser / viewerpass (role: viewer)
[x] JWT Token Issuance (make get-token / make get-token-viewer)
[x] Validation:
    - [x] Valid JWT + role:admin -> 200 OK (make test-jwt-auto)
    - [x] Fake/Invalid JWT -> 401 Unauthorized (make test-fake)

================================================================
  PHASE 6: Attack Scenarios & Performance [DONE]
================================================================

[x] Scenario A: Lateral Movement Attack Defense
    - Rogue Pod -> Backend: 403 Forbidden (mTLS STRICT)
    - Wrong SA -> Backend: 403 Forbidden (SPIFFE ID mismatch)
    - make test-lateral

[x] Scenario B: Token Theft / Forgery Attack Defense
    - Manipulated JWT -> 401 Unauthorized (signature verification)
    - Valid Keycloak JWT -> 200 OK (full pipeline verified)
    - make test-fake, make test-jwt-auto

[x] Scenario C: Context-Based Access Control [NEW]
    - role:user + GET /api/data -> 200 (allowed: safe read)
    - role:user + GET /api/admin -> 403 (path restricted)
    - role:user + POST /api/write -> 403 (write requires admin)
    - role:admin + POST /api/write -> 200 (admin full access)
    - make test-context

[x] Scenario D: JWT Role Claim Access Control [NEW]
    - admin JWT (Keycloak) -> GET /api/admin -> 200
    - viewer JWT (Keycloak) -> GET /api/data -> 200
    - viewer JWT (Keycloak) -> GET /api/admin -> 403
    - viewer JWT (Keycloak) -> POST /api/write -> 403
    - make test-jwt-role

[x] Performance Analysis:
    - [x] Baseline: avg 5.95ms, 168.0 QPS (200 requests, no policy)
    - [x] ZTA ON:   avg 10.8ms, 92.4 QPS (200 requests, full stack)
    - [x] Overhead: +81.5% latency, -45.0% QPS
    - Documented in evidence/zta-vs-baseline-comparison.txt

================================================================
  FINAL DELIVERABLES
================================================================
[x] Working Sandbox (Makefile Automation)
[x] Policy Repository (Rego Policies)
[x] Test Suite (make test-all) - Scenarios A, B, C, D
[x] Documentation (explanation.txt - deep dive with Q&A prep)
[x] ZTA vs Baseline Comparison (evidence/zta-vs-baseline-comparison.txt)

[ ] Evidence Collection  <-- YOU NEED TO DO THIS
    - [ ] OPA Decision Logs (make logs-opa, screenshot terminal)
    - [ ] Kiali Dashboard Screenshots (make open-kiali)
    - [ ] Grafana Dashboard Screenshots (make open-grafana)
    - [ ] Keycloak Realm/Users Screenshots (make open-keycloak)
    - [ ] test-all output (make test-all 2>&1 | tee evidence/test-results.txt)

[ ] Final Report  <-- YOU NEED TO DO THIS
    Include:
    - NIST 800-207 Compliance Mapping (from explanation.txt Part 1-2)
    - Scenario A-D Results + comparison table
    - Performance Analysis (from evidence/zta-vs-baseline-comparison.txt)
    - Screenshots + OPA decision logs

================================================================
  SETUP ORDER (New: run these after cluster setup)
================================================================

  1. First time setup (if cluster not running):
     $ make all

  2. Add viewer user for Scenario D:
     $ make ports
     $ make setup-keycloak-viewer

  3. Apply new OPA policy (if cluster already running):
     $ kubectl apply -f k8s/opa-k8s.yaml
     $ make rebuild-image   # rebuild with new app endpoints
     $ make restart

  4. Run all tests (Scenario A~D):
     $ make test-all

================================================================
  QUICK REFERENCE
================================================================

  Run All Tests:           make test-all          (A+B+C+D)
  Context Tests Only:      make test-context      (Scenario C)
  JWT Role Tests Only:     make test-jwt-role     (Scenario D)
  Check Status:            make status
  Start Port-Forwards:     make ports
  Add Viewer User:         make setup-keycloak-viewer
  Get Admin JWT:           make get-token
  Get Viewer JWT:          make get-token-viewer
  View OPA Decision Logs:  make logs
  Open Dashboards:         make open-kiali / open-grafana / open-keycloak

================================================================
  KEYCLOAK INFO
================================================================

  Admin Console: http://localhost:8080 (after make ports)
  Admin Login:   admin / admin
  Realm:         myrealm
  Client:        zta-client (secret: zta-secret)
  Admin User:    testuser / testpass (role: admin)
  Viewer User:   vieweruser / viewerpass (role: viewer)  [NEW]

================================================================
```

## 2. Deep Explanation (source: explanation.txt)

```text
================================================================================
  ZTA Sandbox - Deep Dive: Architecture, Mechanisms & Security Analysis
  Researcher: Minsoo Ahn | Based on NIST SP 800-207
================================================================================


================================================================================
  PART 1. ZERO TRUST ARCHITECTURE FUNDAMENTALS
================================================================================

  1.1 The Core Problem: Why Traditional Security Fails
  ─────────────────────────────────────────────────────
  Traditional "castle-and-moat" model:
    - Assumption: anything inside the network perimeter is trusted
    - Once attacker breaches perimeter → free lateral movement inside
    - VPN = extended perimeter, still fundamentally perimeter-based

  Real-world failures this model caused:
    - 2020 SolarWinds: attacker inside network moved freely for months
    - 2013 Target breach: HVAC vendor access → credit card data
    - Pattern: initial compromise is unavoidable; lateral movement is the damage

  Zero Trust answer (NIST SP 800-207 §2):
    "No implicit trust is granted to assets or user accounts based solely
     on their physical or network location."
    → Every single request must be authenticated and authorized, regardless
      of where it originates (inside or outside the network).

  ─────────────────────────────────────────────────────────────────────────────
  1.2 ZTA Component Mapping (NIST SP 800-207 Figure 1)
  ─────────────────────────────────────────────────────

  NIST Term              | This Project        | Role
  ───────────────────────┼─────────────────────┼──────────────────────────────
  Policy Engine (PE)     | OPA (Rego policy)   | Decides allow/deny
  Policy Administrator   | OPA ext-authz gRPC  | Communicates decision to PEP
  Policy Enforcement     | Istio Envoy Proxy   | Enforces the decision
  Point (PEP)            | (sidecar)           | (blocks or forwards traffic)
  Identity Provider      | Keycloak            | Issues + manages identities
  (IdP/CDM)             |                     | (JWT tokens, realm roles)
  Subject (User/Service) | testuser, frontend  | Entities requesting access
  Resource               | backend service     | Protected asset

  ─────────────────────────────────────────────────────────────────────────────
  1.3 ZTA Seven Tenets (NIST 800-207 §2.1) → How We Implement Each
  ─────────────────────────────────────────────────────────────────

  Tenet 1: All data sources and computing services are considered resources
    → Backend service treated as a protected resource (not trusted by default)

  Tenet 2: All communication is secured regardless of network location
    → PeerAuthentication STRICT mTLS: every pod-to-pod connection is encrypted
      and mutually authenticated, even on the same node

  Tenet 3: Access to individual enterprise resources is granted per-session
    → Each HTTP request independently evaluated by OPA (no session state)
    → JWT expiry enforced: each token has a TTL, must be re-issued

  Tenet 4: Access to resources is determined by dynamic policy
    → OPA Rego policy checks role + method + path + JWT claims per request
    → "Dynamic" = same identity may get different access based on context

  Tenet 5: The enterprise monitors and measures the integrity of owned assets
    → OPA decision_logs.console=true: every allow/deny logged with full context
    → Kiali: real-time service mesh topology and traffic flow

  Tenet 6: All resource authentication and authorization is dynamic
    → No pre-approved sessions; each request goes through PDP evaluation

  Tenet 7: Enterprise collects as much information as possible about assets
    → Prometheus/Grafana: latency, error rates, traffic patterns


================================================================================
  PART 2. LAYERED DEFENSE ARCHITECTURE
================================================================================

  Request flow for an external user accessing the frontend:

  [External Client]
       │
       │  HTTP (or HTTPS)
       ▼
  ┌────────────────────────────────────────┐
  │  Istio Ingress Gateway (PEP Layer 1)   │  ← North-South entry point
  │  - Terminates external TLS             │
  │  - Forwards to frontend Envoy sidecar  │
  └────────────────┬───────────────────────┘
                   │
                   ▼
  ┌────────────────────────────────────────┐
  │  Envoy Sidecar (frontend pod) (PEP)    │  ← Intercepts ALL traffic
  │  - Checks RequestAuthentication        │    before app container sees it
  │    (JWT signature via Keycloak JWKS)   │
  │  - Calls OPA ext-authz gRPC           │
  └────────────────┬───────────────────────┘
                   │  gRPC CheckRequest
                   ▼
  ┌────────────────────────────────────────┐
  │  OPA (Policy Decision Point)           │  ← Evaluates Rego policy
  │  - Receives full request attributes    │    Returns: allow / deny
  │    (headers, path, method, source SA)  │
  │  - Evaluates context-based rules       │
  │  - Logs every decision                 │
  └────────────────┬───────────────────────┘
                   │  CheckResponse (allow/deny)
                   ▼
  ┌────────────────────────────────────────┐
  │  Envoy Sidecar enforces OPA decision   │
  │  - allow → forward to frontend app     │
  │  - deny  → return 403/401 to client    │
  └────────────────┬───────────────────────┘
                   │  (if allowed)
                   ▼
  ┌────────────────────────────────────────┐
  │  Frontend App (Flask)                  │  ← App never sees blocked requests
  │  - Calls backend service               │
  └────────────────┬───────────────────────┘
                   │  mTLS (SPIFFE/SVID)
                   ▼
  ┌────────────────────────────────────────┐
  │  Envoy Sidecar (backend pod) (PEP)     │  ← East-West enforcement
  │  - PeerAuthentication: STRICT mTLS     │
  │  - AuthorizationPolicy: frontend-sa    │
  │    only (SPIFFE ID check)              │
  └────────────────┬───────────────────────┘
                   │  (if allowed)
                   ▼
  ┌────────────────────────────────────────┐
  │  Backend App (Flask)                   │
  └────────────────────────────────────────┘

  Key insight: The application code NEVER handles security logic.
  All enforcement is at the Envoy/OPA layer → application is unmodifiable
  by an attacker who only compromises app-level code.


================================================================================
  PART 3. SCENARIO A - LATERAL MOVEMENT ATTACK DEFENSE
================================================================================

  3.1 Attack Model
  ─────────────────
  Lateral movement: attacker compromises one internal pod → tries to
  reach other services (pivot) → exfiltrate data or escalate privileges.

  Real-world example: Attacker compromises a logging pod via a CVE exploit.
  Traditional network: logging pod can reach DB pod (same subnet).
  ZTA: logging pod has no SPIFFE identity allowed to reach DB pod → blocked.

  3.2 Defense Mechanism in This Project
  ───────────────────────────────────────

  Two independent defense layers (defense-in-depth):

  Layer 1: PeerAuthentication (mTLS STRICT)
  ┌─────────────────────────────────────────────────────────────┐
  │  k8s/peer-auth.yaml                                         │
  │  spec.mtls.mode: STRICT                                     │
  │                                                             │
  │  What it does:                                              │
  │  - Every pod MUST present a valid mTLS certificate          │
  │  - Certificates are SPIFFE/SVID format, issued by Istio CA  │
  │  - Pod without an Envoy sidecar = no certificate = BLOCKED  │
  │                                                             │
  │  Why a rogue pod cannot bypass this:                        │
  │  - Rogue pod has no Istio sidecar injected                  │
  │  - No sidecar = no SPIFFE certificate                       │
  │  - Cannot complete TLS handshake with backend's Envoy       │
  │  - Connection refused / timeout before sending any data     │
  └─────────────────────────────────────────────────────────────┘

  Layer 2: AuthorizationPolicy (SPIFFE ID allowlist)
  ┌─────────────────────────────────────────────────────────────┐
  │  k8s/authz-policy-backend.yaml                              │
  │  action: ALLOW                                              │
  │  from.source.principals: [frontend-sa SPIFFE ID]            │
  │                                                             │
  │  What it does:                                              │
  │  - Even if a pod HAS a sidecar (e.g., a compromised         │
  │    internal service), it must match the SPIFFE ID           │
  │  - SPIFFE ID = cluster.local/ns/default/sa/frontend-sa      │
  │  - backend-sa, default SA, any other SA = DENIED            │
  │                                                             │
  │  Why ServiceAccount identity matters:                       │
  │  - Pod IP addresses are ephemeral and spoofable             │
  │  - Network segment membership can be faked                  │
  │  - SPIFFE certificates are cryptographically bound to       │
  │    the specific ServiceAccount → cannot be spoofed          │
  └─────────────────────────────────────────────────────────────┘

  

  3.3 Test Execution & Expected Results
  ───────────────────────────────────────

  make test-lateral-block
    Simulates: rogue pod (no sidecar) → direct HTTP to backend:80
    Expected: connection refused or 403
    Why blocked: PeerAuthentication STRICT → no mTLS cert → connection drops
    ZTA principle: "never trust, always verify" → no implicit trust for
                   internal pods

  make test-lateral-sidecar
    Simulates: pod WITH sidecar but wrong ServiceAccount (backend-sa)
               attempting to reach backend service
    Expected: 403 Forbidden
    Why blocked: AuthorizationPolicy only lists frontend-sa
                 backend-sa SPIFFE ID = cluster.local/ns/default/sa/backend-sa
                 → not in allowlist → denied
    ZTA principle: workload identity, not network location, grants access

  3.4 Anticipated Q&A
  ────────────────────

  Q: Can the attacker just inject a sidecar into the rogue pod?
  A: Sidecar injection requires the pod to be in a namespace labeled
     istio-injection=enabled AND the Istio control plane issues the
     certificate. An attacker cannot get Istio CA to issue a certificate
     for frontend-sa without having cluster-admin privileges. If they
     have cluster-admin, the security boundary is already broken anyway.

  Q: Why use two layers (PeerAuth + AuthzPolicy)? Isn't one enough?
  A: Defense-in-depth. PeerAuth catches pods without sidecars (most rogue
     pods). AuthzPolicy catches compromised internal services that DO have
     sidecars (e.g., a legitimate pod that was compromised). Neither alone
     covers all cases.

  Q: What is SPIFFE/SVID?
  A: SPIFFE (Secure Production Identity Framework for Everyone) is a
     standard for workload identity. SVID (SPIFFE Verifiable Identity
     Document) is the certificate format. Istio issues X.509 SVIDs
     containing the SPIFFE URI (spiffe://cluster.local/ns/default/sa/xxx)
     which represents the workload's identity. This is much more reliable
     than IP-based identity.

  Q: Does mTLS protect the data in transit too?
  A: Yes. mTLS provides: (1) mutual authentication (both parties verify
     each other), (2) encryption in transit (TLS 1.2/1.3), (3) integrity
     (MAC on data). Even if someone sniffs the network, they see only
     encrypted data.


================================================================================
  PART 4. SCENARIO B - TOKEN THEFT & JWT FORGERY DEFENSE
================================================================================

  4.1 Attack Model
  ─────────────────
  JWT theft/forgery: attacker steals a valid token OR crafts a fake token
  with elevated privileges → attempts to bypass authentication.

  Scenario B-1: Token Forgery
    Attacker creates a JWT with {"role": "admin"} in the payload
    but signs it with a random private key → signature is invalid

  Scenario B-2: Token Manipulation
    Attacker takes a real JWT, decodes it (base64 is not encryption),
    changes the payload (e.g., adds admin role), re-encodes
    → signature no longer matches payload → invalid

  4.2 Defense Mechanism
  ──────────────────────

  RequestAuthentication (Istio):
  ┌─────────────────────────────────────────────────────────────┐
  │  k8s/jwt-auth.yaml                                          │
  │  jwtRules:                                                  │
  │    issuer: http://localhost:8080/realms/myrealm             │
  │    jwksUri: http://keycloak.../certs                        │
  │                                                             │
  │  Verification process:                                      │
  │  1. Extract JWT from Authorization: Bearer <token>          │
  │  2. Fetch Keycloak's public key from JWKS endpoint          │
  │  3. Verify JWT signature: RSA_verify(payload, sig, pubkey)  │
  │  4. If invalid → 401 Unauthorized (before OPA even runs)    │
  │  5. If valid → attach claims to request context             │
  │                                                             │
  │  Key security property:                                     │
  │  - Keycloak holds the PRIVATE key (signs tokens)            │
  │  - Istio uses the PUBLIC key (verifies tokens)              │
  │  - Attacker has neither key → cannot forge valid signature  │
  └─────────────────────────────────────────────────────────────┘

  4.3 JWT Structure (What Gets Verified)
  ─────────────────────────────────────────

  A JWT has 3 parts: header.payload.signature (base64 encoded)

  Header:  {"alg": "RS256", "kid": "key-id-from-keycloak"}
  Payload: {"sub": "user-id", "iss": "http://.../myrealm",
             "realm_access": {"roles": ["admin"]}, "exp": 1234567890}
  Signature: RSA_SHA256(base64(header) + "." + base64(payload), private_key)

  When attacker modifies payload and keeps signature:
    new_payload ≠ original_payload → signature verification fails
    RSA_verify(new_payload, original_signature, public_key) = FALSE → 401

  4.4 Test Execution & Expected Results
  ───────────────────────────────────────

  make test-fake
    Sends: Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.invalid
    The token has a syntactically valid JWT structure but a random signature
    Expected: 401 Unauthorized
    Where blocked: Istio Envoy sidecar (PEP), before OPA runs
    Why 401 not 403: Authentication failure (can't verify identity)
                     vs authorization failure (identity verified, not allowed)

  make test-jwt-auto
    Fetches real token from Keycloak → sends to frontend
    Expected: 200 OK
    Flow: Keycloak issues token (signed with private key)
          → Istio fetches JWKS from Keycloak → verifies signature
          → OPA checks claims → allow → 200

  4.5 Anticipated Q&A
  ────────────────────

  Q: If someone steals a valid token (not forge), can they use it?
  A: Yes, until it expires. JWT best practices: short TTL (Keycloak default
     5min for access tokens). This project sets tokens for demo purposes.
     For production: short-lived tokens + refresh token rotation + token
     binding (bind token to client TLS certificate).

  Q: Why does Istio return 401 instead of 403 for bad JWT?
  A: HTTP semantics: 401 = authentication failed (who are you?),
     403 = authorization failed (I know who you are, but you can't do this).
     A forged JWT means we can't establish identity → 401 is correct.
     If JWT is valid but role is insufficient → 403 from OPA.

  Q: What if Keycloak is down? Can users still access services?
  A: Istio caches the JWKS (public keys) locally. Existing valid tokens
     will still work until cache expires. New token issuance will fail
     (can't reach Keycloak). This is a trade-off: availability vs security.
     In production, Keycloak would be highly available (cluster mode).

  Q: Is the role:admin header check (make test-pass) secure?
  A: No - it's for demonstration only. Any client can set any HTTP header.
     In production, only JWT-based claims (Scenario D) should be used,
     where the claims are cryptographically bound to a Keycloak-verified
     identity. The header check shows the basic OPA flow; JWT shows real ZTA.


================================================================================
  PART 5. SCENARIO C - CONTEXT-BASED ACCESS CONTROL [NEW]
================================================================================

  5.1 What is "Context" in ZTA?
  ─────────────────────────────

  NIST 800-207 §3.3: "Access to resources is determined by dynamic policy
  including observable attributes of the requesting entity."

  In traditional RBAC (Role-Based Access Control):
    admin → can do everything
    user  → can do user things
    (binary: you have the role or you don't)

  In ZTA context-based access control:
    decision = f(who you are, what you're doing, which resource, when, how)
    - same user may be ALLOWED to GET /api/data but DENIED to POST /api/write
    - same user may be ALLOWED to access /api/data but DENIED /api/admin
    - access is granted for the minimal scope needed (least privilege)

  5.2 Implementation: OPA Rego Context Rules
  ───────────────────────────────────────────

  OPA evaluates three dimensions simultaneously:

  Dimension 1: Identity (role header or JWT claim)
  Dimension 2: HTTP Method (GET = read, POST = write)
  Dimension 3: Request Path (/api/data vs /api/admin)

  Policy matrix:
  ┌───────────┬──────────┬───────────────┬────────────┐
  │ Role      │ Method   │ Path          │ Decision   │
  ├───────────┼──────────┼───────────────┼────────────┤
  │ admin     │ any      │ any           │ ALLOW      │
  │ user      │ GET      │ /api/data     │ ALLOW      │
  │ user      │ GET      │ /api/admin    │ DENY (403) │
  │ user      │ POST     │ any           │ DENY (403) │
  │ none      │ any      │ any           │ DENY (403) │
  └───────────┴──────────┴───────────────┴────────────┘

  Rego rule for user + GET (non-admin):
    allow {
        http_request.headers.role == "user"
        http_request.method == "GET"
        not startswith(http_request.path, "/api/admin")
    }

  Why "not startswith" instead of allowlisting specific paths?
    → Allowlist is brittle: adding new paths requires policy update
    → Deny-list for sensitive prefixes is more robust
    → /api/admin, /api/admin/config, /api/admin/keys → all blocked with one rule

  5.3 Test Execution & Expected Results
  ───────────────────────────────────────

  make test-context-user-get
    Request: GET /api/data with role:user header
    Expected: 200 OK
    OPA rule matched: user + GET + not /api/admin → allow
    ZTA principle: minimum necessary access - user gets what they need

  make test-context-user-admin
    Request: GET /api/admin with role:user header
    Expected: 403 Forbidden
    OPA evaluation: user + GET + /api/admin → "not startswith" fails → deny
    ZTA principle: path-based privilege separation - admin data restricted
                   regardless of method

  make test-context-user-post
    Request: POST /api/write with role:user header
    Expected: 403 Forbidden
    OPA evaluation: user + POST → no rule matches POST for user role → deny
    ZTA principle: write operations are state-changing, higher risk → require
                   elevated privilege (admin)

  make test-context-admin-post
    Request: POST /api/write with role:admin header
    Expected: 200 OK
    OPA rule matched: admin → allow (all methods, all paths)
    ZTA principle: admin identity grants full operational scope

  5.4 Why This Matters for ZTA
  ─────────────────────────────

  Compared to traditional ACL:
    Traditional: "user role can access backend service" (yes/no)
    ZTA context: "user role can GET non-sensitive paths on backend service
                  but NOT POST and NOT access admin paths"

  This is the principle of Least Privilege at a granular level:
    - user cannot accidentally (or maliciously) write data
    - user cannot access confidential admin configs
    - admin's higher privilege is explicitly required and logged

  5.5 Anticipated Q&A
  ────────────────────

  Q: Why not just have two separate services (admin-api and user-api)?
  A: Path-based separation on a single service is valid for microservices
     where one service has multiple operation types. In production, you'd
     often have both service-level separation AND path-level context rules.
     Combining them provides defense-in-depth.

  Q: What if a user crafts a GET request but with a SQL injection in the path?
  A: OPA checks the path prefix, not sanitizes input. SQL injection defense
     is the application layer's responsibility (parameterized queries, etc.).
     ZTA handles access control; application security handles input validation.
     These are complementary, not alternatives.

  Q: How does context differ from ABAC (Attribute-Based Access Control)?
  A: ABAC is a superset that includes context. ZTA uses ABAC principles but
     extends them with continuous verification, cryptographic identity, and
     real-time policy evaluation. Traditional ABAC might be evaluated once
     at session start; ZTA evaluates every single request.

  Q: Can we add time-based context (e.g., only allow access 9am-5pm)?
  A: Yes. OPA can call external data sources (using OPA bundles or external
     API) to get current time and include it in policy evaluation. This
     project demonstrates method+path context; time is an extension.


================================================================================
  PART 6. SCENARIO D - JWT ROLE CLAIM ACCESS CONTROL [NEW]
================================================================================

  6.1 The Problem with Header-Based Authorization
  ─────────────────────────────────────────────────

  Scenarios A, B, and C use "role: admin" HTTP header.
  Problem: HTTP headers are arbitrary strings set by the client.
    - Any client can send role: admin
    - OPA trusts this header without cryptographic verification
    - This is NOT production-grade security

  Scenario D shows the correct ZTA approach:
    - Identity comes from Keycloak (trusted IdP)
    - Identity is encoded in a JWT signed with Keycloak's private key
    - OPA extracts claims from the JWT (cryptographically bound)
    - No client-side manipulation is possible without forging the JWT

  6.2 JWT Structure from Keycloak (Scenario D)
  ──────────────────────────────────────────────

  When testuser (admin role) gets a token, the JWT payload contains:
  {
    "iss": "http://localhost:8080/realms/myrealm",     ← issuer
    "sub": "uuid-of-testuser",                         ← subject (user ID)
    "exp": 1234567890,                                 ← expiry
    "realm_access": {
      "roles": ["admin", "default-roles-myrealm", "offline_access"]
    },
    ...
  }

  When vieweruser (viewer role) gets a token:
  {
    "realm_access": {
      "roles": ["viewer", "default-roles-myrealm", "offline_access"]
    }
  }

  6.3 How OPA Evaluates JWT Claims
  ──────────────────────────────────

  OPA's Rego policy uses io.jwt.decode() to parse the JWT:

  jwt_has_role(req, role) {
      bearer := req.headers.authorization       # "Bearer eyJ..."
      startswith(bearer, "Bearer ")
      token := trim_prefix(bearer, "Bearer ")   # strip prefix safely (OPA built-in)
      [_, payload, _] := io.jwt.decode(token)   # parse without re-verification
      role == payload.realm_access.roles[_]     # check role in array
  }


  Critical design point: io.jwt.decode() does NOT verify the signature.
  Why is this safe?
    - Istio RequestAuthentication ALREADY verified the signature
    - If the JWT was forged, Istio would have returned 401 before OPA runs
    - OPA only sees requests with verified JWTs → safe to trust the payload
    - This avoids duplicate RSA verification (performance optimization)
    - Separation of concerns: Istio = authentication, OPA = authorization

  6.4 Two Users, Two Levels of Access
  ─────────────────────────────────────

  testuser (role: admin via Keycloak)
    make get-token → JWT with realm_access.roles = ["admin", ...]
    OPA rule: jwt_has_role(req, "admin") → true → allow all

  vieweruser (role: viewer via Keycloak)
    make get-token-viewer → JWT with realm_access.roles = ["viewer", ...]
    OPA rules evaluated for viewer:
      - jwt_has_role(req, "viewer") → true
      - GET + non-admin path → allow
      - GET + /api/admin → deny (path check fails)
      - POST → deny (no POST rule for viewer)

  6.5 Test Execution & Expected Results
  ───────────────────────────────────────

  make test-jwt-admin-all
    Token: testuser JWT (admin role)
    Request: GET /api/admin
    Expected: 200 OK
    Flow: Istio verifies JWT signature → OPA: jwt_has_role(admin)=true → allow
    Key point: No role: header sent - identity entirely from JWT claim

  make test-jwt-viewer-read
    Token: vieweruser JWT (viewer role)
    Request: GET /api/data
    Expected: 200 OK
    Flow: Istio verifies JWT → OPA: jwt_has_role(viewer)=true, GET, not /admin → allow

  make test-jwt-viewer-admin
    Token: vieweruser JWT (viewer role)
    Request: GET /api/admin
    Expected: 403 Forbidden
    Flow: Istio verifies JWT → OPA: viewer + /api/admin → no rule matches → deny
    Demonstrates: privilege escalation via JWT impossible without re-issuing token

  make test-jwt-viewer-post
    Token: vieweruser JWT (viewer role)
    Request: POST /api/write
    Expected: 403 Forbidden
    Flow: Istio verifies JWT → OPA: viewer + POST → no rule matches → deny
    Demonstrates: read-only enforcement bound to cryptographic identity

  6.6 Anticipated Q&A
  ────────────────────

  Q: What stops a viewer from just adding role:admin header to bypass OPA?
  A: The OPA JWT rules only check realm_access.roles from the JWT, not the
     role header. The header-based rules (Scenarios A-C) and JWT-based rules
     (Scenario D) are separate. In a fully hardened system, you would REMOVE
     the header-based rules and use ONLY JWT claims, making the role header
     completely irrelevant.

  Q: Why use Keycloak instead of generating JWTs ourselves?
  A: Key management. Generating JWTs yourself means managing signing keys
     securely. Keycloak provides: key rotation, JWKS endpoint (auto-updated),
     multi-realm isolation, user management, MFA, social login integration,
     and audit logging. These are enterprise requirements that Keycloak
     handles out of the box.

  Q: Can a viewer "upgrade" their token to admin without re-authenticating?
  A: No. The JWT is cryptographically signed by Keycloak. Changing the payload
     invalidates the signature. To get an admin token, you need admin
     credentials in Keycloak. If you have those credentials, you ARE admin
     by definition.

  Q: What happens when the JWT expires?
  A: Istio's RequestAuthentication checks the "exp" claim.
     Expired token → 401 Unauthorized → client must re-authenticate with
     Keycloak to get a new token. This enforces the ZTA tenet of per-session
     access rather than long-lived sessions.

  Q: How is viewer different from user in Scenario C?
  A: "user" (Scenario C) = HTTP header, arbitrary, not cryptographically bound.
     "viewer" (Scenario D) = Keycloak JWT claim, signed, tamper-proof.
     They enforce the same access policy (GET only, no /api/admin) but with
     completely different trust models. Scenario C shows the concept;
     Scenario D shows production-grade implementation.


================================================================================
  PART 7. PERFORMANCE ANALYSIS
================================================================================

  7.1 Measured Results
  ─────────────────────

  +─────────────────────┬──────────────┬──────────────┬──────────────────────+
  │ Metric              │ Baseline     │ ZTA Enabled  │ Overhead             │
  │                     │ (no policy)  │ (full stack) │                      │
  ├─────────────────────┼──────────────┼──────────────┼──────────────────────┤
  │ Avg Latency         │  5.95 ms     │  10.8 ms     │ +4.85 ms (+81.5%)    │
  │ QPS (throughput)    │ 168.0        │  92.4        │ -75.6 QPS (-45.0%)   │
  │ p50 Latency         │  5.77 ms     │  ~10 ms      │ +73%                 │
  │ p99 Latency         │  9.00 ms     │  ~15 ms      │ +67%                 │
  +─────────────────────┴──────────────┴──────────────┴──────────────────────+

  Conditions: 200 requests, c=1 (single connection), Fortio load tester,
  Minikube on local machine (not cloud), warm pods

  7.2 What Causes the Overhead?
  ───────────────────────────────

  The ZTA overhead comes from three sources:

  1. mTLS Handshake (~2-3ms per new connection)
     - TLS 1.3 handshake: 1 RTT for initial, 0-RTT for resumption
     - Certificate verification (SVID chain)
     - Key exchange (ECDHE)
     - With connection reuse (keepalive), this amortizes to ~0.5ms/req

  2. OPA ext-authz gRPC call (~2-3ms per request)
     - Every request → Envoy calls OPA via gRPC
     - Rego policy evaluation (Rego interpreter, ~0.1ms)
     - Network round-trip to OPA pod (localhost/loopback: ~0.5ms)
     - Serialization/deserialization of CheckRequest proto

  3. Envoy sidecar processing (~0.5ms per request)
     - Filter chain execution (JWT validation, authz policy check)
     - Header manipulation, telemetry reporting

  7.3 Is This Acceptable?
  ─────────────────────────

  Context:
  - +4.85ms absolute overhead is negligible for most applications
  - Human-perceptible delay threshold: ~100ms
  - Typical microservice call: 5-500ms (network, DB, business logic)
  - ZTA overhead is ~1-5% of typical response time in production

  When it matters:
  - High-frequency trading, real-time gaming: unacceptable overhead
  - Standard enterprise applications, APIs: acceptable
  - The 45% QPS reduction is significant for high-throughput systems
    → Use OPA caching, sidecarless ambient mode for hot paths

  Optimization options (not implemented in this sandbox):
  - OPA caching: cache decisions for same (user, resource, action) for N sec
  - Ambient mode (Istio 1.22+): no sidecar, shared node-level proxy
  - JWT caching in Istio: cache JWKS and verified tokens
  - mTLS session resumption: amortize handshake cost

  7.4 Anticipated Q&A
  ────────────────────

  Q: 81% latency increase seems too high for production. Is ZTA practical?
  A: The percentage sounds high but the absolute increase is 4.85ms.
     In production on faster hardware with connection pooling and caching,
     overhead is typically 1-3ms absolute. The 81% increase here is because
     baseline is already very fast (5.95ms on localhost). For an API that
     takes 100ms, ZTA adds 2-3ms → 2-3% overhead.

  Q: How do you reduce the OPA latency specifically?
  A: Three options: (1) OPA decision caching for repeated same-context
     decisions, (2) Compile Rego to WASM for near-native evaluation speed,
     (3) Use Istio's built-in AuthorizationPolicy for simple rules (no gRPC
     hop needed) and only delegate complex decisions to OPA.

  Q: The QPS dropped 45%. Won't this bottleneck production services?
  A: At 92 QPS on a single connection, this is not the bottleneck -
     the application itself usually is. In production: horizontal scaling
     of OPA (multiple replicas), gRPC connection pooling between Envoy and
     OPA, and OPA's built-in caching reduce this significantly.


================================================================================
  PART 8. POLICY FILES REFERENCE
================================================================================

  +─────────────────────────────────────┬──────────────────────────────────────+
  │ File                                │ Purpose                              │
  ├─────────────────────────────────────┼──────────────────────────────────────┤
  │ k8s/opa-k8s.yaml                   │ OPA deployment + Rego policy          │
  │                                     │ (Scenarios A, B, C, D)               │
  ├─────────────────────────────────────┼──────────────────────────────────────┤
  │ k8s/authz-policy.yaml              │ Istio ext-authz integration           │
  │                                     │ Routes frontend requests to OPA      │
  ├─────────────────────────────────────┼──────────────────────────────────────┤
  │ k8s/peer-auth.yaml                 │ mTLS STRICT mode (East-West)          │
  │                                     │ First line of lateral movement defense│
  ├─────────────────────────────────────┼──────────────────────────────────────┤
  │ k8s/authz-policy-backend.yaml      │ SPIFFE ID allowlist for backend       │
  │                                     │ Second line of lateral movement defense│
  ├─────────────────────────────────────┼──────────────────────────────────────┤
  │ k8s/jwt-auth.yaml                  │ JWT signature verification via JWKS   │
  │                                     │ Istio RequestAuthentication           │
  ├─────────────────────────────────────┼──────────────────────────────────────┤
  │ k8s/jwt-require-policy.yaml        │ Requires JWT principal for access     │
  │                                     │ (optional, complement to jwt-auth)   │
  └─────────────────────────────────────┴──────────────────────────────────────┘


================================================================================
  PART 9. COMPLETE TEST REFERENCE
================================================================================

  Scenario A: North-South + Lateral Movement
  ───────────────────────────────────────────
  make test-block              No token → 403 (unauthenticated blocked)
  make test-pass               role:admin → 200 (basic header auth)
  make test-lateral-block      Rogue pod → backend → 403 (no mTLS cert)
  make test-lateral-sidecar    Wrong SA → backend → 403 (SPIFFE mismatch)

  Scenario B: JWT Authentication
  ───────────────────────────────
  make test-fake               Forged JWT → 401 (signature invalid)
  make test-jwt-auto           Valid Keycloak JWT → 200 (full pipeline)

  Scenario C: Context-Based Access Control [NEW]
  ───────────────────────────────────────────────
  make test-context-user-get    user + GET /api/data → 200
  make test-context-user-admin  user + GET /api/admin → 403
  make test-context-user-post   user + POST /api/write → 403
  make test-context-admin-post  admin + POST /api/write → 200

  Scenario D: JWT Role Claim Access Control [NEW]
  ───────────────────────────────────────────────
  make test-jwt-admin-all       admin JWT → /api/admin → 200
  make test-jwt-viewer-read     viewer JWT → /api/data → 200
  make test-jwt-viewer-admin    viewer JWT → /api/admin → 403
  make test-jwt-viewer-post     viewer JWT → POST /api/write → 403

  Run All:
  make test-all                 All A+B+C+D scenarios


================================================================================
  END OF DOCUMENT
================================================================================
```

## 3. Master TODO (source: todo.txt)

```text
================================================================
  ZTA Project - Master TODO & Framework
  Minsoo Ahn | Updated: 2026-04-14
================================================================

  이 문서는 "무엇을 해야 하는지"의 디테일한 틀이다.
  단순히 make 파일 돌리는 게 아니라,
  "왜 이게 ZTA인지", "어떤 원리로 막는지"를
  시연과 문서에서 명확히 보여줘야 한다.

================================================================
  PART -1. Owner Intent Freeze (2026-04-14)
================================================================

  이 섹션은 "해석 금지" 실행 지침이다.
  이후 작업하는 AI/사람은 아래 의사결정을 기본값으로 사용한다.

  [결정 1] Device Posture 구현 방식
    - 확정: 방안 A 채택 (커스텀 헤더 기반 시뮬레이션 구현)
    - 필수 헤더: X-Device-Firewall (enabled/disabled)
    - 확장 헤더(선택): X-Device-Patch-Level, X-Device-OS-Version
    - 문서 원칙: "헤더 기반은 데모용 간이 모델이며 실제 운영은
                 MDM/attestation 연동이 필요"를 명시

  [결정 2] VPN Baseline 비교 방식
    - 확정(간단 버전): WireGuard 단일 비교를 1차 기준으로 사용
    - 이유 1: 설정이 단순해 실험 재현성이 높음
    - 이유 2: 오버헤드가 낮아 ZTA와의 비교축으로 적합
    - 이유 3: OpenVPN 대비 실험 복잡도가 낮아 현재 일정에 맞음
    - OpenVPN은 선택 과제: 시간 여유가 있으면 2차 비교로 추가
    - 공통 목표: 같은 요청 시나리오에서 latency/throughput/CPU 측정
    - 직접 비교가 불가능하면 성능 오버헤드 데이터로 대체하되,
      대체 사유/한계/재현 절차를 보고서에 명확히 기록
    - 설명 원칙: 예) ZTA 오버헤드 +5ms가 500ms 응답 기준 약 1%인지,
      요청 유형별(읽기/쓰기) 영향으로 해석

  [결정 3] 작업 우선순위
    - 확정: P0/P1/P2 우선순위에 동의
    - P0(필수): Device Posture + JWT tampered test
    - P1(시연): Makefile demo + 공격 스크립트
    - P2(완성도): OPA 로그 포맷 + evidence 구조화

  [결정 4] Phase 0 선행
    - 확정: 코드 수정 전에 분석 문서(Threat Model, Attack Tree,
            Defense Layer) 먼저 작성
    - 문서 톤: thesis 스타일
      "기존에 무엇이 있었는지 -> 무엇을 세팅/변경했는지 ->
       무엇을 배웠는지(한계/인사이트)"
    - 산출물 우선순위: docs/threat-model.md > explanation.txt 보강 >
                      코드 변경

  [오너 입력 확정값 (2026-04-14 추가)]
    - A. VPN 비교 범위: 1차 WireGuard만 수행, OpenVPN은 선택(시간 여유 시)
    - B. 실험 조건(기본): 워밍업 20회 후 측정 100회 x 3라운드, 동시성 10
    - B2. 측정 지표: p50/p95 latency, req/s, error rate, CPU(가능하면)
    - C. 성공 기준(기본): 성공률 99% 이상, 평균 지연 증가 15ms 이하,
         처리량 감소 15% 이하
    - D. thesis 산출물 크기: 소형(2~3페이지 + 그림 2개 + 표 2개)
    - E. 일정: 마감 미정(TBD). 고정 마감 전까지 Phase 순서대로 진행

================================================================
  PART 0. PDF PROPOSAL vs 현재 구현 - GAP 분석
================================================================

  PDF에서 약속한 것           | 현재 상태        | 조치
  ─────────────────────────┼────────────────┼──────────────────
  Scenario A: Lateral       | 구현됨 (O)      | 시연 시나리오 보강
  Movement 방어             |                |
  ─────────────────────────┼────────────────┼──────────────────
  Scenario B: Device Posture| 미구현 (X)      | *** 핵심 GAP ***
  & Context Access Control  | 현재는 JWT 위조  | 아래 PART 2 참조
  (디바이스 건강상태, 위치,   | 방어만 있음      |
   시간 기반 접근제어)        |                |
  ─────────────────────────┼────────────────┼──────────────────
  Dashboard (로그/결정       | Kiali/Grafana   | 커스텀 대시보드 or
  시각화)                   | 만 사용 중       | OPA 로그 시각화
  ─────────────────────────┼────────────────┼──────────────────
  VPN Baseline 비교         | 미구현 (X)      | WireGuard 1차 직접비교,
  (WireGuard/OpenVPN)       |                | OpenVPN 선택 + 불가시 대체
  ─────────────────────────┼────────────────┼──────────────────
  Attack Simulation Scripts | curl 수준       | 현실적 공격 스크립트
  (공격 시뮬레이션)          |                | 필요
  ─────────────────────────┼────────────────┼──────────────────
  Final Report              | 미작성 (X)      | 작성 필요
  ─────────────────────────┼────────────────┼──────────────────

  *** 가장 큰 문제 ***
  PDF Scenario B는 "Device Posture"(디바이스 상태 점검)인데,
  현재 구현에는 이게 전혀 없다. JWT 위조 방어를 Scenario B로
  넣었지만, 이건 PDF와 다르다.

  해결 방향 (확정):
    A) Device Posture 시뮬레이션 구현 (OPA에 디바이스 컨텍스트 추가)
    보완) 문서화는 대체안이 아니라 병행 작업으로 수행.
         현재 구현이 Device Posture 개념을 어떻게 포괄/확장하는지
         explanation.txt에서 논리적으로 연결.


================================================================
  PART 1. 시나리오 재구성 - "왜 ZTA인가"를 보여주는 구조
================================================================

  현재 문제: 시나리오가 make target 나열 수준이다.
  보여줘야 하는 것: "공격 → 방어 → 원리 → 증거" 흐름

  ────────────────────────────────────────────────────────
  [시나리오 1] Lateral Movement Attack (East-West)
  ────────────────────────────────────────────────────────
  스토리:
    "공격자가 프론트엔드 서버의 CVE를 이용해 침투했다.
     전통 네트워크에서는 이 서버에서 백엔드 DB로 바로 접근 가능.
     ZTA에서는?"

  시연 흐름 (3단계):
    Step 1: 공격 상황 재현
      - Rogue Pod 생성 (Istio sidecar 없는 pod)
      - 이 pod에서 backend service로 직접 HTTP 요청
      - 명령: make demo-lateral-step1
      - 보여줄 것: "curl backend:80" 시도 → 연결 거부

    Step 2: 더 정교한 공격 시도
      - Sidecar가 있지만 잘못된 ServiceAccount를 가진 pod
      - mTLS는 통과하지만 SPIFFE ID가 다르다
      - 명령: make demo-lateral-step2
      - 보여줄 것: "403 Forbidden" + OPA 로그에서 deny 결정

    Step 3: 정상 경로 확인
      - Frontend pod → Backend: 정상 200 OK
      - 명령: make demo-lateral-step3
      - 보여줄 것: 200 OK + "이 경로만 허용됨"

  원리 설명 (시연 중 or 후):
    - 방어 레이어 1: PeerAuthentication STRICT (mTLS)
      → Sidecar 없는 pod = 인증서 없음 = TLS 핸드셰이크 실패
    - 방어 레이어 2: AuthorizationPolicy (SPIFFE allowlist)
      → frontend-sa만 허용, 다른 SA = 403
    - 핵심: "네트워크 위치가 아닌 워크로드 신원(identity)으로 접근 제어"

  증거:
    - OPA decision log (deny 이유가 JSON으로 출력)
    - Kiali 토폴로지 (차단된 트래픽 빨간색으로 표시)
    - kubectl describe authorizationpolicy (정책 내용 확인)

  ────────────────────────────────────────────────────────
  [시나리오 2] Token Forgery & Identity Spoofing (North-South)
  ────────────────────────────────────────────────────────
  스토리:
    "공격자가 유효한 JWT를 탈취하거나, 위조된 JWT를 만들어
     시스템에 접근 시도한다. 전통 시스템에서는 세션 쿠키만
     확인하면 끝이지만, ZTA에서는?"

  시연 흐름 (4단계):
    Step 1: 토큰 없이 접근
      - 인증 정보 없이 frontend 접근
      - 결과: 403 Forbidden
      - 원리: OPA가 role header/JWT 없음 → deny

    Step 2: 위조 JWT로 접근
      - 가짜 서명이 있는 JWT 전송
      - 결과: 401 Unauthorized
      - 원리: Istio가 Keycloak JWKS로 서명 검증 → 실패
      - 핵심: "401은 인증 실패(너 누구?), 403은 인가 실패(너 권한 없어)"

    Step 3: 유효 JWT 조작 시도
      - 진짜 JWT의 payload를 수정 (viewer→admin)
      - Base64 디코딩 → payload 변경 → 재인코딩
      - 결과: 401 Unauthorized (서명 불일치)
      - 원리: JWT = header.payload.signature
              payload 변경 → signature 무효화
      *** 이 단계가 현재 없다 - 추가해야 함 ***

    Step 4: 유효한 Keycloak JWT로 정상 접근
      - make get-token → 200 OK
      - 원리: Keycloak 개인키로 서명 → Istio가 공개키로 검증 → 통과

  원리 설명:
    - RSA 비대칭 암호: 개인키(서명) ↔ 공개키(검증)
    - JWKS endpoint: Keycloak이 공개키를 제공하는 URL
    - Istio는 이 공개키를 캐시해서 매 요청마다 검증
    - "인증과 인가의 분리": Istio=인증, OPA=인가

  ────────────────────────────────────────────────────────
  [시나리오 3] Context-Based Access Control (NIST 동적 정책)
  ────────────────────────────────────────────────────────
  스토리:
    "같은 사용자(user)라도 무엇을(method) 어디에(path) 요청하느냐에
     따라 접근이 달라진다. 전통 RBAC는 'user면 OK/NO'이지만,
     ZTA는 컨텍스트를 본다."

  시연 흐름 (데모 매트릭스):
    ┌─────────┬──────────┬───────────┬────────┬─────────────────────┐
    │ 역할    │ 메서드   │ 경로      │ 결과   │ 왜?                 │
    ├─────────┼──────────┼───────────┼────────┼─────────────────────┤
    │ user    │ GET      │ /api/data │ 200    │ 읽기+일반경로=허용  │
    │ user    │ GET      │ /api/admin│ 403    │ 민감경로=차단        │
    │ user    │ POST     │ /api/write│ 403    │ 쓰기작업=관리자만   │
    │ admin   │ POST     │ /api/write│ 200    │ admin=전체 허용      │
    │ (없음)  │ GET      │ /api/data │ 403    │ 인증 없음=차단       │
    └─────────┴──────────┴───────────┴────────┴─────────────────────┘

  원리 설명:
    - NIST 800-207 §3.3: "동적 정책으로 리소스 접근 결정"
    - 전통 RBAC: role = admin → 모든 것 허용 (이진적)
    - ZTA 컨텍스트: decision = f(identity, action, resource, time, ...)
    - OPA Rego 정책이 3개 축(역할, 메서드, 경로)을 동시 평가
    - "최소 권한 원칙"의 구현

  ────────────────────────────────────────────────────────
  [시나리오 4] JWT Claim-Based Access (암호학적 신원)
  ────────────────────────────────────────────────────────
  스토리:
    "시나리오 3의 role:user 헤더는 누구나 조작 가능하다.
     진짜 ZTA는 Keycloak이 발급한 JWT의 claim을 사용한다.
     이건 암호학적으로 위변조가 불가능하다."

  시연 흐름:
    Step 1: Admin JWT로 admin 경로 접근 → 200 OK
    Step 2: Viewer JWT로 일반 데이터 읽기 → 200 OK
    Step 3: Viewer JWT로 admin 경로 접근 시도 → 403
    Step 4: Viewer JWT로 쓰기 시도 → 403

  핵심 차이 (시나리오 3 vs 4):
    시나리오 3: role:user 헤더 (클라이언트가 직접 설정, 위변조 가능)
    시나리오 4: JWT claim (Keycloak 서명, 위변조 불가능)
    → "같은 접근 정책이지만 신뢰 모델이 완전히 다르다"

  ────────────────────────────────────────────────────────
  [시나리오 5] Device Posture / Extended Context (PDF 요구사항)
  ────────────────────────────────────────────────────────
  *** PDF Scenario B에 해당 - 현재 미구현 ***

  구현 방식 (확정: 방안 A):

  [방안 A: 간이 구현] OPA에 디바이스 컨텍스트 헤더 추가
    - 커스텀 헤더로 디바이스 상태 시뮬레이션:
      X-Device-OS-Version: "Windows 11 22H2"
      X-Device-Firewall: "enabled"
      X-Device-Patch-Level: "2026-04"
    - OPA Rego에 디바이스 상태 체크 규칙 추가:
      allow {
          jwt_has_role(http_request, "admin")
          http_request.headers["x-device-firewall"] == "enabled"
          # 방화벽 꺼진 디바이스에서는 admin도 차단
      }
    - 테스트:
      - admin JWT + firewall=enabled → 200 OK
      - admin JWT + firewall=disabled → 403 Forbidden
      - "유효한 자격증명이 있어도 디바이스가 안전하지 않으면 차단"

    장점: 구현 간단, PDF 요구사항 충족
    단점: 헤더 조작 가능 (실제로는 MDM 에이전트가 설정)

  [문서화 보완(병행)] 현재 구현이 Device Posture를 어떻게
    개념적으로 포괄하는지 설명
    - Context-based(시나리오 3)가 Device Posture의 상위 개념
    - OPA의 확장 가능성 언급 (external data source)
    - "현재는 헤더 기반 시뮬레이션, 이후 attestation 연동 확장"

  *** 확정: 방안 A 즉시 구현 (문서화는 병행) ***
    이유: PDF에서 명시적으로 "Device Posture"를 약속했고,
    이게 없으면 Proposal과 구현 사이 괴리가 너무 크다.


================================================================
  PART 2. Makefile 개선 - "데모용 스토리텔링 흐름"
================================================================

  현재 문제:
    - make test-all은 curl 결과만 쭉 출력
    - 보는 사람이 "이게 뭔데? 왜 중요한데?"를 알 수 없음
    - 시나리오 간 연결성이 없음

  개선 방향:

  [1] make demo (전체 스토리텔링 데모)
    ─────────────────────────────────────────────
    하나의 시나리오 흐름으로 연결된 데모.
    각 테스트 전에 "무엇을 하는지, 왜 하는지" 설명 출력.

    예시 출력:
    ──────────────────────────────────────────
    === SCENARIO 1: Lateral Movement Attack ===

    [상황] 공격자가 프론트엔드 서버를 해킹해서 내부 네트워크에 침투.
           전통 네트워크에서는 바로 백엔드 DB에 접근 가능.

    [공격 1] Rogue Pod → Backend 직접 접근 시도...
    [방어] PeerAuthentication STRICT: mTLS 인증서 없음 → 연결 거부
    결과: 403 Forbidden  ← ZTA가 차단함

    [공격 2] Sidecar 있는 Pod (잘못된 SA) → Backend 접근 시도...
    [방어] AuthorizationPolicy: SPIFFE ID가 frontend-sa가 아님 → 거부
    결과: 403 Forbidden  ← ZTA가 차단함

    [정상] Frontend → Backend (올바른 SA)...
    결과: 200 OK  ← 정상 경로만 허용

    [원리] 네트워크 위치(IP)가 아닌 암호학적 워크로드 신원(SPIFFE)으로
           접근을 제어. 내부에 있다고 신뢰하지 않음. (Never Trust)
    ──────────────────────────────────────────

  [2] 각 시나리오별 독립 데모
    make demo-lateral    → 시나리오 1만 (설명 포함)
    make demo-jwt        → 시나리오 2만 (설명 포함)
    make demo-context    → 시나리오 3만 (설명 포함)
    make demo-jwt-role   → 시나리오 4만 (설명 포함)
    make demo-posture    → 시나리오 5만 (설명 포함, 새로 추가)

  [3] make demo-compare (ZTA 있을 때 vs 없을 때)
    ─────────────────────────────────────────────
    같은 공격을 ZTA 정책 유무에 따라 비교.
    핵심: "ZTA 없으면 뚫리는데, 있으면 막힌다"를 눈으로 보여줌.

    참고: 정책 on/off를 실시간으로 하면 너무 복잡하므로,
    evidence/zta-vs-baseline-comparison.txt 내용을 화면에 출력하는
    방식이 현실적.

  [4] 기존 test-* 타겟은 그대로 유지 (자동화 테스트용)
    make test-all = CI/검증용 (출력 간결)
    make demo = 발표/시연용 (설명 포함)


================================================================
  PART 3. explanation.txt 개선
================================================================

  현재 상태: 이미 잘 작성됨 (9 Parts, Q&A 포함)

  개선 필요 사항:

  [1] PDF와의 매핑 테이블 추가 (Part 0 또는 서두)
    "PDF Proposal에서 약속한 것 → 이 프로젝트에서 구현한 것"
    매핑을 명시해서 교수/평가자가 바로 확인 가능하게.

  [2] Device Posture 시나리오 추가 (Part 5.5 또는 새 Part)
    방안 A를 구현하면 해당 시나리오 설명 추가.
    방안 B를 택하면 "왜 변경했는지" 설명 섹션 추가.

  [3] "전통 보안 vs ZTA" 비교를 더 명확하게 (Part 1 보강)
    현재: 개념 설명은 있으나 "실감"이 부족
    추가할 것:
      - Castle-and-Moat 다이어그램 (ASCII art)
      - "VPN으로 들어오면 내부는 자유" 시나리오
      - SolarWinds 공격 흐름도 (간략히)
      - "우리 프로젝트에서 이걸 어떻게 재현하고 막는지"

  [4] 각 시나리오에 "공격자 관점" 추가
    현재: 방어 원리 위주
    추가: "공격자가 이걸 뚫으려면 무엇이 필요한가?"
      - Lateral Movement: Istio CA의 루트 인증서 탈취 필요
        → cluster-admin 권한 필요 → 이미 게임 오버
      - JWT Forgery: Keycloak의 개인키 필요
        → Keycloak 서버 자체를 해킹해야 함
      - "공격 비용이 너무 높아서 현실적으로 불가능"

  [5] 성능 분석 섹션 보강 (Part 7)
    현재: 숫자만 있음
    추가:
      - "이 오버헤드가 실제 서비스에서 어느 정도인지" 비유
        예: "네이버 메인페이지 로딩 ~500ms, ZTA 오버헤드 ~5ms = 1%"
      - 최적화 방안을 구체적으로 (OPA 캐시, Ambient Mesh 등)
      - "보안 vs 성능" 트레이드오프 결론


================================================================
  PART 4. 공격 시뮬레이션 스크립트 강화
================================================================

  현재 문제:
    - 모든 공격이 단순 curl 한 줄
    - "이게 진짜 공격이야?" 라는 질문에 답할 수 없음

  개선:

  [1] scripts/attack-lateral.sh
    ─────────────────────────────────────────────
    #!/bin/bash
    # Lateral Movement Attack Simulation
    # 공격 시나리오: CVE를 이용해 frontend 침투 후 backend로 피벗

    echo "=== Phase 1: 정찰 (Reconnaissance) ==="
    echo "공격자가 내부 네트워크의 서비스 목록을 스캔합니다..."
    kubectl exec -it rogue-pod -- nslookup backend.default.svc.cluster.local
    # → DNS는 조회 가능 (서비스 발견은 되지만 접근은 별개)

    echo "=== Phase 2: 접근 시도 (Access Attempt) ==="
    echo "발견한 backend 서비스에 직접 HTTP 요청을 보냅니다..."
    kubectl exec -it rogue-pod -- curl -v backend:80 2>&1
    # → mTLS STRICT: connection refused

    echo "=== Phase 3: 우회 시도 (Bypass Attempt) ==="
    echo "IP 직접 접근으로 서비스 메시를 우회합니다..."
    BACKEND_IP=$(kubectl get pod -l app=backend -o jsonpath='{.items[0].status.podIP}')
    kubectl exec -it rogue-pod -- curl -v $BACKEND_IP:8080 2>&1
    # → 여전히 차단 (Envoy sidecar가 inbound도 제어)

    echo "=== 결론 ==="
    echo "모든 접근 시도가 차단됨. ZTA의 micro-segmentation이 작동."

  [2] scripts/attack-jwt-forge.sh
    ─────────────────────────────────────────────
    #!/bin/bash
    # JWT Forgery Attack Simulation

    echo "=== Phase 1: 정상 JWT 구조 확인 ==="
    # 실제 JWT를 받아서 구조를 보여줌
    REAL_TOKEN=$(curl -s -X POST "http://localhost:8080/realms/myrealm/protocol/openid-connect/token" ...)
    echo "Header:  $(echo $REAL_TOKEN | cut -d. -f1 | base64 -d)"
    echo "Payload: $(echo $REAL_TOKEN | cut -d. -f2 | base64 -d)"

    echo "=== Phase 2: Payload 조작 (viewer → admin) ==="
    # payload에서 roles를 viewer→admin으로 변경
    MODIFIED_PAYLOAD=$(... base64 encode modified payload ...)
    FORGED_TOKEN="$(echo $REAL_TOKEN | cut -d. -f1).$MODIFIED_PAYLOAD.$(echo $REAL_TOKEN | cut -d. -f3)"

    echo "=== Phase 3: 조작된 토큰으로 접근 시도 ==="
    curl -H "Authorization: Bearer $FORGED_TOKEN" http://localhost/api/admin
    # → 401 Unauthorized (서명 불일치)

    echo "=== 원리 ==="
    echo "JWT signature = RSA_SHA256(header + payload, PRIVATE_KEY)"
    echo "payload를 바꾸면 signature가 무효화됨"
    echo "새 signature를 만들려면 Keycloak의 private key가 필요"

  [3] scripts/attack-posture.sh (새로 추가, 방안 A 구현 시)
    ─────────────────────────────────────────────
    #!/bin/bash
    # Device Posture Attack Simulation

    echo "=== 시나리오: 탈취된 자격증명 + 취약 디바이스 ==="
    echo "공격자가 admin 계정을 피싱으로 탈취했지만,"
    echo "방화벽이 꺼진 디바이스에서 접속합니다."

    echo "=== 유효한 admin JWT 획득 ==="
    TOKEN=$(make get-token -s)

    echo "=== 시도 1: 정상 디바이스 (firewall=enabled) ==="
    curl -H "Authorization: Bearer $TOKEN" \
         -H "X-Device-Firewall: enabled" \
         http://localhost/api/admin
    # → 200 OK

    echo "=== 시도 2: 취약 디바이스 (firewall=disabled) ==="
    curl -H "Authorization: Bearer $TOKEN" \
         -H "X-Device-Firewall: disabled" \
         http://localhost/api/admin
    # → 403 Forbidden

    echo "=== 핵심 ==="
    echo "유효한 자격증명만으로는 부족하다."
    echo "디바이스의 보안 상태도 접근 결정에 포함된다."
    echo "이것이 ZTA의 'Continuous Verification'이다."


================================================================
  PART 5. 코드 변경 사항 (구현 목록)
================================================================

  우선순위 순으로 정렬.

  ─────────────────────────────────────────────
  [P0] 반드시 해야 함 (PDF 요구사항 충족)
  ─────────────────────────────────────────────

  1. Device Posture 시뮬레이션 추가
     파일: k8s/opa-k8s.yaml (Rego 정책에 규칙 추가)
     내용:
       - X-Device-Firewall 헤더 체크 규칙
       - X-Device-Patch-Level 체크 규칙 (선택)
       - "admin이라도 디바이스 상태가 나쁘면 차단"

     파일: Makefile (테스트 타겟 추가)
       - make test-posture-ok: admin JWT + firewall=enabled → 200
       - make test-posture-block: admin JWT + firewall=disabled → 403
       - make demo-posture: 설명 포함 데모

  2. JWT 조작 공격 테스트 추가
     파일: Makefile
       - make test-jwt-tampered: 실제 JWT의 payload를 수정한 토큰 전송
       - 현재 test-fake은 완전히 가짜 토큰, tampered는 진짜 토큰 조작
       - 차이: fake=구조 자체가 가짜, tampered=진짜를 변조

  ─────────────────────────────────────────────
  [P1] 해야 함 (시연 품질 향상)
  ─────────────────────────────────────────────

  3. Makefile에 demo 타겟 추가
     - make demo: 전체 스토리텔링 데모 (각 시나리오 설명 + 테스트)
     - make demo-lateral / demo-jwt / demo-context / demo-jwt-role / demo-posture
     - 각 demo는 echo로 상황 설명 → curl로 테스트 → echo로 원리 설명

  4. 공격 시뮬레이션 스크립트 작성
     폴더: scripts/
     - scripts/attack-lateral.sh
     - scripts/attack-jwt-forge.sh
     - scripts/attack-posture.sh
     - 각 스크립트는 실행 가능하고, 주석으로 원리 설명 포함

  ─────────────────────────────────────────────
  [P2] 하면 좋음 (완성도)
  ─────────────────────────────────────────────

  5. OPA Decision Log 포맷팅
     파일: Makefile
     - make logs-pretty: OPA 로그를 jq로 파싱해서 보기 좋게 출력
       예: "DENY | path=/api/admin | role=viewer | reason=no matching rule"
     - 발표 때 로그를 보여주면 "OPA가 실제로 결정을 내리고 있다" 증명

  6. evidence/ 폴더 구조화
     evidence/
       ├── test-results.txt          (make test-all 출력)
       ├── opa-decision-logs.txt     (OPA 로그 캡처)
       ├── zta-vs-baseline-comparison.txt (이미 있음)
       ├── screenshots/
       │   ├── kiali-topology.png
       │   ├── grafana-latency.png
       │   ├── keycloak-users.png
       │   └── keycloak-realm.png
       └── attack-logs/
           ├── lateral-movement.txt
           ├── jwt-forgery.txt
           └── device-posture.txt


================================================================
  PART 6. explanation.txt 수정 목록
================================================================

  [추가] Part 0: PDF Proposal 매핑 테이블
    - PDF에서 약속한 것 ↔ 구현한 것 매핑
    - 변경된 부분의 사유 설명

  [추가] Part 5.5 또는 새 Part: Device Posture 시나리오
    - 디바이스 상태 기반 접근 제어 설명
    - OPA Rego 규칙 설명
    - 테스트 결과 + Q&A

  [보강] Part 1: "전통 보안 vs ZTA" ASCII 다이어그램 추가
    - Castle-and-Moat 모델 그림
    - "내부=신뢰" 모델의 위험성 그림

  [보강] Part 3-6: 각 시나리오에 "공격자 관점" 추가
    - "이 방어를 뚫으려면 무엇이 필요한가"
    - "공격 비용 분석"

  [보강] Part 7: 성능 분석에 실제 비유 추가
    - 웹사이트 로딩 대비 ZTA 오버헤드 비율
    - 최적화 방안 구체화


================================================================
  PART 7. 발표/데모 준비
================================================================

  [데모 순서] (권장)
  ─────────────────────────────────────────────
  1. 아키텍처 설명 (2분)
     - NIST 800-207 컴포넌트 매핑 다이어그램
     - "PDP=OPA, PEP=Istio, IdP=Keycloak"
     - "모든 요청이 이 파이프라인을 통과한다"

  2. make status (1분)
     - 클러스터 상태, pod 목록, 보안 정책 확인
     - "이것들이 실제로 돌아가고 있다"

  3. 시나리오 1: Lateral Movement (3분)
     - make demo-lateral
     - Kiali에서 차단된 트래픽 보여주기

  4. 시나리오 2: JWT Forgery (3분)
     - make demo-jwt
     - JWT 구조 설명 (header.payload.signature)

  5. 시나리오 3: Context-Based (2분)
     - make demo-context
     - "같은 유저, 다른 결과" 매트릭스

  6. 시나리오 4: JWT Claim (2분)
     - make demo-jwt-role
     - "헤더 vs JWT: 신뢰 모델의 차이"

  7. 시나리오 5: Device Posture (2분)
     - make demo-posture
     - "유효한 자격증명 + 취약 디바이스 = 차단"

  8. 성능 분석 (2분)
     - Grafana 대시보드 보여주기
     - "+5ms는 받아들일 만한 오버헤드"

  9. 결론 (1분)
     - "ZTA는 이론이 아니라 구현 가능한 아키텍처"

  [발표 대비 Q&A 준비]
  ─────────────────────────────────────────────
  Q: 왜 VPN 대신 ZTA인가?
  Q: 실제 기업에서 이 수준의 ZTA를 구현하는가?
  Q: OPA 외에 다른 PDP 옵션은?
  Q: 성능 오버헤드를 줄이는 방법은?
  Q: Device Posture를 실제로 어떻게 수집하는가? (MDM, endpoint agent)
  Q: JWT가 탈취되면?
  Q: mTLS 인증서가 탈취되면?
  → explanation.txt의 Q&A 섹션에 이미 대부분 답이 있음


================================================================
  PART 9. Threat Model & Attack Analysis [*** 연구 격 올리기 ***]
================================================================

  [배경 - 왜 이 파트가 필요한가]
  ─────────────────────────────────────────────
  현재 프로젝트의 치명적 약점:
    - "시나리오 A~D가 pass/fail로 나왔다"는 결과만 있음
    - "왜 하필 그 4개 시나리오인가?"에 대한 답이 없음
    - "공격자가 이걸 우회하려면 뭘 시도할까?"가 없음
    - "어느 계층에서 막히고, 그 계층이 뚫리면 다음은?"이 없음

  심사자/교수의 필연적 질문:
    Q1. "네가 만든 게 ZTA라는 걸 어떻게 증명하냐?"
    Q2. "왜 이 공격 4개만 테스트했냐? 다른 건 왜 안 했냐?"
    Q3. "공격자가 mTLS/JWT/OPA 중 하나를 뚫으면 전부 뚫리냐?"
    Q4. "이 방어를 우회하는 방법은 없냐?"

  지금은 이 질문에 답할 구조가 없음. → 이 PART가 답을 만든다.

  [작업 시간 예상] 코드 변경 없음. 문서 작업만. 반나절~1일.
  [산출물] docs/threat-model.md (새 파일) + explanation.txt 보강


  ─────────────────────────────────────────────
  9-1. Threat Model (위협 모델) - 1페이지
  ─────────────────────────────────────────────

  다음 항목을 docs/threat-model.md에 정리:

  [자산 (Assets) - 지켜야 할 것]
    A1. Backend API의 데이터 (CRUD 대상)
    A2. Keycloak의 서명 private key (JWT 위조 방지)
    A3. Istio CA root certificate (mTLS 신뢰 체인)
    A4. Admin 계정 자격증명
    A5. 클러스터 내부 서비스 간 신뢰 관계

  [공격자 모델 (Adversary Model)]
    T1. 외부 미인증 공격자
        - 능력: 퍼블릭 엔드포인트에 HTTP 요청 가능
        - 목표: backend 데이터 탈취, 관리자 기능 접근
        - 예: 인터넷에서 curl로 /api/admin 시도

    T2. 자격증명 탈취 공격자 (피싱/유출)
        - 능력: 유효한 viewer JWT 소유
        - 목표: admin 경로 접근, 쓰기 권한 획득
        - 예: viewer JWT로 POST /api/write 시도

    T3. 토큰 위조 공격자
        - 능력: JWT 구조 이해, base64 조작 가능
        - 목표: 자기가 서명한 토큰 or 유효 토큰 변조로 통과
        - 예: payload의 role을 admin으로 변조

    T4. 클러스터 내부 침투 공격자 (lateral)
        - 능력: frontend pod의 CVE 악용해 침투 성공
        - 목표: backend, Keycloak, OPA로 측면 이동
        - 예: rogue pod에서 backend:80 직접 호출

    T5. [범위 밖] 공격자가 할 수 없다고 가정하는 것
        - cluster-admin kubectl 접근 (이미 게임 오버)
        - Keycloak private key 탈취 (Keycloak 서버 자체 해킹)
        - Istio CA root 탈취 (노드 루트 권한)
        - Supply chain 공격 (이미지/차트 신뢰)
        → 이 범위를 명시해야 "우리가 지키는 범위"가 분명해진다.


  ─────────────────────────────────────────────
  9-2. Attack Tree (공격 트리)
  ─────────────────────────────────────────────

  루트 목표: "Backend의 민감 데이터 CRUD"
  각 가지에 "어느 방어가 막는지" 매핑.

  Backend 데이터 CRUD
  ├── [T1] 외부에서 직접 API 호출
  │        └── 방어: Istio IngressGateway의 RequestAuthentication
  │                 (JWT 없음 → 401)
  │                 → 시나리오 2의 Step 1
  │
  ├── [T3] 위조/변조된 JWT로 호출
  │        ├── 완전 가짜 JWT
  │        │    └── 방어: Istio가 Keycloak JWKS로 서명 검증 (401)
  │        │             → 시나리오 2의 Step 2
  │        └── 진짜 JWT의 payload 변조 (viewer→admin)
  │             └── 방어: signature 무효화 (401)
  │                      → 시나리오 2의 Step 3 (*** 현재 미구현 ***)
  │
  ├── [T2] 유효 JWT + 권한 초과 호출
  │        ├── viewer JWT로 /api/admin
  │        │    └── 방어: OPA RBAC (path-role 매핑, 403)
  │        │             → 시나리오 4
  │        └── viewer JWT로 POST /api/write
  │             └── 방어: OPA RBAC (method-role 매핑, 403)
  │                      → 시나리오 4
  │
  ├── [T4] 클러스터 내부에서 backend 직접 호출
  │        ├── Sidecar 없는 rogue pod
  │        │    └── 방어: PeerAuthentication STRICT (mTLS 필요, 연결거부)
  │        │             → 시나리오 1 Step 1
  │        ├── Sidecar 있으나 잘못된 SA
  │        │    └── 방어: AuthorizationPolicy (SPIFFE allowlist, 403)
  │        │             → 시나리오 1 Step 2
  │        └── Pod IP로 직접 호출 (서비스 메시 우회 시도)
  │             └── 방어: Envoy inbound filter도 동일 정책 적용
  │                      → *** 현재 테스트 없음, 추가 권장 ***
  │
  ├── [T2+T4] 탈취된 자격증명 + 취약 디바이스
  │           └── 방어: Device Posture (OPA context, 403)
  │                    → 시나리오 5 (*** PART 5의 P0 작업으로 구현 예정 ***)
  │
  └── [범위 밖] 다음 경로는 이 프로젝트에서 방어하지 않음:
               - Keycloak 개인키 탈취 → JWT 자유 발급
               - OPA Rego 정책 자체의 버그
               - 클러스터 노드 루트 권한 획득
               - Supply chain (악성 컨테이너 이미지)

  [이 트리의 의미]
    - 시나리오 A~D가 "왜 그 4개인가"에 체계적 답 제공
    - 다층 방어(defense-in-depth) 구조가 한눈에 보임
    - 비어있는 가지(pod IP 직접 호출 테스트 등)가 드러남
      → 이것만 채우면 "구멍 없음"을 주장 가능


  ─────────────────────────────────────────────
  9-3. Defense Layer Mapping (방어 계층 매핑)
  ─────────────────────────────────────────────

  각 방어 계층의 역할과 실패 시 다음 계층:

  Layer 1: Network Identity (mTLS / PeerAuthentication)
    - 검증 대상: "이 요청이 유효한 워크로드에서 왔는가?"
    - 증거: SPIFFE ID (cert의 SAN)
    - 이 계층이 뚫리려면: Istio CA private key 또는
                         워크로드 인증서 탈취 필요
    - 실패 시 다음 계층: Layer 2 (SA allowlist)

  Layer 2: Workload Authorization (AuthorizationPolicy SA allowlist)
    - 검증 대상: "이 SPIFFE ID가 backend 호출 허가 목록에 있는가?"
    - 증거: frontend-sa만 allow 명시
    - 이 계층이 뚫리려면: frontend-sa의 토큰 탈취 +
                         frontend pod로 위장 필요
    - 실패 시 다음 계층: Layer 3 (JWT)

  Layer 3: User Authentication (RequestAuthentication / JWT sig)
    - 검증 대상: "JWT가 Keycloak이 서명한 진짜인가?"
    - 증거: RS256 signature, Keycloak JWKS public key 매칭
    - 이 계층이 뚫리려면: Keycloak private key 탈취 필요
                         (피싱으로 유효 JWT 탈취는 이걸 우회 못 함,
                          다음 계층에서 걸림)
    - 실패 시 다음 계층: Layer 4 (OPA)

  Layer 4: Context Authorization (OPA Rego: role, method, path, device)
    - 검증 대상: "이 identity가 이 action을 이 context에서 해도 되는가?"
    - 증거: OPA decision log
    - 이 계층이 뚫리려면: Rego 정책 자체의 논리 버그 +
                         OPA ConfigMap 변조 권한 필요
    - 실패 시 다음 계층: 없음 (여기가 마지막 게이트)

  [핵심 주장]
    한 계층만 뚫어서는 backend에 도달 불가.
    네 계층을 동시에 뚫으려면 cluster-admin 권한이 필요하고,
    그 순간엔 이미 범위 밖이다. → "실질적 방어 충분" 논증.


  ─────────────────────────────────────────────
  9-4. Bypass Analysis (시나리오별 우회 시도 분석)
  ─────────────────────────────────────────────

  각 시나리오마다 "공격자가 이걸 피하려면?" 한 단락씩 작성.
  explanation.txt의 각 시나리오 섹션 말미에 삽입.

  [시나리오 1 - Lateral Movement] 우회 시도:
    시도 1: Pod IP로 직접 호출 (서비스 메시 우회)
      → 결과: Envoy inbound listener도 동일 정책 적용 → 차단
      → 이유: sidecar가 iptables로 모든 inbound를 가로챔
    시도 2: frontend-sa ServiceAccount 토큰 탈취
      → 필요 조건: frontend pod 내부 파일시스템 접근
      → 필요 권한: pod exec 또는 컨테이너 RCE
      → 결론: 이 수준 공격이면 이미 다른 방어(PSP, RBAC)가 먼저 걸림
    시도 3: sidecar 주입 없는 pod로 spoofing
      → 결과: mTLS 인증서 자체가 없어서 TLS handshake 실패

  [시나리오 2 - JWT Forgery] 우회 시도:
    시도 1: JWT header의 alg를 "none"으로 변경
      → 결과: Istio RequestAuthentication이 alg 지정 검증 → 거부
    시도 2: JWKS endpoint 자체를 스푸핑 (DNS poisoning 등)
      → 필요 조건: 클러스터 내 DNS 장악 또는 MITM
      → 결론: 범위 밖 (K8s 네트워크 레벨 공격)
    시도 3: 만료된 유효 JWT 재사용
      → 결과: exp claim 검증으로 거부
      → 추가 고려: JWT revocation은 현재 범위 밖 (논문 [4] 참조)

  [시나리오 3 - Context Header] 우회 시도:
    시도 1: role: admin 헤더를 클라이언트가 임의 설정
      → 결과: *** 시나리오 3만으로는 막을 수 없음 ***
      → 그래서 시나리오 4(JWT claim 기반)가 존재함
      → 핵심: 시나리오 3은 "헤더 기반은 신뢰 못 한다"를 보이는
              의도적으로 취약한 데모. 시나리오 4가 진짜 방어.

  [시나리오 4 - JWT Claim] 우회 시도:
    시도 1: JWT payload의 realm_access.roles 배열 조작
      → 결과: signature 무효화 → 401
      → 시나리오 2 Step 3과 동일 원리
    시도 2: 다른 유저의 admin JWT 탈취
      → 필요 조건: 피싱, XSS, 세션 탈취
      → 결론: 이 공격을 완전히 막으려면 Device Posture(시나리오 5),
              token binding, 짧은 TTL 등이 필요
      → *** 시나리오 5가 이 공백을 채우는 이유 ***

  [시나리오 5 - Device Posture] 우회 시도:
    시도 1: X-Device-Firewall: enabled 헤더를 클라이언트가 직접 설정
      → 결과: *** 현재 구현(헤더 기반)의 한계 ***
      → 실제 환경 해결책: MDM 에이전트가 헤더 값을 서명하거나,
                        TLS client cert에 attestation 포함,
                        또는 gateway가 값을 주입
      → 이 한계를 솔직하게 문서화하는 것이 연구 정직성

  [최종 메시지]
    우회 시도를 전부 열거한 후:
    "모든 우회는 (a) 범위 밖 가정 위반, (b) 다음 계층에서 차단,
     (c) 현재 구현의 명시된 한계(시나리오 5 헤더) 중 하나로 귀결된다.
     이는 설계가 의도적이며 공백이 인지되고 있음을 의미한다."


  ─────────────────────────────────────────────
  9-5. NIST 800-207 Tenet Mapping (재정리)
  ─────────────────────────────────────────────

  7가지 tenet에 시나리오를 매핑해서 "이게 ZTA다"를 논증:

  Tenet 1: 모든 데이터 소스/서비스는 리소스
    → backend, Keycloak, OPA 모두 리소스로 취급, 각자 정책 적용
  Tenet 2: 네트워크 위치 무관 통신 보안
    → 시나리오 1: 내부에서도 mTLS 강제
  Tenet 3: 세션 단위 접근 부여
    → 시나리오 2/4: JWT 단위 검증, stateless
  Tenet 4: 동적 정책 기반 접근 결정
    → 시나리오 3/4/5: role+method+path+device context 결합
  Tenet 5: 자산 무결성 모니터링
    → 시나리오 5(Device Posture), Kiali 모니터링
  Tenet 6: 엄격한 인증/인가 enforcement
    → 시나리오 1-4 전부
  Tenet 7: 자산/네트워크/통신 데이터 수집
    → OPA decision log, Istio access log, Grafana metrics

  [이 표의 용도]
    "이게 왜 ZTA인가?" 질문에 "NIST 800-207의 7 tenet을 모두
     구현 시나리오로 매핑한다"로 답. 심사에서 가장 강한 논거.


================================================================
  PART 8. 작업 순서 (실행 계획)
================================================================

  Phase 0: *** 문서 분석 (연구 격 올리기 - 코드 0줄) ***
  ─────────────────────────────────────────────
  □ 0-1. docs/threat-model.md 작성 (PART 9-1: Assets + Adversary T1~T5)
  □ 0-2. Attack Tree 작성 (PART 9-2, ASCII 트리 그대로 옮기기)
  □ 0-3. Defense Layer 매핑 문서화 (PART 9-3, 4계층 실패 시 다음 계층)
  □ 0-4. Bypass Analysis 작성 (PART 9-4, 시나리오별 우회 시도 + 결론)
  □ 0-5. NIST 800-207 Tenet 매핑 표 작성 (PART 9-5)
  □ 0-6. thesis narrative 초안 작성
         (Before/Setup/Learning 구조: "무엇이 있었고, 무엇을 세팅했고,
          무엇을 배웠는지")
  *** 이 Phase 0가 연구 논문의 가장 중요한 "분석 레이어"다. ***
  *** 코드보다 이게 먼저. 반나절~1일이면 끝난다. ***

  Phase 1: 코드 변경 (구현 보강)
  ─────────────────────────────────────────────
  □ 1-1. Device Posture 규칙을 OPA Rego에 추가 (시나리오 5)
  □ 1-2. Makefile에 test-posture, demo-posture 타겟 추가
  □ 1-3. JWT 조작 공격 테스트 (test-jwt-tampered) 추가
         (시나리오 2 Step 3 - 현재 공백)
  □ 1-4. Pod IP 직접 호출 차단 테스트 추가
         (Attack Tree의 T4 비어있는 가지 채우기)
  □ 1-5. Makefile에 demo 타겟들 추가 (스토리텔링 출력)
  □ 1-6. app.py 변경 필요 시 (Device Posture 응답 등)

  Phase 2: 스크립트 & 문서
  ─────────────────────────────────────────────
  □ 2-1. scripts/ 폴더에 공격 시뮬레이션 스크립트 작성
  □ 2-2. explanation.txt 보강:
         - 각 시나리오 말미에 "우회 시도" 단락 (PART 9-4 내용)
         - Part 0에 Threat Model 요약 (PART 9-1 요약)
         - Device Posture 시나리오 섹션 추가
  □ 2-3. evidence/ 폴더 구조 정리

  Phase 3: 테스트 & 증거 수집
  ─────────────────────────────────────────────
  □ 3-1. 클러스터에 변경사항 적용 (rebuild, restart)
  □ 3-2. make test-all 실행 → evidence/test-results.txt
  □ 3-3. make logs-opa → OPA 결정 로그 캡처
  □ 3-4. 대시보드 스크린샷 (Kiali, Grafana, Keycloak)
  □ 3-5. VPN 직접 비교 가능성 점검 (1차: WireGuard)
  □ 3-6. WireGuard baseline 측정 + 결과 해석
  □ 3-7. OpenVPN은 선택 수행, 미수행 시 사유 문서화

  Phase 4: 최종
  ─────────────────────────────────────────────
  □ 4-1. Final Report 작성
  □ 4-2. 발표 리허설 (make demo 실행해보기)
  □ 4-3. 전체 cleanup & 최종 git commit

================================================================
  END
================================================================
```
