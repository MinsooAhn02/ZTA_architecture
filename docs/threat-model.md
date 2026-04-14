# ZTA Threat Model and Attack Analysis

Date: 2026-04-14
Project: ZTA sandbox (Keycloak + Istio + OPA)
Reference: NIST SP 800-207

## 1) Objective and Scope

This document explains why the selected scenarios are sufficient and how each defense layer blocks practical attack paths.

In-scope objective:

- Protect backend read/write/admin operations from external and lateral attackers.
- Show decision flow using identity, context, and policy.

Out-of-scope (explicit assumptions):

- Cluster-admin compromise
- Keycloak private key theft
- Istio CA root key theft
- Supply-chain compromise of container images/charts

## 2) Protected Assets

A1. Backend API data (read/write/admin endpoints)
A2. Keycloak signing private key (JWT trust anchor)
A3. Istio mTLS trust chain (workload identity)
A4. Admin credentials and tokens
A5. Service-to-service trust boundaries (frontend -> backend)

## 3) Adversary Model

T1. External unauthenticated attacker

- Capability: sends HTTP requests to exposed entry points
- Goal: access admin functions or data without identity

T2. Credential theft attacker

- Capability: owns a valid low-privilege token (viewer)
- Goal: escalate to admin path or write operation

T3. Token forgery attacker

- Capability: understands JWT format, can alter base64 payload/header
- Goal: bypass signature and claim checks

T4. Lateral movement attacker inside cluster

- Capability: runs rogue pod or compromises one workload
- Goal: pivot to backend directly via internal network

T5. Out-of-scope super attacker

- Capability: root-level cluster or IdP compromise
- Goal: bypass all trust anchors directly

## 4) Attack Tree (Root Goal: backend sensitive CRUD)

```text
Backend sensitive CRUD
|-- T1: Direct external call without identity
|   `-- Blocked by JWT/authz gate (401/403)
|
|-- T3: Forged or tampered JWT
|   |-- Fake signature token
|   |   `-- Blocked by no-principal authz deny path (403)
|   `-- Tampered real token payload with old signature
|       `-- Blocked by signature mismatch (401)
|
|-- T2: Valid low-privilege identity abusing privilege
|   |-- viewer -> /api/admin
|   |   `-- Blocked by OPA path+role policy (403)
|   `-- viewer -> POST /api/write
|       `-- Blocked by OPA method+role policy (403)
|
|-- T4: Internal lateral movement
|   |-- Rogue pod without sidecar
|   |   `-- Blocked by mTLS strict / policy chain (403 or handshake failure)
|   |-- Sidecar pod with wrong SA
|   |   `-- Blocked by SPIFFE/SA authorization policy (403)
|   `-- Direct pod-IP call attempt
|       `-- Expected blocked by inbound Envoy + policy (to be explicit in test target)
|
`-- T2+T4: Valid admin token from risky device posture
    `-- Blocked by posture condition (X-Device-Firewall=disabled -> 403)
```

## 5) Defense Layer Mapping (Defense in Depth)

Layer 1. Workload identity (mTLS)

- Question: is this workload cryptographically known?
- Control: PeerAuthentication STRICT + Istio cert identity

Layer 2. Workload authorization (SA/SPIFFE)

- Question: is this principal allowed to call backend?
- Control: AuthorizationPolicy allowlist

Layer 3. User authentication (JWT authenticity)

- Question: is this token issued by trusted IdP?
- Control: RequestAuthentication + JWKS signature verification

Layer 4. Context authorization (OPA)

- Question: should this identity do this action on this resource now?
- Control: role + method + path + posture conditions

Security claim:

- A single bypass is insufficient.
- Attackers need to break multiple independent controls unless they are already out-of-scope (T5).

## 6) Bypass Analysis by Scenario

Scenario A (Lateral movement)

- Attempt: sidecar-less rogue pod -> backend
- Result: blocked by mesh/policy chain
- Hard bypass requirement: cluster-level compromise or cert theft (out-of-scope)

Scenario B (JWT forgery/tamper)

- Attempt: fake token or tampered payload
- Result: fake token denied by no-principal path (403), tampered token by signature verification (401)
- Hard bypass requirement: IdP private key compromise (out-of-scope)

Scenario C (Header context demo)

- Attempt: client injects role:admin header
- Result: header model alone is weak by design
- Mitigation in project: Scenario D uses signed JWT claims as trusted source

Scenario D (JWT claim authorization)

- Attempt: viewer token on admin/write path
- Result: blocked by OPA claim+resource policy (403)
- Residual risk: stolen admin token until expiry

Scenario E (Device posture simulation)

- Attempt: attacker sends fake posture header
- Result: known limitation of header simulation
- Production path: MDM/attestation source, gateway-injected trusted posture signal

## 7) NIST 800-207 Tenet Mapping

| Tenet                                              | Project Mapping                                                  | Evidence                         |
| -------------------------------------------------- | ---------------------------------------------------------------- | -------------------------------- |
| 1. All services are resources                      | frontend/backend/keycloak/opa all treated as protected resources | policy files and scenario matrix |
| 2. Secure all communication regardless of location | internal east-west uses mTLS and policy                          | lateral tests (rogue/wrong SA)   |
| 3. Per-session access grant                        | JWT-based request/session validation                             | JWT fake/tamper/valid tests      |
| 4. Dynamic policy decisions                        | OPA evaluates role+method+path+posture                           | context and JWT-role scenarios   |
| 5. Asset integrity monitoring                      | posture check demonstrates integrity signal concept              | posture allow/deny tests         |
| 6. Dynamic authn/authz                             | authn (Istio) and authz (OPA) are continuously enforced          | 401 vs 403 behavior and logs     |
| 7. Collect telemetry                               | OPA decision logs and dashboards                                 | logs-pretty, Kiali, Grafana      |

## 8) Thesis Narrative (Compact)

Before:

- Initial implementation proved basic policy enforcement but lacked explicit threat structure and proposal-to-implementation traceability.

Setup:

- Structured threat model and attack tree were added.
- Existing scenarios were mapped to layered controls and NIST tenets.
- Remaining gap (pod-IP explicit test target) was isolated as a concrete engineering task.

Learning:

- ZTA value comes from layered verification, not one control.
- Header-only context is useful for demonstration but weak as trust source.
- Strong trust requires cryptographic identity and trusted posture source.

## 9) Immediate Next Actions

1. Add explicit pod-IP bypass Makefile test target and include in lateral suite.
2. Run full tests and export evidence files.
3. Sync explanation narrative with this threat model.
