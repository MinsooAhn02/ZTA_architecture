# Zero Trust Architecture Sandbox — Final Report

**Author:** Minsoo Ahn
**Date:** 2026-04-14
**Reference:** NIST SP 800-207

---

## 1. Executive Summary

This project implements a working Zero Trust Architecture (ZTA) sandbox using three open-source components — Istio (service mesh), OPA (policy engine), and Keycloak (identity provider) — on a local Kubernetes cluster, aligned to NIST SP 800-207.

The central argument is not that ZTA replaces existing security tools, but that it enforces a class of decisions that traditional mechanisms fundamentally cannot: **per-request, cryptographically-bound, context-aware authorization at the workload level.** Five attack scenarios are validated end-to-end, each targeting a gap that firewalls, VPNs, or application proxies leave open.

---

## 2. What Standard Security Cannot Do — and Why ZTA Fills the Gap

A common question when reviewing ZTA implementations is whether the same outcomes can be achieved with existing mechanisms: server-side token checks, firewall rules, IDP configurations, or application proxies with deep packet inspection (DPI).

The answer is: partially, but not at the workload level, and not for the right threat model.

| Capability | Firewall | App Proxy / DPI | VPN | **This ZTA** |
|---|---|---|---|---|
| Block unauthenticated external traffic | Yes | Yes | Yes | Yes |
| Per-request role + method + path policy | No | Partial | No | **Yes** |
| Cryptographic workload identity (pod-to-pod) | No | No | No | **Yes (SPIFFE/mTLS)** |
| Block lateral movement inside the network | No | No | No | **Yes** |
| Deny access based on device health / software posture | No | No | No | **Yes** |
| Per-request re-evaluation (no implicit session trust) | No | No | No | **Yes** |

**The firewall gap:** Firewalls operate at the network boundary. Once a request passes the perimeter — via a valid credential, a stolen token, or a legitimate internal service — the firewall has no further role. Internal (East-West) traffic between pods is invisible to it.

**The application proxy / DPI gap:** DPI inspects request content and can block known attack patterns. However, it operates on *what a request contains*, not on *who is making it at the workload level*. It cannot enforce a policy such as: *deny this request because the source device is running software with a known unpatched critical vulnerability.* That decision requires a trusted posture signal and identity-aware policy evaluation — neither of which is in scope for DPI.

**The VPN gap:** VPN encrypts the transport tunnel. Once a user is connected, they receive broad network access within their segment. Individual service-to-service requests are not re-evaluated. VPN secures the path; ZTA secures the request.

**The server-side token check gap:** Distributing token validation to each application means security correctness depends on every service implementing it properly. One misconfigured or unpatched service breaks the chain. ZTA moves this enforcement to the infrastructure layer (Envoy sidecar), making it independent of application code and uniformly applied.

ZTA addresses all of these gaps by enforcing identity verification and context-aware policy at the infrastructure layer, before any application code executes.

---

## 3. Architecture

Three components map directly to NIST SP 800-207 Figure 1:

| NIST Role | Component | Function |
|---|---|---|
| PEP (Policy Enforcement Point) | Istio / Envoy sidecar | Intercepts every request; enforces decisions |
| PDP (Policy Decision Point) | OPA (Open Policy Agent) | Evaluates Rego policy; returns allow or deny |
| IdP (Identity Provider) | Keycloak | Issues signed JWTs; manages users and roles |

The request flow: every inbound request passes through the Envoy sidecar → JWT signature is verified against Keycloak's public key → OPA evaluates role, method, path, and device posture → decision is enforced before the application sees the request.

East-West (pod-to-pod) traffic is separately governed by mTLS STRICT and SPIFFE-based workload identity, enforced independently of the user-facing authorization path.

---

## 4. Security Scenario Outcomes

| Scenario | Attack | Control | Result |
|---|---|---|---|
| A | Lateral movement — rogue pod, wrong workload identity | mTLS STRICT + SPIFFE allowlist | Blocked (403 / handshake failure) |
| B | JWT forgery and payload tampering | Istio JWKS signature verification | Blocked (403 forged / 401 tampered) |
| C | Over-privileged access via header manipulation | OPA role + method + path policy | Blocked (403) |
| D | Role escalation via JWT claim | Keycloak-signed JWT + OPA claim policy | Blocked (403) |
| E | Valid credential from unhealthy device | OPA device posture condition | Blocked (403) |

All 18 test cases across Scenarios A–E (A:5, B:3, C:4, D:4, E:2) passed in the final validation run. Full output: `evidence/test-results.txt`.

**Key security property:** No single bypass is sufficient. An attacker with a valid token but no workload certificate is blocked at Layer 1. An attacker with a valid certificate but a forged token is blocked at Layer 3. An attacker with a valid token and valid certificate but the wrong role is blocked at Layer 4. Layers are independent.

---

## 5. Performance Trade-off

Measured on local Minikube (Docker Desktop on WSL2) using Fortio (200 requests, single
persistent connection, `-qps 0`). Baseline = Istio sidecar present but no AuthorizationPolicy
or PeerAuthentication applied, so the delta isolates policy-enforcement cost (not the sidecar):

| Metric | Baseline | ZTA Enabled | Delta |
|---|---|---|---|
| Avg Latency | 5.33 ms | 6.86 ms | +1.53 ms (+28.6%) |
| Throughput (QPS) | 187.5 | 145.7 | −22.3% |
| p99 Latency | 8.5 ms | 10.5 ms | +2.0 ms (+23.5%) |

The absolute overhead (+1.53 ms) is negligible for human-facing applications (perceptible threshold ≈ 100 ms). The QPS drop is significant only in single-connection micro-benchmarks. In production with connection reuse and OPA caching, typical overhead is 1–3 ms.

For comparison, WireGuard VPN adds ~0.1–3 ms transport overhead but provides none of the per-request authorization or lateral movement controls. The recommended production configuration is WireGuard for network-layer entry combined with ZTA inside the cluster — complementary, not alternatives.

---

## 6. Known Limitations

| Limitation | Scope | Production Path |
|---|---|---|
| Device posture is header-simulated | Scenario E demo only | MDM / endpoint attestation signal injection at gateway |
| role header rules active alongside JWT path | Scenarios A/C demo scaffolding — clearly marked in policy | Remove header-based rules; enforce JWT-only (Scenario D) |
| Envoy ↔ OPA gRPC channel is plaintext | Structural: sidecar injection on OPA creates circular dependency | NetworkPolicy restricting port 9191 to mesh-internal traffic (`k8s/opa-network-policy.yaml`) |
| Cluster-admin compromise breaks all controls | Out of scope | IAM hardening, audit logging, network policy |
| Keycloak private key compromise invalidates JWT trust | Out of scope | Key rotation policy, HSM storage |

---

## 7. Conclusion

This sandbox demonstrates that ZTA can be implemented as enforceable, layered infrastructure controls — not as application-level logic spread across services. The key result: even when one credential or one path is compromised, per-request re-verification and context-aware policy at the infrastructure layer significantly reduce lateral movement and privilege escalation risk.

The controls demonstrated here — workload identity via mTLS/SPIFFE, cryptographic token verification, and policy-as-code authorization via OPA — address a class of threats that firewalls, DPI proxies, and VPNs are architecturally not designed to handle. This is not a theoretical claim; Google's BeyondCorp initiative has applied the same model in production since 2014, replacing corporate VPN with identity-and-posture-based access entirely.

The open-source stack used in this project makes this architecture reproducible and accessible without proprietary infrastructure.
