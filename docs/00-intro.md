# Introduction: Why Zero Trust Architecture?

## 1. The Attack Scenario

An attacker does not need to break through a firewall directly. A phishing email obtains one employee's credentials. From there, the attack unfolds in two stages.

**Stage 1 — Getting in (North-South traffic: external → internal).**
The attacker authenticates via the company's IdP (Identity Provider) and receives a valid access token. The firewall sees a legitimate request and lets it through.

**Stage 2 — Moving around (East-West traffic: internal service ↔ internal service).**
Inside the network, services trust each other by default. A request from one pod (the smallest deployable unit in a Kubernetes cluster) to another needs no further verification — they are both "inside." The attacker pivots from the compromised service to a backend database, then to an admin API, without triggering any alert.

This two-stage pattern — credential theft followed by unchecked lateral movement — is the dominant model in real-world breaches.

---

## 2. Why Traditional Security Falls Short

| Mechanism | What it does well | The gap |
|---|---|---|
| **Firewall** | Blocks unauthorized North-South traffic | No visibility into East-West traffic; once inside, requests are trusted |
| **IdP + Token checks** | Verifies user identity at login | Each service must implement validation correctly; no check on device health or workload identity |
| **App Proxy / DPI** | Inspects request content, blocks known attack patterns | Cannot enforce workload identity or deny requests based on device software vulnerabilities |
| **VPN** | Encrypts the network tunnel | Grants broad internal access once connected; individual requests are not re-evaluated |

The common assumption across all four: **trust is established at the boundary and maintained inside.** In modern infrastructure — containers on shared clusters, employees on unmanaged devices — that perimeter no longer exists as a reliable boundary.

---

## 3. Zero Trust Architecture: A Different Assumption

ZTA replaces perimeter trust with one principle:

> **Never trust, always verify — regardless of where the request comes from.**

Every request must prove its identity and be authorized against policy *per request*, not once per session. The three components that implement this are:

- **PEP (Policy Enforcement Point):** intercepts every request and enforces decisions — here, the Istio/Envoy sidecar injected alongside every pod.
- **PDP (Policy Decision Point):** evaluates policy and returns allow or deny — here, OPA (Open Policy Agent), using Rego (a declarative policy language).
- **IdP (Identity Provider):** issues cryptographically signed tokens — here, Keycloak.

East-West workload identity is enforced through mTLS (Mutual TLS — both client and server present certificates to each other) using SPIFFE/SVID (a standard for issuing cryptographic machine identities). The PEP and PDP communicate via gRPC (a high-performance remote procedure call framework), keeping enforcement and decision logic independently deployable.

In concrete terms: a pod without a certificate cannot connect, a valid token from an unhealthy device is denied, and a low-privilege user cannot reach an admin endpoint regardless of what headers they set.

---

## 4. This Is Not Just Theory: Google BeyondCorp

Google implemented this model in their **BeyondCorp** initiative (first published 2014, in production since). The result: their internal corporate VPN was removed entirely. Access is granted based on identity and device state alone — the network the employee is on is irrelevant. ZTA is operationally proven at scale.

This project implements the same architectural pattern using open-source tooling (Istio, OPA, Keycloak) on a reproducible local cluster.

---

## 5. What This Project Demonstrates

| Scenario | Attack Type | ZTA Control |
|---|---|---|
| A | Lateral movement — rogue pod, wrong workload identity | mTLS STRICT + SPIFFE allowlist |
| B | JWT forgery and payload tampering | Istio JWKS signature verification |
| C | Over-privileged access via header manipulation | OPA role + method + path policy |
| D | Role escalation via JWT claim | Keycloak-signed JWT + OPA claim policy |
| E | Valid credential from unhealthy device | OPA device posture condition |

**Recommended reading order:**
1. [What It Can Do](01-what-it-can-do.md) — capabilities and test scenarios
2. [Threat Model](02-threat-model.md) — attack paths and defense layer mapping
3. [How It Works](03-how-it-works.md) — architecture, request flow, and NIST SP 800-207 alignment
4. [Changes from Proposal](04-added.md) — what was added beyond the original proposal
5. [Implementation Checklist](05-checklist.md) — verification status and evidence
6. [Final Report](06-final-report-draft.md) — summary and conclusions
