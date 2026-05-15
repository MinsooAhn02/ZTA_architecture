# Presentation Script — ZTA Sandbox Implementation
**5-minute talk · English · School presentation**

---

## Slide 1 — Title (~20s)

**[Slide content]**
- Zero Trust Architecture Sandbox Implementation
- NIST SP 800-207 · Keycloak + Istio + OPA · Kubernetes
- Minsoo Ahn

**[Speaker notes]**
> "Hi everyone. Today I'll present my project — a working implementation of Zero Trust Architecture on Kubernetes, validated against five real attack scenarios. The goal was not just to read about ZTA, but to build it, break it, and prove that it holds."

---

## Slide 2 — The Problem: Why ZTA? (~60s)

**[Slide content]**
- Classic attack: phishing → stolen credential → inside the network
- Stage 1 (North-South): valid token → firewall lets it through
- Stage 2 (East-West): lateral movement — pods trust each other by default
- Traditional tools **cannot stop this**:
  - Firewall: no East-West visibility
  - VPN: grants broad access once connected; no per-request check
  - DPI / App Proxy: inspects content, not workload identity
  - Server-side token checks: only as secure as the weakest service

**[Speaker notes]**
> "The threat model starts simple. An attacker steals one employee's credentials through phishing. The firewall sees a valid token and lets them in. Now they're inside. And inside Kubernetes, pods trust each other by default — no certificate required, no re-verification. The attacker pivots from service to service without triggering any alert. This is lateral movement — and it's the dominant pattern in real-world breaches. Traditional tools all share one assumption: trust is established at the boundary and maintained inside. That assumption breaks in modern containerized environments."

---

## Slide 3 — Our Solution: ZTA Stack (~50s)

**[Slide content]**
- Core principle: **"Never trust, always verify — per request, regardless of origin"**
- Three components mapping to NIST SP 800-207:

| NIST Role | Tool | Function |
|-----------|------|----------|
| PEP (Enforcement Point) | Istio / Envoy sidecar | Intercepts every request; enforces decisions |
| PDP (Decision Point) | OPA (Open Policy Agent) | Evaluates Rego policy; returns allow/deny |
| IdP (Identity Provider) | Keycloak | Issues cryptographically signed JWTs |

- East-West: **mTLS STRICT + SPIFFE** workload identity (pod-level certificates)

**[Speaker notes]**
> "ZTA replaces perimeter trust with one rule: verify every request, every time. I implemented this with three open-source components. Istio's Envoy sidecar is injected into every pod and intercepts all traffic — that's the enforcement point. OPA evaluates the policy: is this role allowed to make this request to this path with this device posture? Keycloak issues signed JWTs. For pod-to-pod traffic, mTLS with SPIFFE certificates enforces workload identity — a pod without a certificate literally cannot connect."

---

## Slide 4 — Architecture & Request Flow (~60s)

**[Slide content]**
- Every inbound request passes through this pipeline (North-South):
  ```
  Client → [Istio JWT Auth] → [Istio DENY Policy] → [OPA Rego] → App
                  ↑
            Keycloak JWKS (RSA signature verify)
  ```
- East-West enforcement (pod-to-pod):
  ```
  Rogue Pod → [mTLS STRICT] → [SPIFFE Allowlist] → Backend
  ```
- Enforcement at **infrastructure layer** — before any application code runs
- Independent layers: compromising one does not bypass the others

**[Speaker notes]**
> "Here's the key architectural point. Every request, before it reaches the application, is checked at the infrastructure layer. First Istio verifies the JWT signature against Keycloak's public key. Then it checks whether a valid principal was set. Then OPA evaluates role, method, path, and device posture — all in one Rego policy. For internal traffic, mTLS + SPIFFE handles it separately. The layers are independent. An attacker with a valid token but no pod certificate is blocked at mTLS. An attacker with a valid certificate but a forged token is blocked at JWT auth. No single bypass is sufficient."

---

## Slide 5 — Results: 5 Scenarios, 18 Tests (~70s)

**[Slide content]**

| Scenario | Attack | Control | Result |
|----------|--------|---------|--------|
| A — Lateral Movement | Rogue pod; wrong workload identity | mTLS STRICT + SPIFFE allowlist | Blocked |
| B — JWT Forgery | Forged key; tampered payload | Istio JWKS RSA signature verify | Blocked |
| C — Context Access | Wrong method/path for user role | OPA role + method + path policy | Blocked |
| D — Role Escalation | Viewer JWT attempts admin endpoint | OPA `io.jwt.decode` claim check | Blocked |
| E — Device Posture | Valid admin token, unhealthy device | OPA `X-Device-Firewall` posture | Blocked |

**18 / 18 test cases: PASS**

Key insight: **each layer is independently enforceable — no single bypass breaks the chain.**

**[Speaker notes]**
> "I ran 18 automated test cases across 5 attack scenarios. All 18 passed. Let me highlight the key result. In Scenario B — JWT forgery — the attacker signs a token with their own private key. Istio detects the RSA signature mismatch and blocks it before OPA even sees the request. In Scenario E — device posture — even a stolen valid admin token is denied because the device firewall signal is missing. The point is that authentication alone is never enough in ZTA. You need identity, role, and context — and all three are verified independently on every single request."

---

## Slide 6 — Conclusion (~20s)

**[Slide content]**
- ZTA adds what Firewall / VPN / DPI **cannot**:
  - Cryptographic workload identity (pod-to-pod)
  - Per-request re-verification (no implicit session trust)
  - Context-aware policy (role + method + path + device)
  - Block lateral movement **inside** the network
- Open-source stack: Istio + OPA + Keycloak — fully reproducible
- Proven at scale: Google BeyondCorp since 2014

**[Speaker notes]**
> "To wrap up: ZTA doesn't replace your firewall. It fills the gap that firewalls, VPNs, and DPI proxies fundamentally cannot close — per-request, cryptographically-bound, context-aware authorization at the workload level. This project shows that's achievable with open-source tools on a local cluster. Thank you."

---

## [Optional Demo — only if time remains]

**Sequence:**
1. Open `http://localhost:5001` (dashboard already running via `make view`)
2. Click **B-1: Forged JWT reject** → terminal shows `make test-fake` running → FAIL → topology animates block at "Istio JWT Auth"
3. Click **E-2: Posture disabled deny** → terminal shows `make test-posture-block` → FAIL → block at "OPA Policy"
4. Click **B-4: Valid Keycloak JWT allow** → shows full green path through all nodes

**Script if showing demo:**
> "Here's the live dashboard. When I click a scenario card, it actually runs the make command — you can see the raw curl output in the terminal. This is B-1: forged JWT. Blocked at Istio before OPA even runs. And here's the happy path — valid token, all nodes green."

---

## Timing Guide

| Slide | Topic | Target |
|-------|-------|--------|
| 1 | Title | 0:20 |
| 2 | Problem | 1:20 |
| 3 | ZTA Stack | 2:10 |
| 4 | Architecture | 3:10 |
| 5 | Results | 4:20 |
| 6 | Conclusion | 4:40 |
| Demo (optional) | Live dashboard | 4:40–5:00 |
