# Presentation Script — ZTA Sandbox Implementation
**5-minute talk · English · School showcase · Audience: non-security-expert professors**

---

## Slide 1 — Title (~15s)

**[Slide content]**
- **Zero Trust Architecture: Proven Security on Kubernetes**
- NIST SP 800-207 · Istio + OPA + Keycloak
- Minsoo Ahn | 2026

**[Speaker notes]**
> "Hi everyone. I'm Minsoo Ahn. Today I'll walk you through my project — a working implementation of Zero Trust Architecture on Kubernetes. I didn't just study the theory. I built a system, attacked it with five real attack scenarios, and proved it holds under each one."

---

## Slide 2 — The Problem: Perimeter Security Is Broken (~55s)

**[Slide content]**

*[Diagram: two-stage attack flow]*

**Stage 1 — Getting In (North-South traffic)**
- Attacker steals one employee's password via phishing
- Firewall sees a valid login → lets them through ✓

**Stage 2 — Moving Around (East-West / Lateral Movement)**
- Inside Kubernetes, containers (pods) trust each other by default
- Attacker pivots: pod → database → admin API — no alerts triggered ✗

**The shared flaw of traditional tools:**

| Tool | What it does | The gap |
|------|-------------|---------|
| Firewall | Blocks unauthorized entry | No visibility inside the network |
| VPN | Encrypts the tunnel | Broad access once connected; no per-request check |
| App Proxy | Inspects request content | Cannot verify workload identity |

> Traditional security: **trust is established at the boundary, assumed inside.**

**[Speaker notes]**
> "Think of a hotel. Security checks your ID at the front door. Once you're inside, you can walk to any floor — they don't check again. That's exactly how most networks work. An attacker steals one employee's password through a phishing email. They log in — the firewall sees a valid credential and lets them through. Now they're inside. And inside a Kubernetes cluster — the system that runs containerized applications — the individual services trust each other by default. No further verification required. The attacker can jump from one service to the next without triggering a single alert. This pattern — steal one credential, roam freely inside — is the dominant model in real-world breaches. The problem is not the perimeter tools. It's the assumption they all share: once you're in, you're trusted."

---

## Slide 3 — Solution: Zero Trust Architecture (~50s)

**[Slide content]**

**Core Principle:** *"Never trust, always verify — every request, every time."*

*[Diagram: 3-component architecture mapped to NIST SP 800-207]*

| NIST Role | Tool | What It Does |
|-----------|------|-------------|
| Enforcement Point (PEP) | **Istio / Envoy sidecar** | Intercepts every request before the app sees it |
| Decision Point (PDP) | **OPA (Open Policy Agent)** | Evaluates: right role? right endpoint? healthy device? |
| Identity Provider (IdP) | **Keycloak** | Issues cryptographically signed digital tokens (JWT) |

**Pod-to-pod (East-West):** mTLS mutual certificates + SPIFFE workload identity
→ No certificate = no connection. Period.

**[Speaker notes]**
> "Zero Trust replaces the hotel model with one rule: every request must prove itself — every time, regardless of where it comes from. I built this with three open-source components. Istio acts like a security guard injected directly into every container — it intercepts all traffic before the app code even runs. OPA is the policy engine — it answers the question: is this user, with this role, allowed to call this specific API path, from a device that's currently in a healthy state? Keycloak is the identity system — it issues digitally signed tokens, like a cryptographic ID badge that cannot be forged. And for container-to-container traffic inside the cluster, mutual TLS enforces that both sides present a certificate. A container without one cannot connect at all."

---

## Slide 4 — How Every Request Is Verified (~70s)

**[Slide content]**

*[Diagram: two-path verification pipeline]*

**Path 1 — External Request (North-South):**
```
Client
  → [Layer 3] Istio verifies JWT signature against Keycloak public key
  → [Layer 4] OPA evaluates: role + HTTP method + path + device posture
  → App receives only pre-approved requests
```

**Path 2 — Internal Pod-to-Pod (East-West):**
```
Pod A
  → [Layer 1] mTLS STRICT: both pods present SPIFFE certificates
  → [Layer 2] SPIFFE allowlist: only frontend-sa identity is permitted
  → Backend App
```

**Key property:** Security enforced at the **infrastructure layer** — independent of application code. Layers are independent: bypassing one does not bypass the others.

**[Speaker notes]**
> "Here's how it works. Every external request goes through a two-step pipeline. First, Istio checks that the digital token was actually signed by Keycloak — not forged by an attacker. If the signature is wrong, it's rejected immediately, before the policy engine even runs. If the signature is valid, OPA evaluates the full context: what role does this user have? what operation are they trying to perform? is the device they're on in a healthy state? Only if all conditions pass does the request reach the application. For traffic between containers inside the cluster — which firewalls can't see at all — it's enforced separately through mutual TLS certificates. These layers are completely independent. A valid token doesn't bypass the certificate check. A valid certificate doesn't bypass the policy check. An attacker who compromises one layer is still blocked by the others."

---

## Slide 5 — Results: 5 Attack Scenarios, 20 Tests (~70s)

**[Slide content]**

*[Results table with BLOCKED column highlighted in red/green]*

| # | Attack Type | Defense Layer | Result |
|---|------------|---------------|--------|
| A | Rogue pod — no workload certificate | mTLS STRICT + SPIFFE allowlist | ✅ BLOCKED |
| B | JWT forgery — token signed with attacker's own key | Istio RSA signature verification | ✅ BLOCKED |
| C | Path escalation — user role calls admin endpoint | OPA role + method + path policy | ✅ BLOCKED |
| D | Role escalation — viewer JWT targets admin endpoint | OPA JWT claim check | ✅ BLOCKED |
| E | Valid admin token from unhealthy device | OPA device posture condition | ✅ BLOCKED |

**20 / 20 test cases: ALL PASS**

> Key insight: **no single bypass is sufficient** — every layer independently enforced.

**[Speaker notes]**
> "I ran 20 automated test cases across five attack scenarios. Let me highlight two results. In Scenario B — JWT forgery — the attacker creates their own digital token and signs it with their own key. Istio detects the RSA signature mismatch and blocks it before OPA even evaluates a single rule. In Scenario E — device posture — even a completely valid, legitimately issued admin token is denied because the device health signal is absent. This is the core property of Zero Trust: who you are is not enough. You need the right identity, the right permissions, and the right context — all independently verified on every single request. Twenty out of twenty tests passed."

---

## Slide 6 — Conclusion (~30s)

**[Slide content]**

**What ZTA adds that traditional tools cannot:**

| Traditional tools miss | ZTA enforces |
|-----------------------|-------------|
| East-West (internal) traffic | Cryptographic workload identity between containers |
| Per-request re-verification | No implicit session trust — every request re-evaluated |
| Context-aware decisions | Role + method + path + device posture, per request |
| Lateral movement inside network | Blocked at infrastructure layer before app code |

- **Stack:** Istio + OPA + Keycloak — open-source, fully reproducible
- **Latency cost:** +4.85 ms avg — negligible for human-facing apps (threshold ≈ 100 ms)
- **Production proof:** Google BeyondCorp (2014) — same model, replaced corporate VPN entirely

**[Speaker notes]**
> "To wrap up: Zero Trust doesn't replace your firewall. It fills the gap that firewalls, VPNs, and application proxies are architecturally not designed to handle — per-request, cryptographically-bound, context-aware authorization at the workload level. This project shows it's achievable with open-source tools on a local cluster. The same model has powered Google's internal network since 2014. Thank you."

---

## Timing Guide

| Slide | Topic | Cumulative |
|-------|-------|-----------|
| 1 | Title | 0:15 |
| 2 | The Problem | 1:10 |
| 3 | ZTA Solution | 2:00 |
| 4 | Architecture | 3:10 |
| 5 | Results | 4:20 |
| 6 | Conclusion | 4:50 |

---

---

# Claude Web Prompt — Paste This to Generate Marp PPT

> Copy everything below this line and paste it into Claude.ai (claude.ai/new) to generate the Marp slides.

---

Create a **Marp presentation** (marp: true) for the following content. Requirements:

- **Theme:** uncover (dark, professional)
- **Style:** CS academic presentation — diagrams, data tables, and results-first
- **Audience:** Non-security-expert professors — explain jargon with a short parenthetical the first time it appears
- **Font:** Clean monospace for code/diagrams; sans-serif for body
- **Color accent:** Use a consistent blue (#2E86AB) for headers and key callouts
- **Each slide:** Clear title, minimal text, one visual (diagram or table) per slide
- **Slides:** 6 total

---

**Slide 1 — Title**
- Title: Zero Trust Architecture: Proven Security on Kubernetes
- Subtitle: NIST SP 800-207 · Istio + OPA + Keycloak
- Author: Minsoo Ahn | 2026
- Visual: simple horizontal rule separator

**Slide 2 — The Problem: Perimeter Security Is Broken**
- Top half: two-stage attack diagram using ASCII art or SVG-style flow
  - Stage 1: Phishing → stolen password → firewall lets valid token through (North-South)
  - Stage 2: Inside cluster, pods trust each other by default → lateral movement (East-West)
- Bottom half: 3-row table showing gaps of Firewall / VPN / App Proxy
- Big callout box: "Traditional security: trust established at the boundary, assumed inside."

**Slide 3 — Solution: Zero Trust Architecture**
- Large callout: "Never trust, always verify — every request, every time."
- 3-row table (NIST role | Tool | What it does):
  - Enforcement Point (PEP) | Istio / Envoy sidecar | Intercepts every request before the app sees it
  - Decision Point (PDP) | OPA (Open Policy Agent) | Evaluates: right role? right endpoint? healthy device?
  - Identity Provider (IdP) | Keycloak | Issues cryptographically signed digital tokens (JWT)
- Footer note: "Pod-to-pod: mTLS mutual certificates + SPIFFE workload identity — no cert = no connection"

**Slide 4 — How Every Request Is Verified**
- Title: "Two Independent Verification Pipelines"
- Left column — North-South (External Request):
  ```
  Client
    → [L3] Istio: verify JWT signature (Keycloak public key)
    → [L4] OPA: role + method + path + device posture
    → App (only if all checks pass)
  ```
- Right column — East-West (Pod-to-Pod):
  ```
  Pod A
    → [L1] mTLS STRICT: mutual certificates
    → [L2] SPIFFE allowlist: only frontend-sa permitted
    → Backend App
  ```
- Footer callout (highlighted): "Layers are independent — bypassing one does NOT bypass the others."

**Slide 5 — Results: 5 Attack Scenarios, 20 Tests**
- 5-row results table with columns: # | Attack Type | Defense Layer | Result
  - A | Rogue pod — no workload certificate | mTLS STRICT + SPIFFE allowlist | ✅ BLOCKED
  - B | JWT forgery — attacker-signed token | Istio RSA signature verification | ✅ BLOCKED
  - C | Path escalation — user calls admin endpoint | OPA role + method + path policy | ✅ BLOCKED
  - D | Role escalation — viewer JWT targets admin | OPA JWT claim check | ✅ BLOCKED
  - E | Valid admin token, unhealthy device | OPA device posture condition | ✅ BLOCKED
- Large bold result: "20 / 20 test cases: ALL PASS"
- Key insight callout: "No single bypass is sufficient — every layer independently enforced."

**Slide 6 — Conclusion**
- Comparison table: "What traditional tools miss" vs "What ZTA enforces" (4 rows)
  - East-West traffic → Cryptographic workload identity between containers
  - Per-request re-verification → No implicit session trust
  - Context-aware decisions → Role + method + path + device posture, per request
  - Lateral movement → Blocked at infrastructure layer
- Three bullet points:
  - Stack: Istio + OPA + Keycloak — open-source, fully reproducible
  - Latency: +4.85 ms avg overhead — negligible (human threshold ≈ 100 ms)
  - Proven at scale: Google BeyondCorp (2014) — replaced corporate VPN
- Final line: "Thank you."

---

Output the complete Marp markdown file, ready to render. Use `---` to separate slides. Include `marp: true`, `theme: uncover`, and `paginate: true` in the frontmatter.
