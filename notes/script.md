# Presentation Script — ZTA Sandbox Implementation
**5-minute talk · English · UROP Showcase · Audience: peers + UROP reviewers (non-security background)**

---

## Slide 1 — Title (~15s)

**[Layout]**
```
┌─────────────────────────────────┐
│                                 │
│   Zero Trust Architecture:      │
│   Proven Security on Kubernetes │
│                                 │
│   NIST SP 800-207               │
│   Istio + OPA + Keycloak        │
│                                 │
│   Minsoo Ahn | 2026             │
│                                 │
└─────────────────────────────────┘
큰 제목 중앙 정렬, 부제목 작게, 이름/연도 하단
```

**[Speaker notes]**
> "Hi everyone. I'm Minsoo Ahn. My project is about a security architecture called Zero Trust. I didn't just read about it — I built a working system, attacked it with five real attack scenarios, and showed it holds up against each one."

---

## Slide 2 — The Problem: How Attacks Actually Work (~30s)

**[Layout]**
```
┌─────────────────────────────────────────────────┐
│                                                 │
│  [Phishing email]  →  [Stolen password]         │
│        ↓                                        │
│  Firewall: valid credential → LETS THROUGH ✓   │
│        ↓                                        │
│  Inside cluster:                                │
│  Pod A  →  Pod B  →  Database  →  Admin API    │
│        (no checks, no alerts) ✗                 │
│                                                 │
│  ┌─────────────────────────────────────────┐   │
│  │ "Once you're in, you're trusted."        │   │
│  └─────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
화살표 흐름 다이어그램 + 하단 callout 박스 1개
```

**[Speaker notes]**
> "Think of a hotel. Security checks your ID at the front door — but once you're inside, you can walk to any floor without being checked again. Most networks work exactly like that. An attacker steals one password through a phishing email, logs in, and the firewall waves them through because the credential looks valid. Now they're inside. And inside a Kubernetes cluster — the system that runs containerized apps — each service trusts the others by default. The attacker can jump from service to service, quietly, without triggering a single alert. This is called lateral movement, and it's the dominant pattern in real-world breaches."

---

## Slide 3 — The Gap in Traditional Tools (~25s)

**[Layout]**
```
┌─────────────────────────────────────────────────┐
│                                                 │
│  Tool       │ What it does          │ The gap   │
│  ───────────┼───────────────────────┼─────────  │
│  Firewall   │ Blocks bad entry      │ No        │
│             │                       │ visibility│
│             │                       │ inside    │
│  VPN        │ Encrypts the tunnel   │ Broad     │
│             │                       │ access    │
│             │                       │ once in   │
│  App Proxy  │ Inspects content      │ Can't     │
│             │                       │ verify    │
│             │                       │ workload  │
│                                                 │
│  ┌─────────────────────────────────────────┐   │
│  │ "Trust established at the boundary,      │   │
│  │  assumed inside."                        │   │
│  └─────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
3행 테이블 + 하단 callout 박스 1개
```

**[Speaker notes]**
> "The issue isn't any single tool — it's the shared assumption they all make. Firewalls block the door but can't see inside. VPNs encrypt the tunnel but give broad access once connected. App proxies inspect content but can't verify which workload is actually making the request. None of them check again after you're in."

---

## Slide 4 — Solution: Zero Trust Architecture (~50s)

**[Layout]**
```
┌─────────────────────────────────────────────────┐
│                                                 │
│  ┌─────────────────────────────────────────┐   │
│  │ "Never trust, always verify —            │   │
│  │  every request, every time."             │   │
│  └─────────────────────────────────────────┘   │
│                                                 │
│  NIST Role         │ Tool      │ What It Does   │
│  ──────────────────┼───────────┼─────────────   │
│  Enforcement (PEP) │ Istio     │ Intercepts     │
│                    │ /Envoy    │ every request  │
│  Decision  (PDP)   │ OPA       │ role? path?    │
│                    │           │ device?        │
│  Identity  (IdP)   │ Keycloak  │ Issues signed  │
│                    │           │ tokens (JWT)   │
│                                                 │
│  Pod-to-pod: mTLS + SPIFFE — no cert = no conn  │
└─────────────────────────────────────────────────┘
상단 callout 박스 + 3행 테이블 + 하단 한 줄 강조
```

**[Speaker notes]**
> "Zero Trust replaces that assumption with one rule: every request must prove itself, every time, no matter where it comes from. I built this with three open-source tools. Istio acts like a security guard injected into every container — it intercepts all traffic before the app code even runs. OPA is the policy engine — it asks: does this user have the right role, are they calling the right endpoint, is their device healthy? Keycloak issues digitally signed tokens — like a cryptographic badge that can't be faked. And for container-to-container traffic inside the cluster, mutual TLS means both sides must present a certificate. No certificate, no connection."

---

## Slide 5 — What Happens to Every Request (~55s)

**[Layout]**
```
┌──────────────────────┬──────────────────────────┐
│  External Request    │  Pod-to-Pod (Internal)   │
│  (North-South)       │  (East-West)             │
│                      │                          │
│  Client              │  Pod A                   │
│    ↓                 │    ↓                     │
│  Istio               │  mTLS                    │
│  verify JWT sig      │  both present cert       │
│    ↓                 │    ↓                     │
│  OPA                 │  SPIFFE allowlist        │
│  role+path+device    │  frontend-sa only        │
│    ↓                 │    ↓                     │
│  App ✓               │  Backend App ✓           │
│                      │                          │
└──────────────────────┴──────────────────────────┘
│  "Bypassing one layer does NOT bypass the others." │
└────────────────────────────────────────────────────┘
2단 박스 + 하단 전체 폭 callout
```

**[Speaker notes]**
> "Here's the actual flow. Every external request hits two gates sequentially. Istio first checks whether the token was genuinely signed by our identity server — a forged token gets rejected right there. If valid, OPA checks role, path, and device health. Only requests that clear every check reach the app. For traffic between containers inside the cluster — which a firewall can't even see — mutual TLS handles it on a completely separate path. These two paths are independent. A valid token doesn't help you bypass the certificate check. The layers don't share a weakness."

---

## Slide 6 — Results: Each Layer Held Independently (~65s)

**[Layout]**
```
┌─────────────────────────────────────────────────┐
│                                                 │
│  #  │ Attack              │ Layer that blocked  │
│  ───┼─────────────────────┼───────────────────  │
│  A  │ Rogue pod, no cert  │ mTLS / SPIFFE       │
│     │                     │ (before OPA runs)   │
│  B  │ Forged JWT          │ Istio sig check     │
│     │                     │ (before OPA runs)   │
│  C  │ User → admin path   │ OPA only            │
│  D  │ Viewer JWT → admin  │ OPA only            │
│  E  │ Valid admin token,  │ OPA only            │
│     │ unhealthy device    │ (JWT was fine)      │
│                                                 │
│  ┌─────────────────────────────────────────┐   │
│  │ Each layer blocked what it was           │   │
│  │ designed to block — independently.       │   │
│  └─────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
5행 테이블 (layer 명시) + 하단 설계 포인트 callout
```

**[Speaker notes]**
> "The interesting result isn't that all tests passed — that's expected. What matters is which layer blocked each attack, and why. Scenarios A and B never even reached OPA. A rogue pod without a certificate is dropped at the mTLS layer. A forged JWT is rejected by Istio before the policy engine runs. Scenarios C, D, and E made it past identity checks — they had valid credentials — but OPA caught them on context: wrong path, wrong role, unhealthy device. Each layer did exactly its job, and nothing else. That independence is the whole point of Zero Trust: a valid token doesn't help you if your workload identity is wrong. Valid credentials don't help you if your device is compromised."

---

## Slide 7 — Conclusion (~30s)

**[Layout]**
```
┌──────────────────────┬──────────────────────────┐
│  Traditional tools   │  ZTA enforces            │
│  miss                │                          │
│  ────────────────    │  ──────────────────────  │
│  East-West traffic   │  Cryptographic workload  │
│                      │  identity                │
│  Per-request verify  │  Every request           │
│                      │  re-evaluated            │
│  Context-aware auth  │  Role+path+device        │
│                      │  per request             │
│  Lateral movement    │  Blocked at infra layer  │
└──────────────────────┴──────────────────────────┘
│  Stack: Istio + OPA + Keycloak  ·  +1.53ms avg  │
│                                                  │
│  "Zero Trust isn't a product you buy —           │
│   it's an architecture you enforce,              │
│   one request at a time."                        │
└──────────────────────────────────────────────────┘
2단 비교 박스 + 하단 전체 폭 마무리 callout
```

**[Speaker notes]**
> "To wrap up: Zero Trust doesn't replace your firewall — it fills the gap that firewalls and VPNs were never designed to handle. Per-request, cryptographically-bound, context-aware authorization at the workload level. The latency cost is only 1.53 milliseconds on average — negligible. This project shows it's achievable with open-source tools on a local cluster. Zero Trust isn't a product you buy — it's an architecture you enforce, one request at a time. Thank you."

---

## Timing Guide

| Slide | Topic | Duration | Cumulative |
|-------|-------|----------|-----------|
| 1 | Title | ~15s | 0:15 |
| 2 | How attacks work | ~30s | 0:45 |
| 3 | Gap in traditional tools | ~25s | 1:10 |
| 4 | ZTA solution | ~50s | 2:00 |
| 5 | Request flow | ~55s | 2:55 |
| 6 | Results | ~65s | 4:00 |
| 7 | Conclusion | ~30s | 4:30 |
