# Presentation Script — ZTA Sandbox Implementation
**5-minute talk · English · UROP Showcase · Audience: peers + professors**

---

## Slide 1 — Title

**[Speaker notes]**
> "My name is Minsoo Ahn, a fourth-year student graduating next semester. My interest in security led me to Zero Trust Architecture — and under the guidance of Professor Mione, I built a working implementation of it. Every day, attackers get in through a single stolen password and then move freely inside. This project is about closing that gap, using Istio, OPA, and Keycloak on a Kubernetes cluster, evaluated against five attack scenarios across eighteen test cases."

---

## Slide 2 — The Problem: How Attacks Actually Work

**[Speaker notes]**
> "To motivate the problem, consider how a typical attack unfolds. An attacker obtains valid credentials through phishing. The perimeter firewall sees a valid login and grants access. Once inside the Kubernetes cluster — which is the system that runs containerized applications — no further verification occurs. Services inside the cluster trust each other by default, so the attacker can move from pod to pod, reach the database, and access the Admin API without triggering a single alert. This is called lateral movement — moving through a system after the initial breach — and it is the dominant pattern in real-world attacks."

---

## Slide 3 — The Gap in Traditional Tools

**[Speaker notes]**
> "You might think a better firewall solves this. It does not. This is not a problem unique to firewalls. VPNs encrypt the connection but give broad access once connected. Application proxies inspect request content but cannot verify which specific workload is making the request. All three tools share the same fundamental assumption: trust is established at the perimeter, and maintained inside. None of them re-verify on each individual request after access is granted. That is the gap this project is designed to close."

---

## Slide 4 — Solution: Zero Trust Architecture

**[Speaker notes]**
> "Zero Trust addresses this with one principle: no request is trusted by default — it must prove itself every time. The implementation maps to three NIST roles. Istio is the Policy Enforcement Point — it intercepts all traffic before application code runs. OPA is the Policy Decision Point — it evaluates role, endpoint, and device health on each request. Keycloak is the Identity Provider — it issues cryptographically signed JWT tokens that cannot be forged. For pod-to-pod traffic inside the cluster, mutual TLS through SPIFFE enforces that both sides present a valid certificate. No certificate, no connection."

---

## Slide 5 — What Happens to Every Request

**[Speaker notes]**
> "Looking at the request flow in detail. External requests — traffic coming from outside the cluster — pass through two independent verification gates. Istio first checks whether the JWT token was genuinely signed by Keycloak's private key. If the signature does not match, the request is rejected at this point, before OPA is even involved. If the token is valid, OPA then evaluates the full context: role, path, and device health. Only requests that clear both checks reach the application. Internal pod-to-pod traffic follows a completely separate path. Mutual TLS verifies certificates on both sides, and SPIFFE enforces that only workloads with explicitly permitted identities can connect. That independence is what we will see in the results."

---

## Slide 6 — Results: Each Layer Held Independently

**[Speaker notes]**
> "The two verification paths are fully independent — a valid token provides no advantage in bypassing the certificate check, and compromising one layer does not weaken the other. Moving to the evaluation results. Eighteen test cases were run across five attack scenarios. Scenarios A and B — a rogue pod presenting no workload certificate, and a request carrying a forged JWT — were both rejected before reaching OPA. This confirms that the enforcement layers operate independently: the mTLS and signature checks do not rely on OPA to catch these cases. Scenarios C, D, and E all carried valid credentials and passed identity checks — but were blocked by OPA on contextual grounds: wrong role, wrong path, or an unhealthy device. All eighteen test cases passed. Each layer blocked the specific attack class it was designed to handle, with no overlap or cross-dependency."

---

## Slide 6.5 — Live Evidence: Kiali Graph

**[Speaker notes]**
> "This is the Kiali workload graph — captured live from the cluster during the test run. It does not show all eighteen test cases; it shows one representative request per scenario. Kiali draws a line every time a request actually gets through. The green path with the padlock — that is frontend to backend, protected by mutual TLS. Now look at test-rogue at the bottom right. It tried to connect directly to the backend, bypassing the frontend entirely — that is the lateral movement attack. There is no line. It never got through. The mTLS and SPIFFE allowlist stopped it at the connection level. The absence of a line is the evidence."

---

## Slide 7 — Conclusion

**[Speaker notes]**
> "In summary, traditional perimeter tools leave three gaps that this implementation addresses. East-west traffic between pods is now governed by cryptographic workload identity through mutual TLS and SPIFFE. Per-request re-verification is enforced on every request through the Istio and OPA pipeline. Context-aware authorization — considering role, path, and device state together — is handled by OPA independently on each request. The average latency overhead of this system was measured at 1.53 milliseconds, which is negligible for production workloads. Zero Trust is not a product category — it is an enforcement model that operates at the request level, at the infrastructure layer, on every interaction. The most well-known example is Google's BeyondCorp. It is the origin of the Zero Trust model and its most successful implementation at scale. Google eliminated their corporate VPN entirely — and instead treated every network, whether internal or external, as untrusted. Every request, from every device, in every location, had to prove itself. That is exactly the model this project implements. Thank you."
