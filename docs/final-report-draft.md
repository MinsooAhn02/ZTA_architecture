# Zero Trust Architecture Sandbox - Final Report Draft

Date: 2026-04-14
Author: Minsoo Ahn

## 1. Executive Summary

This project implements a practical Zero Trust Architecture (ZTA) sandbox using Istio, OPA, and Keycloak, aligned to NIST SP 800-207.

Core result:

- Requests are evaluated by layered controls (mTLS identity, JWT authenticity, OPA authorization, context policy).
- Lateral movement and token-forgery attack paths are blocked.
- Device posture simulation was added to close proposal gap for Scenario E.

## 2. Before -> Setup -> Learning

Before:

- Initial implementation had strong policy components but lacked explicit proposal traceability and formal threat modeling.

Setup:

- Threat model, attack tree, defense-layer mapping, and bypass analysis were documented.
- Scenario E (device posture) was integrated via posture-aware policy condition.
- Lateral movement test suite was extended with explicit pod-IP bypass attempt coverage.

Learning:

- Security value comes from multiple independent controls, not a single gate.
- Header-only context is useful for demonstration but weak as trust source.
- Production-grade posture verification requires trusted attestation/MDM source.

## 3. Architecture and NIST Mapping

Policy path:

1. Istio enforces traffic interception and authentication checks.
2. Keycloak provides signed identity tokens.
3. OPA evaluates request context and returns allow/deny.
4. Envoy enforces decision before app code executes.

NIST alignment:

- Tenet 1-7 mapping is documented in docs/threat-model.md and explanation.txt.

## 4. Scenario Outcomes (Security Validation)

| Scenario | Goal                        | Expected                                  | Status           |
| -------- | --------------------------- | ----------------------------------------- | ---------------- |
| A        | Block lateral movement      | rogue/wrong-SA/podIP denied               | Validated (PASS) |
| B        | Block fake/tampered JWT     | tampered or forged token denied (401/403) | Validated (PASS) |
| C        | Enforce context policy      | role+method+path matrix                   | Validated (PASS) |
| D        | Enforce JWT claim policy    | viewer denied on admin/write              | Validated (PASS) |
| E        | Enforce device posture gate | firewall=enabled allow, disabled deny     | Validated (PASS) |

## 5. Performance Interpretation

Measured local sandbox data indicates latency increase and throughput drop under full ZTA stack.

Interpretation:

- Absolute overhead is small in milliseconds but visible in localhost micro-benchmark.
- Main overhead contributors are mTLS handshake, ext-authz roundtrip, and sidecar processing.
- For production, use connection reuse, policy caching, and horizontal scaling to reduce impact.

WireGuard-first baseline context:

- Benchmark-based comparison indicates WireGuard typically adds lower transport overhead,
  while ZTA adds additional request-time checks.
- ZTA overhead is higher but includes controls that VPN alone does not provide:
  request-level authentication/authorization, workload identity enforcement,
  and stronger lateral movement reduction.
- Full comparison record is provided in evidence/vpn-zta-comparison.txt.

## 6. Known Limits and Honest Scope

In-scope defense claims:

- Unauthorized access from unauthenticated, low-privilege, forged-token, and lateral-movement paths.

Out-of-scope assumptions:

- Cluster-admin compromise
- Keycloak private key compromise
- Istio CA root compromise
- Supply-chain compromise

Known demo limitation:

- Device posture header can be forged by client in simulation mode.
- Production version must use trusted posture signal injection/attestation.

## 7. Evidence Index

Prepared evidence locations:

- evidence/test-results.txt
- evidence/opa-decision-logs.txt
- evidence/attack-logs/lateral-movement.txt
- evidence/attack-logs/jwt-forgery.txt
- evidence/attack-logs/device-posture.txt
- evidence/vpn-zta-comparison.txt
- evidence/screenshots/kiali-topology.png
- evidence/screenshots/grafana-latency.png
- evidence/screenshots/keycloak-users.png
- evidence/screenshots/keycloak-realm.png

Validation note:

- `make test-all` and `make demo` both completed with PASS in WSL-backed cluster session.

## 8. Conclusion

The sandbox demonstrates that ZTA can be implemented as enforceable, layered controls rather than conceptual guidance.

Main conclusion:

- Even if one credential or one path is compromised, request-level re-verification and context-aware policy significantly reduce lateral and privilege-escalation risk.

Next practical step:

- Finalize formatting and references for submission package, then prepare commit/tag for reproducible handoff.
