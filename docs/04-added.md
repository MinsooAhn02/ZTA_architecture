# Technical Evolution Report (Added Items Only)

Project: Zero Trust Sandbox (Keycloak + Istio + OPA)
Baseline Proposal: Project_Proposal_ZTA_Implementation.pdf (August 2025)

## Added Items Since the August 2025 Proposal

### 1) Scenario expansion from A/B to A-E

How:

- The two abstract proposal scenarios were split into five independently testable scenarios (A-E).
- Dedicated scenario suites were added in Makefile: test-lateral, test-fake/test-jwt-tampered, test-context, test-jwt-role, test-posture.

### 2) Scenario D (JWT claim-based authorization) was added

How:

- Istio authenticates token authenticity through RequestAuthentication (issuer + JWKS).
- JWT-required deny path blocks requests without valid principals.
- OPA uses jwt_has_role and method/path rules to enforce admin vs viewer authorization.

### 3) Scenario E (posture gate) was implemented to close proposal gap

How:

- OPA added device_posture_ok condition to decision logic.
- test-posture-ok (200) and test-posture-block (403) validate healthy vs risky posture behavior.

### 4) Formal threat model and attack tree were added

How:

- docs/threat-model.md now defines assets, attacker personas (T1-T4), and attack tree branches.
- Each attack path is mapped to blocking layers: mTLS, ServiceAccount/SPIFFE policy, JWT checks, and Rego authorization.

### 5) Authentication and authorization responsibilities were explicitly separated

How:

- Istio handles authentication (is the JWT valid?).
- OPA handles authorization (is this identity allowed for this method/path/context?).
- Validation semantics are separated in tests (e.g., tampered JWT 401 vs policy deny 403).

### 6) Bypass-focused attack tests were added

How:

- test-lateral-podip was added for direct podIP bypass attempt coverage.
- test-jwt-tampered and test-fake were added for cryptographic attack-path validation.

### 7) Verification harness depth was increased

How:

- 28 test/performance targets are now defined in Makefile.
- test-all aggregates results into EXPECT/RESULT/STATUS records for reproducible evidence.

### 8) Quantitative performance analysis was completed

How:

- Fortio benchmarks were executed through test-perf-baseline and test-perf-zta.
- Measured deltas were documented: average latency +1.53 ms (5.33 -> 6.86, +28.6%), throughput -22.3% QPS (187.5 -> 145.7), p99 +2.0 ms (8.5 -> 10.5). Baseline = sidecar present, no AuthorizationPolicy/PeerAuthentication.

### 9) WireGuard baseline comparison was added

How:

- A capability and overhead comparison was documented in evidence/vpn-zta-comparison.txt.
- The analysis frames trade-off as tunnel security (VPN) vs per-request enforcement (ZTA), not one-to-one replacement.

## One-line Summary

The final implementation added scenario depth, stronger trust semantics (JWT claim + posture), formal threat modeling, bypass-aware validation, and measurable security-performance trade-off evidence beyond the original proposal scope.
