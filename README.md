# Minsoo ZTA Sandbox

A practical implementation of **Zero Trust Architecture (ZTA)** on Kubernetes, aligned with **NIST SP 800-207** standards. This project demonstrates how to build a secure environment using industry-standard open-source tools to mitigate modern cyber threats.

---

## 👤 Author
- **Name:** Minsoo Ahn
- **Student ID:** 114743792

---

## 🎯 Research Objectives
The primary goal of this sandbox is to:
1.  **Build a ZTA Environment:** Integrate open-source security tools (Istio, OPA, Keycloak) within a Kubernetes cluster.
2.  **Validate Security Scenarios:** Solve virtual attack scenarios (Unauthorized Access, Lateral Movement) using Zero Trust principles.
3.  **Performance Analysis:** Measure the security overhead of ZTA policies compared to a traditional perimeter-based approach.

---

## 🏗 System Architecture
This project maps core ZTA components as defined by NIST 800-207:

| NIST Component | Tool Used | Description |
| :--- | :--- | :--- |
| **PDP** (Policy Decision Point) | **OPA** (Open Policy Agent) | Centralized policy engine for granular access control. |
| **PEP** (Policy Enforcement Point) | **Istio** (Envoy Proxy) | Sidecar proxies that enforce mTLS and authorization. |
| **IdP** (Identity Provider) | **Keycloak** | Identity management and JWT token issuance. |

---

## 🛡 Security Scenarios & Solutions

### Scenario 1: North-South Access Control (External to Internal)
- **Threat:** Unauthorized external users attempting to access internal services.
- **Solution:** Integrated **Keycloak JWT** with **OPA**. Only requests with valid tokens and `role: admin` are permitted.
- **Verification:** `make test-block` (Unauthorized) vs. `make test-pass` (Authorized).

### Scenario 2: East-West Lateral Movement Prevention (Internal to Internal)
- **Threat:** A compromised pod (Rogue Pod) attempting to attack other services within the cluster.
- **Solution:** Enforced **mTLS STRICT mode** via Istio PeerAuthentication and **Micro-segmentation** using ServiceAccount-based policies.
- **Verification:** `make test-lateral` ensures that even internal pods cannot talk to each other without explicit permission.

---

## 📁 Project Structure
- `app/`: Source code for Frontend and Backend (Flask).
- `k8s/`: Kubernetes manifests for Deployment, Service, and Security Policies.
- `istio-1.28.3/`: Istio binaries and configuration.
- `evidence/`: **(Presentation Materials)**
  - `dashboards/`: Kiali and Grafana screenshots.
  - `scenarios/`: Logs and CLI outputs of attack/defense results.
- `Makefile`: Full automation for setup, testing, and monitoring.
- `checklist.txt`: Comprehensive project progress tracker.

---

## 🚀 Quick Start

### 1. Prerequisites
- Windows with WSL2 (Ubuntu)
- Docker Desktop
- Minikube installed in WSL

### 2. Full Setup
The `Makefile` is designed to be self-contained. If the Istio directory is missing, it will automatically download and configure it for you.
```bash
# Clone the repository
git clone https://github.com/MinsooAhn-SBU/ZTA_architecture.git
cd ZTA_architecture

# One command to set up the entire environment (Phase 1 to 6)
make setup
```

### 3. Run Security Tests
Verify both North-South and East-West security:
```bash
make test-all
```

### 4. Launch Dashboards
- **Kiali (Topology):** `make dashboard`
- **Grafana (Metrics):** `make grafana`

---

## 📊 NIST 800-207 Compliance Mapping

| Principle | Implementation in this Sandbox |
| :--- | :--- |
| **All communication is secured** | mTLS STRICT mode (Istio) |
| **Access is granted on a per-session basis** | JWT Token expiration and verification (Keycloak) |
| **Access is determined by dynamic policy** | Rego-based OPA policies |
| **Monitor and measure state of assets** | Kiali observability & Grafana metrics |

---
