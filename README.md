# Minsoo ZTA Sandbox

Practical implementation of Zero Trust Architecture (ZTA) on Kubernetes, aligned with NIST SP 800-207.

This repository includes an automated Makefile workflow for:

- environment setup
- deployment of app + Keycloak + OPA + Istio
- security policy application
- attack-scenario verification
- observability and performance checks

## Author

- Name: Minsoo Ahn
- Student ID: 114743792

## Research Objectives

1. Build a ZTA environment with open-source components (Istio, OPA, Keycloak) on Kubernetes.
2. Validate five security scenarios covering north-south, east-west, JWT forgery, context-based access, and device posture.
3. Measure performance overhead introduced by ZTA controls and compare security model against VPN (WireGuard).

## System Architecture

| NIST Component                 | Tool Used               | Description                                                 |
| :----------------------------- | :---------------------- | :---------------------------------------------------------- |
| PDP (Policy Decision Point)    | OPA (Open Policy Agent) | Centralized policy decisions for fine-grained authorization |
| PEP (Policy Enforcement Point) | Istio (Envoy sidecar)   | Enforces mTLS and authorization at service boundaries       |
| IdP (Identity Provider)        | Keycloak                | Identity management and JWT token issuance                  |

## Security Scenarios

| Scenario | Threat | Control | Verify |
|---|---|---|---|
| A: North-South | Unauthenticated external access | OPA role/JWT check | `make test-block`, `make test-pass` |
| A: East-West | Compromised pod lateral movement | mTLS STRICT + SPIFFE allowlist | `make test-lateral` |
| B: JWT Forgery | Forged / tampered JWT token | Istio JWKS signature verify | `make test-fake`, `make test-jwt-tampered` |
| C: Context Access | Over-privileged request (wrong method/path) | OPA role+method+path policy | `make test-context` |
| D: JWT Claim | Role escalation via JWT claim | OPA `io.jwt.decode` + Keycloak claim | `make test-jwt-role` |
| E: Device Posture | Valid credential from unhealthy device | OPA `X-Device-Firewall` posture check | `make test-posture` |

Run all scenarios at once:

```bash
make test-all
```

## Project Structure

- app/: Flask frontend/backend source
- k8s/: Kubernetes manifests and security policies (OPA Rego, Istio AuthzPolicy, JWT, mTLS)
- scripts/: Attack simulation scripts (lateral movement, JWT forgery, device posture)
- evidence/: Test results, OPA decision logs, performance comparison data
- docs/: Project documentation (read in order)
  - `00-intro.md`: Why ZTA — attack scenario, comparison with traditional security, key terms
  - `01-what-it-can-do.md`: Features, scenarios, test commands, dashboards
  - `02-threat-model.md`: Assets, adversaries, attack tree, bypass analysis
  - `03-how-it-works.md`: Architecture, request flow, defense layers, NIST mapping
  - `04-added.md`: What was added beyond the original proposal
  - `05-checklist.md`: Implementation and scenario verification status
  - `06-final-report-draft.md`: Final report for submission
- istio-1.28.3/: Istio binary/manifests (auto-downloaded by Makefile if missing)
- Makefile: setup, deployment, test, demo, monitoring, cleanup automation

## Environment Setup (Windows 11 + WSL2)

Important: run all commands below inside WSL Ubuntu terminal, not PowerShell.

### 1. Required Software

On Windows host:

- WSL2 with Ubuntu
- Docker Desktop
  - Enable WSL integration for Ubuntu distro in Docker Desktop settings

Inside WSL Ubuntu:

- make (usually via build-essential)
- kubectl
- minikube
- docker CLI
- curl
- python3 + pip

### 2. Install Core Packages in WSL

```bash
sudo apt update
sudo apt install -y build-essential curl python3 python3-pip ca-certificates gnupg
```

This installs make via build-essential.

### 3. Install kubectl (if missing)

```bash
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
rm kubectl
```

### 4. Install Minikube (if missing)

```bash
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube
rm minikube-linux-amd64
```

### 5. Verify Tooling

```bash
make --version
docker --version
kubectl version --client
minikube version
python3 --version
```

If make is not found:

```bash
sudo apt update
sudo apt install -y build-essential
```

## Quick Start

### 1. Clone and Enter Repository

```bash
git clone https://github.com/MinsooAhn-SBU/ZTA_architecture.git
cd ZTA_architecture
```

### 2. Start Docker Desktop (Windows)

Ensure Docker Desktop is running before starting minikube.

### 3. One-Command Full Setup

```bash
make setup
```

What make setup does:

1. Starts minikube
2. Installs Istio (if needed)
3. Installs Istio addons (Kiali/Prometheus/Grafana)
4. Builds app image in minikube docker environment
5. Deploys app + Keycloak + OPA
6. Applies authorization and micro-segmentation policies

Keycloak realm and users are configured automatically during `make setup`.
To add the viewer user needed for Scenario D (if not already done):

```bash
make setup-keycloak-viewer
```

### 4. Run Security Tests

```bash
make test-all
```

### 5. Open Dashboards

```bash
make ports        # Start all port-forwards first
make open-kiali   # Open Kiali in browser
make open-grafana # Open Grafana in browser
make open-keycloak # Open Keycloak in browser
```

## Dashboard Usage Guide

### Kiali - Service Mesh Topology

Kiali visualizes your service mesh and helps you understand traffic flow.

**How to Open:**

```bash
make ports       # Ensure port-forward is running
make open-kiali  # Opens http://localhost:20001
```

**What to Look For:**

1. **Graph View** (left menu → Graph)
   - Shows real-time traffic between services
   - Green edges = healthy traffic
   - Red edges = errors (403, 500, etc.)
   - Click on a service to see details

2. **Workloads** (left menu → Workloads)
   - Check if all pods have Istio sidecar (should show "Envoy" badge)
   - View logs and metrics per workload

3. **Istio Config** (left menu → Istio Config)
   - See applied security policies (AuthorizationPolicy, PeerAuthentication)
   - Green checkmark = valid config
   - Red X = configuration error

**Screenshot Tips for Report:**

- Capture the Graph view showing frontend → backend traffic flow
- Show the mTLS lock icon on connections (indicates encrypted traffic)

---

### Grafana - Metrics & Performance

Grafana displays detailed metrics and performance data.

**How to Open:**

```bash
make ports        # Ensure port-forward is running
make open-grafana # Opens http://localhost:3000
```

**Useful Dashboards:**

1. **Istio Service Dashboard**
   - Path: Home → Dashboards → Istio → Istio Service Dashboard
   - Shows: Request rate, error rate, latency (p50, p90, p99)
   - Use: Compare latency before/after ZTA policies

2. **Istio Mesh Dashboard**
   - Path: Home → Dashboards → Istio → Istio Mesh Dashboard
   - Shows: Overall mesh health, global request volume
   - Use: Verify mTLS coverage percentage

3. **Istio Workload Dashboard**
   - Path: Home → Dashboards → Istio → Istio Workload Dashboard
   - Shows: Per-workload metrics (frontend, backend, opa)
   - Use: Identify which service has highest latency

**Screenshot Tips for Report:**

- Capture latency graphs showing p50, p90, p99 values
- Show the request success rate (should be near 100% for valid requests)

---

### Keycloak - Identity Provider Admin

Keycloak manages users, roles, and JWT token issuance.

**How to Open:**

```bash
make ports         # Ensure port-forward is running
make open-keycloak # Opens http://localhost:8080
```

**Login Credentials:**

- Username: `admin`
- Password: `admin`

**Key Areas:**

1. **Realm Settings** (left menu → Realm Settings under "myrealm")
   - Shows realm configuration
   - Tokens tab: JWT token lifetimes

2. **Users** (left menu → Users)
   - View/manage users (testuser exists by default)
   - Click user → Role Mappings to see assigned roles

3. **Clients** (left menu → Clients)
   - "zta-client" is the OAuth2 client for this project
   - Credentials tab shows client secret

4. **Realm Roles** (left menu → Realm Roles)
   - "admin" role is used for authorization
   - OPA checks for this role in JWT claims

**Screenshot Tips for Report:**

- Capture the Users list showing testuser
- Show the Realm Roles with "admin" role
- Show Clients page with zta-client configured

---

### Quick Dashboard Commands Summary

| Command              | URL                    | Purpose                      |
| -------------------- | ---------------------- | ---------------------------- |
| `make open-kiali`    | http://localhost:20001 | Service mesh visualization   |
| `make open-grafana`  | http://localhost:3000  | Metrics & performance graphs |
| `make open-keycloak` | http://localhost:8080  | Identity provider admin      |
| `make ports`         | -                      | Start all port-forwards      |
| `make ports-stop`    | -                      | Stop all port-forwards       |

## Key Make Targets

- make help: show all commands
- make setup: full environment setup
- make step1 / make step2 / make step3 / make step4: phased setup
- make test-all: full security verification
- make status: cluster/service status
- make clean: remove app/policy resources
- make clean-all: full cleanup including Istio and minikube

## Troubleshooting

### make: command not found

```bash
sudo apt update
sudo apt install -y build-essential
```

### Cannot connect to Docker daemon in WSL

1. Start Docker Desktop on Windows.
2. Enable WSL integration for Ubuntu distro.
3. Reopen WSL terminal and retry docker --version.

### minikube start fails

- Check Docker Desktop is running.
- Ensure enough resources are available (recommended 4 CPU, 8 GB RAM).
- Retry:

```bash
minikube delete
minikube start --cpus 4 --memory 8192
```

### kubectl or minikube not found

Re-run the install steps in this README and verify with version commands.

## NIST 800-207 Compliance Mapping

| Tenet | Principle | Implementation |
|---|---|---|
| 1 | All data sources are resources | Backend, Keycloak, OPA each treated as protected resources |
| 2 | All communication secured regardless of location | Istio mTLS STRICT (Scenario A) |
| 3 | Access granted per session | JWT per-request validation, stateless (Scenario B/D) |
| 4 | Access determined by dynamic policy | OPA role + method + path + posture context (Scenario C/D/E) |
| 5 | Asset integrity monitored continuously | Kiali topology, Grafana metrics, OPA decision logs |
| 6 | All authentication and authorization dynamic | No pre-approved sessions; every request re-evaluated |
| 7 | Collect as much information as possible | Prometheus/Grafana metrics, OPA `decision_logs.console=true` |
