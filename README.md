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

| Scenario          | Threat                                      | Control                               | Verify                                     |
| ----------------- | ------------------------------------------- | ------------------------------------- | ------------------------------------------ |
| A: North-South    | Unauthenticated external access             | OPA role/JWT check                    | `make test-block`, `make test-pass`        |
| A: East-West      | Compromised pod lateral movement            | mTLS STRICT + SPIFFE allowlist        | `make test-lateral`                        |
| B: JWT Forgery    | Forged / tampered JWT token                 | Istio JWKS signature verify           | `make test-fake`, `make test-jwt-tampered` |
| C: Context Access | Over-privileged request (wrong method/path) | OPA role+method+path policy           | `make test-context`                        |
| D: JWT Claim      | Role escalation via JWT claim               | OPA `io.jwt.decode` + Keycloak claim  | `make test-jwt-role`                       |
| E: Device Posture | Valid credential from unhealthy device      | OPA `X-Device-Firewall` posture check | `make test-posture`                        |

Run all scenarios at once:

```bash
make test-all
```

## Scenario Selection Rationale (Report Note)

The five scenarios were chosen to be representative, repeatable, and realistic for
day-to-day attacker behavior in microservice environments. They cover both north-south
and east-west paths and map directly to NIST SP 800-207 tenets.

- A: Lateral movement is a common post-compromise behavior.
- B: Forged or tampered JWTs are realistic API abuses.
- C: Context misuse (method/path) shows why identity alone is insufficient.
- D: Signed claim-based authorization closes header spoofing gaps.
- E: Device posture highlights risk-based access decisions.

## Reflection Summary (Report Note)

- ZTA is a strong practical approach, but it is not perfect or exhaustive.
- The initial setup and integration were the hardest part; the core flow was manageable.
- Performance overhead was higher than expected, reinforcing the security vs. speed trade-off.
- AI-assisted work helped iteration but did not replace manual validation.
- Future work should target more efficient policy paths and stronger low-level isolation.

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
- visualizer/: Web-based security dashboard (`server.py`) — live test runner, animated ZTA pipeline graph, 2-column attack detail panel, real-time performance metrics table
- Makefile: setup, deployment, test, demo, monitoring, cleanup automation. `make view` auto-starts cluster if needed and wraps everything in WSL for Windows PowerShell compatibility.
- (Istio binary is auto-downloaded by Makefile during `make step1` if not already present)

## ZTA Security Dashboard (Visualizer)

A browser-based control panel that runs directly from WSL — no extra dependencies needed.

**Prerequisites:** Python 3 (standard library only — no pip installs required).

**How to run:**

```bash
# From the project root — works from PowerShell or WSL:
make view        # recommended (auto-starts cluster if not ready)
# or
make visualizer
# or (inside WSL directly):
python3 visualizer/server.py

# Then open in browser:
#   http://localhost:5001
```

> **`make view` is self-contained.** It checks whether the minikube cluster and
> `frontend` deployment are already running. If they are, it only restarts port-forwards.
> If not, it runs `make all` (full cluster setup) automatically before starting the server.
> No manual pre-flight required.

> **Windows note:** `make view` wraps the command in `wsl bash -c '...'`, so it can
> be called from PowerShell directly. The Python server and all `make` targets run
> inside WSL automatically.

**Stop:** `Ctrl+C` in the terminal.

**Layout:**

```
┌────────────────────────────────────────────────────────────────────────────────┐
│  ⬡ ZTA Security Dashboard  |  Minsoo Ahn · NIST SP 800-207 · Keycloak+Istio+OPA · 18 Scenarios  │  18 Total  0 Pass  │  Keycloak Grafana Kiali ↓Report  │
├────┬──────────────┬─────────────────────────────────────────┬──────────────────┤
│ ▲  │              │                                         │                  │
│All │  Scenario    │   ZTA Security Pipeline (node graph)    │  Request         │
│ A  │  Cards       │   North-South or East-West topology     │  Journey         │
│ B  │  (280 px)    │   Nodes animate green/red on test run   │  (step-by-step   │
│ C  │              │   No scroll — all nodes visible         │   flow list)     │
│ D  │  Click →     │                                         │                  │
│ E  │  selects &   ├─────────────────────────────────────────┴──────────────────┤
│    │  runs test   │  Attack Detail & Defense  (2-column, full width)           │
│    │              │  Left: ID · title · signals · verdict · block reason        │
│    │              │  Right: "Why It Is Blocked" insight paragraph (14px)        │
├────┴──────────────┴──────────────────────────────────────────────────────────┤
│  Terminal (3/8 width)    │  Run History & Performance (5/8 width)             │
│  Live make output        │  Table: # · Scenario · Cat · Pipeline ·            │
│  streamed via SSE        │  Expect HTTP · Actual HTTP · Match · Block Layer ·  │
│  from WSL                │  Verdict · Duration · Exit Code · Time             │
├──────────────────────────┴──────────────────────────────────────────────────┤
│  Bottom bar: test-all · jwt-refresh · opa-logs · cluster                     │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Panels:**

| Area | What it does |
|------|-------------|
| **Vertical category tabs** (far left, 52 px) | Filter cards by scenario group: All / A / B / C / D / E. Click to filter; active group highlighted with blue left-border. |
| **Scenario cards** (280 px) | 18 test cards. Each shows scenario ID, title, description, request signals (method / path / identity / role / posture), and a PASS / FAIL / running badge. Click a card to select it, animate the graph, and stream the make output live. |
| **ZTA Security Pipeline** (graph, flex 4) | Animated node topology — North-South path: Client → Istio JWT Auth → Istio DENY → OPA Policy → App; East-West path: Rogue Pod → mTLS STRICT → SPIFFE Allowlist → Backend. Nodes animate green (passed) or red+pulsing (blocked). No scrollbar — all nodes visible at once. |
| **Request Journey** (right of graph, flex 2) | Step-by-step list: each node in the flow gets a passed / BLOCKED HERE / skipped badge. The block point shows the exact policy rule that fired. |
| **Attack Detail & Defense** (bottom half of right panel, full width) | 2-column layout. **Left:** scenario ID + title, description, signal tags, BLOCKED / ALLOWED verdict, defense layer badge, pipeline label (NS/EW), block reason in monospace box, make target. **Right:** "Why It Is Blocked / Why It Is Allowed" — full insight paragraph at 14 px line-height 1.8. |
| **Terminal** (bottom-left, 3/8 width) | Live `make` output streamed via SSE from WSL. Color-coded: green for PASS lines, red for FAIL, yellow for EXPECT/RESULT, white for headers. Auto-scrolls. |
| **Run History & Performance** (bottom-right, 5/8 width) | Real-time table populated after each test run. Columns: **#, Scenario, Category, Pipeline, Expected HTTP, Actual HTTP, Match ✓/✗, Block Layer, Verdict, Duration, Exit Code, Time**. HTTP codes parsed live from EXPECT:/RESULT: SSE lines; pipeline and block layer sourced from scenario metadata. Sticky header, 13 px font. |
| **Bottom bar** | Quick-run buttons: `test-all`, `jwt-refresh`, `opa-logs`, `cluster` (kubectl pod/policy dump). |
| **Header** | Single inline banner: hex icon · title · pipe · meta info (author, NIST ref, tools, scenario count) · pass/total counters · service links (Keycloak, Grafana, Kiali, Report PDF download). |

Requires WSL — the Python server shells out to `make` for live command execution.

---

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
The viewer user (`vieweruser`) needed for Scenario D is created and role-assigned
automatically when `make test-all` runs — no manual step required.

To add or repair the viewer user outside of `test-all`:

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
make open-kiali    # Open Kiali in browser    (http://localhost:20000)
make open-grafana  # Open Grafana in browser  (http://localhost:20002)
make open-keycloak # Open Keycloak in browser (http://localhost:18080)
```

## Dashboard Usage Guide

### Kiali - Service Mesh Topology

Kiali visualizes your service mesh and helps you understand traffic flow.

**How to Open:**

```bash
make ports       # Ensure port-forward is running
make open-kiali  # Opens http://localhost:20000
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
make open-grafana # Opens http://localhost:20002
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
make open-keycloak # Opens http://localhost:18080
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

| Command              | URL                     | Purpose                      |
| -------------------- | ----------------------- | ---------------------------- |
| `make open-kiali`    | http://localhost:20000  | Service mesh visualization   |
| `make open-grafana`  | http://localhost:20002  | Metrics & performance graphs |
| `make open-keycloak` | http://localhost:18080  | Identity provider admin      |
| `make ports`         | -                       | Start all port-forwards      |
| `make ports-stop`    | -                       | Stop all port-forwards       |

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

| Tenet | Principle                                        | Implementation                                               |
| ----- | ------------------------------------------------ | ------------------------------------------------------------ |
| 1     | All data sources are resources                   | Backend, Keycloak, OPA each treated as protected resources   |
| 2     | All communication secured regardless of location | Istio mTLS STRICT (Scenario A)                               |
| 3     | Access granted per session                       | JWT per-request validation, stateless (Scenario B/D)         |
| 4     | Access determined by dynamic policy              | OPA role + method + path + posture context (Scenario C/D/E)  |
| 5     | Asset integrity monitored continuously           | Kiali topology, Grafana metrics, OPA decision logs           |
| 6     | All authentication and authorization dynamic     | No pre-approved sessions; every request re-evaluated         |
| 7     | Collect as much information as possible          | Prometheus/Grafana metrics, OPA `decision_logs.console=true` |
