# Minsoo's ZTA Project

This is my original Zero Trust Architecture (ZTA) project for CSE 487. I built it with my professor as a local Kubernetes research project.

## Project

The original project has 18 security test cases across five scenario groups. It already uses Keycloak JWTs, Istio mutual TLS (mTLS), and OPA policies. It covers identity, request permissions, device-posture simulation, and service-to-service traffic.

| Role | Component | Use |
|---|---|---|
| Identity provider | Keycloak | Issues user tokens |
| Policy decision point | OPA | Checks roles, paths, methods, and the posture demo header |
| Policy enforcement | Istio / Envoy | Verifies JWTs and enforces mTLS and service policies |
| Application | Flask frontend and backend | Provides test routes and sample responses |

The posture header and some scenario inputs are simulations. They do not measure a real device.

## Quick start

Run these commands in WSL Ubuntu with Docker Desktop running and the project tools installed:

```bash
make all
make test-all
```

`make all` starts the Minikube environment, deploys the services and policies, and opens the configured port-forwards. Run it before `make test-all`; the tests need the live services. `make test-all` runs the original 18-case suite.

Useful commands:

```bash
make status
make open-kiali
make open-grafana
make open-keycloak
make test-perf
```

The dashboards use localhost ports 20000 (Kiali), 20002 (Grafana), and 18080 (Keycloak). Check the Makefile before using a target; it is the source of truth for this branch.

## Reports and evidence

- [Final project report](final_report_v3.pdf)
- [Project background](docs/00-intro.md)
- [Original test output](evidence/test-results.txt)
- [Original performance results](evidence/perf-zta-latest.txt)
- [Original evidence folder](evidence/)
- [AI reflection](docs/AI_REFLECTION.md)

These files describe the original project and its 18-case baseline. They are separate from the later v2 results.

## v2 hardening (`zta-v2-hardening` branch)

I continued this project on the [`zta-v2-hardening`](https://github.com/MinsooAhn02/ZTA_architecture/tree/zta-v2-hardening) branch. I used AI to help review the design and implement upgrades, then checked the changes against the source, tests, and recorded evidence. The original project and its evidence stay on this branch.

The original project already used JWTs, mTLS, Keycloak, and OPA. v2 strengthens how those parts work together:

- stricter issuer, audience, signature, and token-time checks
- signed, user-bound posture tokens
- independent backend checks
- explicit route and role rules, and tighter OPA management access

The v2 test plan has 34 cases: 33 functional cases plus S32, a 30-cell performance matrix. These tests are for a local research system. Posture is a signed simulation, writes do not commit to a database, and the results are not production performance claims.

Run v2 from its branch (WSL Ubuntu, Docker Desktop, project tools installed):

```bash
git checkout zta-v2-hardening
make check      # offline checks
make all        # start the v2 environment
make test-all   # 33 functional cases
make perf       # optional; 30-cell performance matrix
make verify     # after test-all and perf both pass
make view       # local dashboard
```

Default v2 ports: 5002 (dashboard), 18081 (Keycloak), 20010 (Kiali), 20012 (Grafana).

The 33/33 functional and 30/30 performance results are historical and tied to the source fingerprint in the report. Later dashboard changes got a separate UI check; the full suite and performance matrix were not rerun afterward.

- [v2 results](https://github.com/MinsooAhn02/ZTA_architecture/blob/zta-v2-hardening/docs/v2/RESULTS.md)
- [UI follow-up checks](https://github.com/MinsooAhn02/ZTA_architecture/blob/zta-v2-hardening/docs/v2/UI_CHECK.md)
- [Implementation contract](https://github.com/MinsooAhn02/ZTA_architecture/blob/zta-v2-hardening/docs/v2/CONTRACT.md)
