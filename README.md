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

## Later v2 work

I continued this project on a separate [`zta-v2-hardening` branch](https://github.com/MinsooAhn02/ZTA_architecture/tree/zta-v2-hardening). I used AI to help review the design and implement upgrades, then checked the work against tests and recorded evidence. The later branch expands the test plan to 34 cases and makes token, posture, backend, and management-plane checks stricter.

The v2 report distinguishes its historical full-run evidence from later UI-only checks. See the [v2 results](https://github.com/MinsooAhn02/ZTA_architecture/blob/zta-v2-hardening/docs/v2/RESULTS.md), or open the branch link above.
