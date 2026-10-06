# ZTA v2 Hardening

This separate branch continues my original CSE 487 ZTA project. I used AI to help review the design and implement upgrades, then checked changes against the source, tests, and recorded evidence. The original project and its evidence remain in the main branch.

**Branch:** [`zta-v2-hardening`](https://github.com/MinsooAhn02/ZTA_architecture/tree/zta-v2-hardening)

## What changed

The original project already used JWTs, mTLS, Keycloak, and OPA. This branch strengthens how those parts work together. It adds stricter issuer, audience, signature, and token-time checks; signed user-bound posture tokens; independent backend checks; explicit route and role rules; and tighter OPA management access.

The v2 test plan defines 34 cases: 33 functional cases and S32, a 30-cell performance matrix. These tests are for a local research system. Posture is a signed simulation, writes do not commit to a database, and the results are not production performance claims.

## Quick start

Run from this branch in WSL Ubuntu with Docker Desktop and the project tools available:

```bash
make check
make all
make test-all
make perf       # optional; runs the full 30-cell matrix
make verify     # after test-all and perf both pass
```

`make check` runs offline checks. `make all` starts the v2 environment. `make test-all` runs the 33 functional cases. `make perf` runs the 30 performance cells. `make verify` checks the saved runs and current source fingerprint; it requires successful test and performance runs.

Use `make view` to open the local dashboard. The default ports are 5002 for the dashboard, 18081 for Keycloak, 20010 for Kiali, and 20012 for Grafana.

## Results and limits

- [Full validation report](docs/v2/RESULTS.md)
- [UI follow-up checks](docs/v2/UI_CHECK.md)
- [Implementation contract](docs/v2/CONTRACT.md)
- [Functional JSONL evidence](evidence/v2/9ced27f9-3fee-4f33-8d23-6dcc78612eca/results.jsonl)
- [Performance JSONL evidence](evidence/v2/5ee24e5b-7436-443b-b1a2-be44f6a68cd1/results.jsonl)
- [AI reflection](docs/AI_REFLECTION.md)

The 33/33 functional and 30/30 performance results are historical and tied to the source fingerprint in the report. Later dashboard changes received a separate UI check; the full 34-case suite and performance matrix were not rerun after those UI changes. Read the report for evidence and limits.

## Original project

The original 18-case project is kept separately on the main branch. This branch does not replace its code or history. Compare the original and v2 work through the [main project](https://github.com/MinsooAhn02/ZTA_architecture) and the [v2 branch](https://github.com/MinsooAhn02/ZTA_architecture/tree/zta-v2-hardening).
