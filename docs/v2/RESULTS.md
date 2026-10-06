# ZTA v2 최종 검증 결과

상태: **완료 — 34개 coverage, 공식 성능 30회, strict 복원 및 verify 통과**.

이 전체 검증은 아래에 기록한 소스 fingerprint 기준의 결과다. 이후 2026-10-07에 Kiali 임베드·시나리오 선택/실행 분리 등 UI만 개편했으며, 이 UI 변경에 대해 전체34개와 성능30회를 다시 실행했다고 주장하지 않는다. [UI 후속 검증](UI_CHECK.md)에 범위와 증거를 따로 기록한다. 같은 요청으로 원본 README에 승인한 회고 글을 추가했으므로, 현재 원본의 README 문서 변경은 의도된 변경이다.

최종 live 확인: 2026-10-07. Docker 재시작 후 기존 v2 클러스터를 재개하고 readiness·동일 소스 fingerprint·strict 정상/거부 canary·원본 clean 상태를 다시 확인했다.

- 기능 실행: `9ced27f9-3fee-4f33-8d23-6dcc78612eca` — 33/33 PASS (integration 32, unit 1).
- 성능 실행: `5ee24e5b-7436-443b-b1a2-be44f6a68cd1` — S32 및 30/30 측정 PASS (experiment).
- 원본 main/49daa49 및 과거 evidence 보존, 원본 minikube 정지 상태 확인.
- 소스 fingerprint: `b88a790e84290ac320f3c2ee8ecbc6dba313c2febdaafc1b90cf29f6fa4882c4`. 두 실행 모두 변경 없이 종료.
- 앱: Python 3.12.15, Flask 3.1.3, requests 2.32.5.
- 별도 zta-v2 profile/context/namespace, Kubernetes1.34.0 / Istio1.28.3 / containerd / Calico / 4CPU8192MB.
- Python 회귀21, Rego 회귀6, 다섯 모드 manifest 검사 및 배포된 Python3.12 앱 회귀4 통과.
- 실제 listener8080의 JWT/OPA/RBAC, 정규화, 공유 JWKS와 native build image ID 확인.
- 정상/거부 canary와 strict 복원 성공. 실행 evidence에서 JWT 패턴이 발견되지 않음.

## 성능 결과

동일 앱·경로·Fortio client·두 토큰 헤더·자원 조건에서 각30초×3회, 동시성1/4로 측정했다. 조합별10초 워밍업과 seed 기반 순서 섞기를 사용했다. 전체 제공 부하는 8 QPS이며 최대 처리량을 측정한 결과는 아니다. 본문 assertion은 측정 직전 canary에서 수행하며, 각 Fortio 측정 응답의 본문을 검사했다고 주장하지 않는다. 모든 측정의 응답 오류율은0이다. 평균은 세 반복의 평균, 변동은 반복 간 표본 표준편차다. p95는 세 반복 p95의 평균이다. 원본의 과거 수치와 직접 비교하지 않는다.

| 단계 | 동시성 | 평균 latency ms | 반복 표준편차 ms | 평균 p95 ms | 평균 QPS |
|---|---:|---:|---:|---:|---:|
| sidecar | 1 | 5.496 | 0.112 | 7.297 | 8.00 |
| sidecar | 4 | 8.039 | 0.133 | 10.348 | 8.00 |
| mTLS | 1 | 5.719 | 0.117 | 7.950 | 8.00 |
| mTLS | 4 | 8.292 | 0.035 | 10.759 | 8.00 |
| JWT | 1 | 5.784 | 0.065 | 7.781 | 8.00 |
| JWT | 4 | 8.566 | 0.088 | 10.948 | 8.00 |
| OPA 역할 | 1 | 8.237 | 0.109 | 10.286 | 8.00 |
| OPA 역할 | 4 | 13.809 | 0.542 | 17.289 | 8.00 |
| OPA 역할 + 상태 | 1 | 8.832 | 0.034 | 10.952 | 8.00 |
| OPA 역할 + 상태 | 4 | 14.843 | 1.709 | 18.982 | 8.00 |

각 측정의 p50/p95/p99, QPS, 응답 코드 분포와 전체 latency histogram은 성능 실행의 `perf/` JSON에 보존했다. 위 결과는 이 로컬 실험 조건의 비용이며 production 성능으로 일반화하지 않는다.

## Coverage

| Case | 조건 | Level | 결과 |
|---|---|---|---|
| S01 | 무토큰 + role:admin | integration | PASS |
| S02 | viewer JWT + role:admin | integration | PASS |
| S03 | 정상 viewer 읽기 / admin 읽기·쓰기 | integration | PASS |
| S04 | 유효 토큰의 role 하나만 변조 | integration | PASS |
| S05 | 정상 서명 구조 + 다른 issuer | integration | PASS |
| S06 | 같은 issuer + 다른 audience | integration | PASS |
| S07 | 만료 JWT / 미래 nbf | integration | PASS |
| S08 | unsigned·형식 오류·잘못된 Authorization | integration | PASS |
| S09 | Keycloak 서명 키 교체 | integration | PASS |
| S10 | 로그아웃 후 access-token 재사용 | integration | PASS |
| S11 | sidecar 없는 rogue pod | integration | PASS |
| S12 | sidecar는 있지만 허용되지 않은 SA | integration | PASS |
| S13 | backend Service 및 pod-IP 직접 접근 | integration | PASS |
| S14 | 침해된 frontend-sa의 backend admin/write 직접 호출 | integration | PASS |
| S15 | frontend-sa가 viewer token을 backend로 전달 | integration | PASS |
| S16 | 비인가 pod의 OPA 관리 API 접근 | integration | PASS |
| S17 | OPA 중단·timeout | integration | PASS |
| S18 | policy 변경 직후 요청 | integration | PASS |
| S19 | 불량 posture + admin / viewer | integration | PASS |
| S20 | posture 누락·enabled 헤더 위조 | integration | PASS |
| S21 | 만료 또는 다른 주체의 signed posture | integration | PASS |
| S22 | backend 403/503·응답 지연·중단 | integration | PASS |
| S23 | frontend/OPA 재시작 후 재검증 | integration | PASS |
| S24 | Keycloak 일시 중단 | integration | PASS |
| S25 | 경로·method 경계 | integration | PASS |
| S26 | 중복 Authorization/role/posture 헤더 | integration | PASS |
| S27 | 다른 출처에서 dashboard 명령 실행 | integration | PASS |
| S28 | HTML이 들어 있는 공격 요청 로그 | integration | PASS |
| S29 | 두 dashboard/test 작업 동시 실행 | integration | PASS |
| S30 | raw decision log·실패 diagnostics 수집 | integration | PASS |
| S31 | 성능 실행 실패·mixed status·실행 취소 | unit | PASS |
| S32 | 단계별 보안 제어 및 동시성 비교 | experiment | PASS |
| S33 | mesh sync timeout·필요 proxy 누락 | integration | PASS |
| S34 | 앱 소스 변경 후 재배포 | integration | PASS |

## 관측과 한계

- S09: 키 유지 370.75초, 폐기 시 이전 토큰 exp 잔여 491.86초. 이전 키 폐기 거부와 새 키 정상 발급/요청을 구분했다.
- S09는 키 폐기와 자연 만료를 구분하려고900초 access fixture를 발급하고 client 설정을 곧바로300초로 복원했다. S21은 age와 exp를 구분하려고300초 posture fixture를 발급하고120초 설정을 기다리기 전에 복원했다.
- 상태 토큰은 관리자 역할로 표현한 서명된 테스트 주장이다. 실제 장치 측정/attestation이 아니다. write는 JSON 객체를 받는 시뮬레이션이며 DB commit을 수행하지 않는다.
- 로그아웃 후 refresh 재발급 거부와 만료 전 access-token의 잔여 유효성을 별도로 확인했다. 즉시 회수를 보장하지 않는다.
- S31은 mixed status/환경 오류/취소에 대한 실제 CLI lifecycle의 단위 fault injection이다. S33은 live 필수 workload 제거/복원과 unit NACK/missing-sidecar/timeout fixture를 구분한다.
- S22의 backend 중단503 전달은 live 실험이다. 연결 오류502/timeout504와 응답 타입 보존은 배포된 Python3.12 앱 단위 검증이다.
- S05의 다른 realm은 issuer와 키가 함께 달라지는 통합 조건이다. issuer만 다른 같은 키 조건 및 상태 토큰 issuer/audience/signature는 Rego fixture로 분리했다.
- mTLS pre-HTTP 거부에는 destination request ID가 없다. 정상 대조 요청 전후 성공과 source IP/port·시각·filter_chain_not_found로 연결했다. OPA 관리 API 차단은 대상 Calico DROP 카운터와 시간 구간, 정상 대조 요청으로 입증했다.
- Envoy의 CUSTOM/OPA가 JWT 필터보다 앞에 있어 불량 토큰이403으로 먼저 거부될 수 있다. 코드만으로 차단 원인을 단정하지 않았다.
- 실패/중단한 초기 실행은 진단 기록으로 남기고 최종 PASS에 합산하지 않았다.

## 증거 경로

- [기능 JSONL](../../evidence/v2/9ced27f9-3fee-4f33-8d23-6dcc78612eca/results.jsonl), [기능 manifest](../../evidence/v2/9ced27f9-3fee-4f33-8d23-6dcc78612eca/manifest.json)
- [성능 JSONL](../../evidence/v2/5ee24e5b-7436-443b-b1a2-be44f6a68cd1/results.jsonl), [성능 manifest](../../evidence/v2/5ee24e5b-7436-443b-b1a2-be44f6a68cd1/manifest.json)
- [최종 verify 증거](../../evidence/v2/ca946f36-9c7e-4868-b83b-94b54b57986a/verification.json), [verify 실행 출력](../../evidence/v2/ca946f36-9c7e-4868-b83b-94b54b57986a/verify-cli.txt)
- [운영 문서](README.md), [공통 계약](CONTRACT.md). 복구: `Launch-ZTA.ps1 restore-strict`.
