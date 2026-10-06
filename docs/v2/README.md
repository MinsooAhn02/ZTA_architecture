# ZTA v2 로컬 실험 운영

원본은 `../../zta-project`의 main / `49daa49`에 보존하고, 이 worktree의 `zta-v2-hardening` 브랜치에서 확장한다. 과거 18개 결과는 v2 결과에 합산하지 않는다. 현재 검증 상태는 [RESULTS.md](RESULTS.md)에 기록한다.

## 실행

Windows PowerShell에서 다음과 같이 실행한다. Ubuntu WSL, Docker Desktop, minikube와 원본 Istio 1.28.3 배포 도구를 사용하는 로컬 환경이다.

```powershell
$ztaV2 = 'C:\Users\Minsoo\minsoo_security\projects\zta-improvements\source\Launch-ZTA.ps1'
& $ztaV2 check
& $ztaV2 start
& $ztaV2 test
& $ztaV2 perf
& $ztaV2 verify
& $ztaV2 dashboard
```

`status`, `stop`, `restore-strict`, `jwt-refresh`도 같은 진입점으로 제공한다. `dashboard`는 서버 프로세스를 유지하므로 별도 터미널에서 실행한다. `test`는 S32를 제외한 33개, `perf`는 S32의 공식 30개 측정이다. CLI와 dashboard 실행은 같은 사용자 전용 파일 lock을 사용한다. 충돌한 CLI는 종료 코드 2, dashboard는 HTTP 409를 반환한다.

`check`는 Python/Bash 구문, OPA 컴파일과 Rego 회귀, Python 회귀, 다섯 모드 manifest 생성을 확인한다. 실제 배포된 Python 3.12 앱의 단위 검증도 실행별 evidence에 따로 남긴다. 테스트 실행 중 소스가 바뀌면 정상 latest를 갱신하지 않는다. `verify`는 현재 소스와 결과의 fingerprint가 일치해야 성공한다.

## 환경 격리와 복원

- 프로필/context/namespace: `zta-v2`.
- Kubernetes 1.34.0, Istio 1.28.3, containerd, Calico, 4 CPU / 8192MB.
- WSL 전용 상태: `~/.local/share/zta-v2`; 별도의 MINIKUBE_HOME과 KUBECONFIG를 사용한다.
- 포트: dashboard 5002, Keycloak 18081, Kiali 20010, Grafana 20012. 포워딩과 dashboard는 127.0.0.1에 바인딩한다.
- Keycloak 23.0.7의 실험 realm과 키는 로컬 PVC에 저장한다. 외부 DB는 사용하지 않는다.

v2 `start`가 원본 minikube를 먼저 정지한다. 원본으로 돌아갈 때는 다음 순서로 실행한다.

```powershell
& $ztaV2 stop
& 'C:\Users\Minsoo\minsoo_security\projects\zta-improvements\setup\Launch-ZTA.ps1' start
```

성능 실행은 종료·실패·취소 시 strict 복원과 정상/거부 canary를 수행한다. 복원 실패는 ERROR이며 latest를 덮어쓰지 않는다. 복구 명령은 `& $ztaV2 restore-strict`다. 원본과 v2 클러스터를 동시에 실행하지 않는다.

## 인증과 상태 주장

GET `/`, `/api/data`는 viewer/admin, GET `/api/admin`과 POST `/api/write`는 admin만 허용한다. 보호 자원은 사용자 JWT와 `X-ZTA-Posture`를 함께 요구한다. GET `/healthz`는 민감한 데이터를 포함하지 않는다. write는 64KiB 이하 JSON 객체를 받는 시뮬레이션이며 `write-accepted`, `committed: false`를 반환한다.

사용자 토큰은 audience `zta-frontend`와 `zta-backend`, TTL 300초다. 별도 client의 상태 토큰은 audience `zta-posture`, TTL/최대 age 120초이며 사용자 토큰과 sub가 같아야 한다. `posture-healthy` 역할은 realm 관리자가 부여한다. `role`, `X-Device-Firewall` 헤더는 권한 근거로 쓰지 않는다. 상태 토큰은 서명된 테스트 주장이다. 실제 장치 측정이나 attestation을 수행하지 않는다.

frontend와 backend 모두 JWT/OPA 검증을 적용하고, backend는 frontend-sa의 mTLS 신원을 추가 요구한다. Envoy는 DECODE_AND_MERGE_SLASHES를 사용하고 OPA는 query를 제외한 정확한 메서드·경로를 검사한다. 설치된 Envoy에서는 CUSTOM/OPA 필터가 JWT 필터보다 앞에 있어 잘못된 토큰이 OPA의 403으로 먼저 거부될 수 있다. 결과는 코드와 관측 원인을 함께 기록한다.

JWKS는 한 snapshot을 OPA와 Istio에 적용하고 실제 listener 8080의 필터/JWKS, OPA 데이터, proxy 설정 일치를 확인한다. 키 교체는 이전 키를 최소 360초 유지한 뒤 폐기한다. 폐기 테스트의 이전 토큰은 아직 exp가 남아 있음을 별도로 기록한다. 로그아웃 후 refresh 재발급 거부와 기존 access-token의 잔여 유효성을 구분한다. 즉시 회수는 제공하지 않는다.

## 결과와 해석

`evidence/v2/<run-id>/results.jsonl`이 정식 결과다. 각 행에 schema_version, run_id, case_id, level, request_id, status, expected, observed, evidence가 들어간다. manifest에 실행 환경, 소스 fingerprint, 앱 이미지, 실제 listener/버전 검사, 복원 상태를 기록한다. 진행 중 case 기록과 완료 결과는 구별된다. 실패·중단 결과도 보존한다.

종료 코드는 0=전체 assertion 성공, 1=assertion 실패, 2=실행/환경 오류다. 미실행은 PASS가 아니다. 일반 timeout/DNS/kubectl 오류와 원인 미확인 000은 ERROR다. mTLS 차단은 정상 대조 요청 전후 성공과 대상 Envoy의 source IP·연결 시각·filter_chain_not_found를 요구한다. TLS 전 거부에는 destination request ID가 없다는 한계를 기록한다. OPA 관리 API 차단은 실제 Calico DROP 카운터 증가, 대상 pod/규칙/시간 구간, 정상 OPA 대조 요청을 함께 요구한다.

S31의 mixed status/환경 실패/취소는 실행 제어 코드에 대한 단위 fault injection이다. S33은 실제 필수 workload 제거/복원 검증과 missing sidecar/NACK/timeout의 단위 fixture를 구별해 기록한다. S22의 실제 backend 중단 결과와 Python 3.12 단위 검증의 502·504 처리를 구분한다. S05의 다른 realm 토큰은 issuer와 키가 함께 달라지는 통합 조건이며, 같은 서명 키에서 issuer만 달라지는 조건은 Rego 단위 fixture로 검증한다.

성능은 같은 앱·경로·Fortio client·두 토큰 헤더·자원 조건에서 `sidecar → mTLS → JWT → OPA 역할 → OPA 역할+상태`의 비용을 비교한다. 동시성 1/4, 각 30초×3회, 조합별 10초 워밍업이다. 전체 제공 부하는 8 QPS로 고정하며 native 보고서의 RequestedQPS도 확인한다. 이 결과는 해당 부하에서의 지연 비교이며 최대 처리량 측정으로 해석하지 않는다. seed로 반복 순서를 섞고 latency 평균/p50/p95/p99, QPS, 오류율, 전체 histogram과 반복 간 변동을 보존한다. 과거 원본 수치와 직접 비교하지 않는다.

대시보드의 시작은 POST+Host/Origin/CSRF 검사, SSE는 조회 전용이다. 로그와 관측 결과는 textContent로 표시한다. 예상 topology, 실제 차단 이유, 전체 작업 시간, HTTP latency를 구분한다.

성능 cell의 `preflight_body_ok`는 직전에 같은 경로·토큰으로 보낸 정상 요청의 본문 assertion이다. Fortio 측정은 HTTP 상태·분포·지연·요청 수를 관측하며, 각 측정 응답의 본문은 검사하지 않는다. 따라서 `body_ok`는 null, `measured_response_body_asserted`는 false로 기록한다. 성공 결과의 latest 포인터는 canonical UUID, evidence 디렉터리 범위, manifest의 action/run ID, 각 결과 row의 run ID를 함께 검사한다.

측정 시작 명령은 `kubectl exec -i`로 Fortio pod의 native curl에 JSON을 stdin으로 전달하고 pod 내부 localhost REST API를 호출한다. native curl의 표준 HTTP client는 chunked 응답을 디코딩한다. 이 제어 경로는 실험 중 변경되는 mesh 정책을 지나지 않으며, 실제 측정 요청은 모든 단계에서 동일한 Fortio server의 client → frontend → backend 경로를 사용한다. native curl은 별도 HTTP 상태를 출력하지 않으므로 제어 응답의 `http_code`/`curl_exit`는 null로 남기고 실제 kubectl 종료 코드와 유효한 native 보고서를 검증한다. measured cell의 HTTP 상태는 Fortio RetCodes에서 얻는다. 제어 요청·대조 요청의 시간과 측정 응답 지연은 구별한다.

## 구현 위치

| 작업 | 구현 |
|---|---|
| W01 인증·역할 경계 | k8s/policy.rego, k8s/v2-resources.yaml |
| W02 결과·실패 판정 | scripts/suite.py, scripts/remote_request.sh, scripts/zta.py |
| W03 backend 위임 경계 | app/app.py, backend ALLOW/JWT/CUSTOM 정책 |
| W04 OPA 관리 경계·로그 | NetworkPolicy, k8s/mask.rego, DROP/로그 검증 |
| W05 JWT/JWKS·회수 | scripts/identity.py, scripts/runtime.py |
| W06 서명된 테스트 상태 | posture client, subject/freshness/역할 검증 |
| W07 dashboard | visualizer/server.py, visualizer/dashboard.html |
| W08 성능·복원 | scripts/performance.py, 공통 runner |
| W09 환경·이미지·자원 | scripts/runtime.py, Launch-ZTA.ps1, app/Dockerfile |
| W10 운영·근거 문서 | CONTRACT.md, README.md, RESULTS.md |
