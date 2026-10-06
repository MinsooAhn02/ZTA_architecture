# ZTA 개선·확장 계획

작성일: 2026-10-06
상태: 검토용 계획 / 구현 전
원본: `C:/Users/Minsoo/minsoo_security/projects/zta-project`
기준 커밋: `49daa49e49dc1a7a626ff998cf2038983fd63eef` (`main`, 로컬 확인)

> 최신 사용자 요청 원문
>
> 다 개선 하면 좀 좋을거 같은데 이제 원래 있던거 + 로 하는거라서 새로운 tree든 해서 살짝 구별되게 하는게 좋을거 같아 그렇게 해서 다 개선 및 추가하면 좋을만한 시나리오나 보완이 있으면 좋겠어서 일단 뭐뭐 하면 좋을지 md나 뭐 파일 만들어서 나에게 보여주며 적어볼까

## 1. 이번 개선의 목표

기존 프로젝트의 Istio·OPA·Keycloak 구성과 A–E 시나리오를 바탕으로 다음을 만든다.

1. JWT 권한을 데모 헤더로 우회할 수 없는 기본 정책.
2. 접근 거부, 연결 장애, 백엔드 처리 실패를 구분하는 검증.
3. 정책 엔진·로그·대시보드까지 포함한 보안 경계.
4. 토큰 수명과 키 교체, 정책 장애, 신뢰 가능한 장치 상태를 다루는 추가 시나리오.
5. 같은 조건에서 반복할 수 있고, 제어별 비용을 설명하는 성능 실험.
6. 원본과 개선본의 차이를 코드·테스트·실험 결과로 설명하는 문서.

현재 계획은 로컬 소스와 저장된 결과 분석을 바탕으로 한다. 실제 클러스터에서 우회 재현이나 18개 테스트 재실행은 아직 하지 않았다. 저장된 PASS와 새 구현의 검증 결과는 별도로 다룬다.

## 2. 원본과 개선본을 구분하는 구조

### 지금 만들어진 파일

```text
projects/
├─ zta-project/                    # 기존 저장소: 현재 단계에서 변경하지 않음
└─ zta-improvements/
   └─ IMPROVEMENT_PLAN.md           # 이 계획서
```

### 구현을 시작할 때 만들 구조

```text
projects/
├─ zta-project/                    # 원본 / 수업 프로젝트 및 과거 증거
└─ zta-improvements/
   ├─ IMPROVEMENT_PLAN.md           # 범위·순서·완료 기준
   └─ source/                      # 원본 저장소에서 만드는 별도 Git worktree
      ├─ app/                      # 기존 앱을 개선
      ├─ k8s/                      # 기존 manifest·Rego를 개선
      ├─ scripts/                  # 기존 runner와 실험 스크립트를 개선
      ├─ visualizer/               # 기존 대시보드를 개선
      ├─ docs/
      │  └─ v2/                    # 새 위협 모델·차이·검증 방법
      └─ evidence/
         └─ v2/
            └─ <run-id>/          # 실행별 config·결과·비밀값 제거 로그
```

- `source/`는 아직 없으며, 빈 구현 폴더나 저장소 복제본을 미리 만들지 않는다.
- 구현 시작 시 기준 커밋에서 별도 worktree와 개선 branch를 만든다. branch 이름 제안: `zta-v2-hardening`.
- worktree는 파일 작업만 분리한다. Kubernetes context·클러스터·namespace·Docker 이미지·포트는 별도로 구분해야 한다.
- 기존 원본의 과거 evidence를 덮어쓰지 않는다. 새 테스트·실험은 `evidence/v2/<run-id>/`에 기록한다.
- 기존 A/C의 헤더 데모는 명시적인 `legacy-demo` 모드로 남길 수 있다. 기본 실행은 `strict` 모드다.
- 새 라이브러리나 정책 프레임워크는 필요한 경우에만 추가하고, 현재 구성과 표준 라이브러리를 우선 사용한다.

## 3. 확인된 사항과 아직 실행으로 확인할 사항

| 항목 | 현재 확인 수준 |
|---|---|
| demo role 헤더 allow 규칙이 JWT 규칙과 동시에 활성화 | 소스에서 확인. viewer JWT + role:admin 조합은 실제 요청으로 재현 필요 |
| JWT 필수 정책의 포트 80과 frontend 수신 8080 불일치 | manifest에서 확인. 실제 적용된 Envoy 정책의 매칭 검증 필요 |
| EW 테스트가 000·503을 PASS로 인정 | runner·Makefile과 저장된 summary에서 확인 |
| backend 오류 상태가 frontend 응답에서 유실 | 실제 `_proxy` 함수 격리 실행으로 403·연결 실패 처리 확인. HTTP E2E 검증은 별도 |
| OPA 8181 HTTP API 노출, 접근 제한 공백 | 설정에서 확인. 비인가 pod의 관리 API 변경 가능성은 재현 필요 |
| posture가 요청 헤더 기반이며 누락 허용, viewer에는 검사 없음 | Rego에서 확인. 신뢰 가능한 실제 장치 검사와 구분 필요 |
| frontend→backend Authorization 전달 설명과 구현 차이 | 소스·정책·문서 교차확인 |
| dashboard 외부 인터페이스 바인딩·무인증 명령 실행·HTML 로그 삽입 | 소스 및 일부 격리 검증. 실제 외부 도달 가능성·브라우저 공격은 미확인 |
| 성능 데이터가 200회·워밍업 0·단일 짧은 실행 | 저장된 Fortio 결과에서 확인 |

## 4. 개선 작업 목록

### W01. JWT 전용 기본 정책과 헤더 우회 제거 — 최우선

**문제:** `demo_mode=true`에서 role 헤더 allow가 JWT 역할 제한을 우회한다. JWT 필수 DENY의 포트 조건도 실제 수신 포트와 다르다.

**작업**

- [ ] 기본 policy에서 데모 헤더 경로를 비활성화한다. 데모 모드 활성화는 명시적인 별도 실행으로 한정한다.
- [ ] JWT 필수 정책의 포트 조건을 실제 워크로드에 맞춘다. 불필요하다면 포트 조건을 제거한다.
- [ ] admin·viewer의 허용 method/path를 명시하고, 그 외 요청의 기본 거부를 확인한다.
- [ ] A/C 시나리오를 strict 모드용 JWT 테스트로 바꾼다. legacy-demo 결과에는 교육용 설정임을 표시한다.

**완료 기준:** 무토큰+role:admin, viewer JWT+role:admin, 위조된 역할 주장 모두 거부. 정상 viewer 읽기와 admin 쓰기는 실제 backend까지 성공.

근거: [demo 및 allow 규칙](../zta-project/k8s/opa-k8s.yaml), [JWT 필수 정책](../zta-project/k8s/jwt-require-policy.yaml), [앱 manifest](../zta-project/k8s/k8s-manifest.yaml).

### W02. 테스트의 PASS 의미와 오류 진단 바로잡기 — 최우선

**문제:** 연결 실패를 차단 성공으로 취급하고, 성공 응답의 본문을 검사하지 않는다. pod 내부 curl의 응답 파일을 host 파일로 읽는 진단 오류도 있다.

**작업**

- [ ] HTTP 거부, TLS/transport 실패, timeout, kubectl 실행 실패를 서로 다른 결과로 기록한다.
- [ ] 거부 테스트 직전에 정상 인증 요청으로 backend 가용성을 확인한다.
- [ ] `000`이 실제 mTLS 차단에서 발생할 수 있음을 반영하되, 상태만 보고 PASS로 처리하지 않는다. 대응 로그와 정상 대조 요청으로 원인을 입증한다.
- [ ] 허용 테스트는 상태 코드와 데이터·`write-accepted` 같은 결과를 함께 검사한다.
- [ ] runner가 실패 종료 코드를 보존하고, 진단 정보의 토큰·개인값을 제거한다.
- [ ] 응답 본문은 host/pod 경계를 고려해서 수집하고 임시 파일을 정리한다.
- [ ] backend-IP 누락 summary 행의 구분자 오류를 고친다.
- [ ] 판정 로직에는 네트워크 없이 실행 가능한 작은 회귀 검증을 남긴다.

**완료 기준:** 백엔드 중단·DNS 오류·kubectl 실패가 차단 성공으로 나오지 않는다. 응답 본문이 잘못된 200은 FAIL. 실패 행을 대시보드와 CLI가 동일하게 읽는다.

근거: [테스트 runner](../zta-project/scripts/run_case.sh), [EW 및 summary recipe](../zta-project/Makefile), [summary parser](../zta-project/visualizer/server.py).

### W03. frontend→backend 처리와 신뢰 경계 정리 — 최우선 + 확장

**문제:** frontend가 backend 오류를 일반 문자열로 반환한다. 문서에는 JWT가 backend에 전달된다고 쓰였지만 앱은 전달하지 않는다. backend 정책은 frontend-sa 신원에 넓은 권한을 준다.

**작업**

- [ ] backend의 HTTP 상태·응답 타입을 정상 응답에 반영한다. timeout/연결 오류는 명시적인 upstream 실패로 처리한다.
- [ ] 현재의 사용자 인가 위치와 workload 신원 경계를 코드와 문서에 일치시킨다.
- [ ] frontend-sa에서 backend admin/write에 직접 접근하는 시나리오로 현재 위협 모델의 한계를 확인한다.
- [ ] 확장 목표로 backend도 검증된 사용자 신원과 권한을 확인하도록 구성한다. 단순 토큰 전달만으로 완료 처리하지 않는다.
- [ ] backend에 RequestAuthentication/인가를 적용한다면 service audience, 내부 호출 규칙, 정상 요청까지 함께 검증한다.
- [ ] frontend에 사용자의 권한보다 넓은 권한을 위임할 필요가 있는지 판단하고 최소 허용 경로로 좁힌다.

**완료 기준:** upstream 거부/장애가 outer 200으로 숨지 않는다. 확장 완료 시 frontend workload 신원만으로 backend의 민감한 작업을 실행할 수 없고, viewer 신원을 전달해도 admin 작업은 거부된다.

근거: [앱 proxy](../zta-project/app/app.py), [backend 인가](../zta-project/k8s/authz-policy-backend.yaml), [CUSTOM 적용 범위](../zta-project/k8s/authz-policy.yaml), [README 설명](../zta-project/README.md).

### W04. OPA 관리 API·결정 로그·네트워크 경계 보호 — 우선

**문제:** OPA 관리 포트 8181이 노출되고 기존 NetworkPolicy도 그 포트의 원천을 제한하지 않는다. 원시 decision log에 Bearer token이 기록될 수 있다.

**작업**

- [ ] OPA 관리 API를 loopback 또는 제한된 관리 경로로 옮기고 불필요한 Service 포트를 제거한다.
- [ ] ext-authz 9191은 필요한 workload만 호출하도록 설계한다.
- [ ] 기존 NetworkPolicy의 적용 여부와 CNI의 실제 집행 여부를 별도로 확인한다. YAML apply 성공만으로 보호된다고 주장하지 않는다.
- [ ] 비인가 pod에서 OPA 상태 조회·정책/데이터 변경 시도를 검증한다. 실험용 무해한 입력으로 실행하고 원상복구를 보장한다.
- [ ] OPA가 로그를 내보내는 시점에 Authorization 등 비밀값을 마스킹한다. 예쁜 출력에서만 숨기는 방식에 의존하지 않는다.
- [ ] 관리 API 제한 후 health/readiness 확인과 ext-authz 정상 동작을 검증한다.

**완료 기준:** 비인가 pod는 정책 엔진을 관리할 수 없다. 정상 ext-authz는 동작하고, 원시 로그·진단·evidence에 테스트 토큰이 남지 않는다.

환경 변경: CNI 및 클러스터 네트워크 설정은 별도 확인 후 진행한다.

근거: [OPA 배포](../zta-project/k8s/opa-k8s.yaml), [OPA NetworkPolicy](../zta-project/k8s/opa-network-policy.yaml), [원시 로그 요약](../zta-project/scripts/parse_opa_logs.py).

### W05. JWT audience·수명·키 교체 검증 — 우선

**문제:** issuer 확인과 역할 검사만으로는 서비스 대상까지 좁혀지지 않는다. JWKS가 inline 방식으로 바뀌며 수동 갱신에 의존한다. 기존 위조 테스트는 서명·issuer·claims 오류를 동시에 바꿔 거부 원인을 분리하기 어렵다.

**작업**

- [ ] Keycloak이 대상 서비스 audience를 발급하게 하고, Istio가 동일 audience를 요구하도록 구성한다.
- [ ] 원본 jwt-auth와 inline-JWKS 생성 경로가 같은 검증 조건을 유지하도록 한다.
- [ ] 유효 JWT의 역할 하나만 바꾸고 기존 서명과 나머지 claims는 유지하는 변조 테스트를 만든다.
- [ ] 잘못된 issuer, audience, 만료 exp, 미래 nbf, unsigned token을 개별 테스트한다. 허용할 clock skew를 먼저 정하고 시간 경계 밖과 정상 대조 요청을 비교한다.
- [ ] 새 서명 키 반영·이전 키 유지/폐기·갱신 실패 시 처리 절차를 명시하고 실제 요청으로 검증한다.
- [ ] access-token TTL과 refresh-token/session 종료의 의미를 구분해서 문서화한다. 로그아웃 후 refresh-token 재발급 거부는 기존 access-token 만료와 별도 검증한다.

**완료 기준:** 정상 대상 토큰만 허용. 원인이 다른 부정 토큰을 각각 거부. 키 교체의 허용 유예 기간과 폐기 이후 거부가 설정된 계약과 일치한다.

**별도 확장:** 즉시 권한 회수까지 원하면 introspection 또는 신뢰된 revocation 상태를 검토한다. 서명만 검사하는 JWT는 로그아웃 직후에도 exp 전까지 유효할 수 있으므로, 즉시 거부를 기본 완료 기준으로 두지 않는다.

근거: [JWT 설정](../zta-project/k8s/jwt-auth.yaml), [inline JWKS 생성](../zta-project/scripts/apply-jwt-inline-jwks.sh), [Keycloak 설정](../zta-project/scripts/setup-keycloak.sh).

### W06. 장치 상태 입력의 신뢰성과 정책 일관성 — 확장

**문제:** 현재 posture는 클라이언트 헤더 시뮬레이션이며 누락을 허용한다. viewer allow에는 검사도 없다.

**작업**

- [ ] 장치 상태가 필수인 보호 자원을 정의하고 모든 관련 allow 경로에 동일 조건을 적용한다.
- [ ] 필수 자원에서는 상태 누락·불량·너무 오래된 상태를 거부한다.
- [ ] 요청자가 직접 보낸 posture 헤더를 권위 있는 정보로 사용하지 않는다.
- [ ] 기존 구성으로 검증 가능한 서명된 posture 입력을 만들고 신뢰 issuer·사용자/장치 연결·유효기간을 확인한다.
- [ ] 최소 버전은 Keycloak의 서명된 테스트 claim으로 신뢰 경계를 시연할 수 있다. 이 경우 실제 장치 건강성을 측정한 것으로 표현하지 않는다.
- [ ] 실제 장치 검사는 MDM/endpoint 검사 결과를 연결하는 후속 단계로 둔다. 외부 서비스 연결은 별도 승인 후 진행한다.

**완료 기준:** 헤더를 enabled로 바꾸거나 삭제해도 장치 상태 제한을 우회할 수 없다. viewer도 보호 자원의 posture 조건을 따른다. 만료된 상태나 다른 주체의 결과는 거부된다.

근거: [posture 및 viewer 규칙](../zta-project/k8s/opa-k8s.yaml), [posture 공격 스크립트](../zta-project/scripts/attack-posture.sh).

### W07. 대시보드 실행·표시·동시성 개선 — 우선

**작업**

- [ ] 기본 서버 바인딩을 localhost로 제한한다.
- [ ] 명령 시작은 POST로 바꾸고 Host/Origin 또는 동등한 출처 검증을 적용한다. SSE는 실행된 작업의 출력을 읽는 용도로 분리한다.
- [ ] 불필요한 wildcard CORS를 제거하고 고정 명령 allowlist를 유지한다.
- [ ] 서버에서 한 번에 하나의 변경/테스트 작업만 실행한다. 충돌하는 요청에는 busy 응답을 준다.
- [ ] 로그 출력을 `textContent`로 표시하고, 다른 동적 HTML에도 신뢰하지 않는 값을 안전하게 출력한다.
- [ ] 예상 차단 계층과 실제 관측 결과를 구분한다. 고정 flow marker는 계층 차단의 실측 증거가 아니다.
- [ ] 테스트 전체 소요 시간과 HTTP 요청 latency를 다른 항목으로 표시한다.

**완료 기준:** 다른 출처의 명령 실행 요청이 거부된다. HTML을 포함한 로그는 문자로 보인다. 동시 테스트가 summary나 정책 상태를 섞지 않는다.

근거: [dashboard server](../zta-project/visualizer/server.py).

### W08. 성능 실험과 baseline 전환 재현성 — 우선

**문제:** baseline 안내의 clean이 앱까지 삭제한다. 실험 실패를 무시하고 일부 응답 코드만 기록한다. 저장된 결과는 단일·짧은·워밍업 없는 실행이다.

**작업**

- [ ] 앱을 유지하는 실험 전용 policy 전환을 만들고 종료 시 원래 strict 상태로 복원한다.
- [ ] baseline 모드는 격리된 실험 환경에서만 허용하고, 보안이 약화된 상태임을 명확하게 표시한다.
- [ ] 실행 실패·혼합 응답·기대와 다른 응답이 있으면 유효한 성능 결과로 확정하지 않는다.
- [ ] HTTP status 전체 분포와 응답 수, 성공 본문을 확인한다.
- [ ] 초기 실험안: 워밍업 후 30–60초 측정, 각 조건 5회, 동시성 1/4/16. 실제 환경 자원에 맞춰 조정한다.
- [ ] 계층 비교: sidecar 기준 → mTLS → JWT → OPA. 같은 route·identity·서비스 경로를 유지하고 변경한 조건을 기록한다.
- [ ] 이전 정책·JWT 키·Envoy 설정이 새 조건에 섞이지 않도록 sync/readiness를 확인한다. 필요한 proxy가 모두 존재하고 대상 설정이 반영됐는지 검사한다. 같은 istiod 하나에 연결됐다는 조건만으로 완료 처리하지 않으며, timeout·proxy 누락이면 테스트/측정을 시작하지 않고 실패 종료한다.
- [ ] avg·p50·p95·p99·QPS·오류율과 반복 간 변동을 함께 보고한다. 측정 순서를 교차해 시간 순서 편향을 줄인다.
- [ ] component 버전, 자원 배정, 적용 정책, commit, 시간, workload readiness를 실행별 manifest에 기록한다. 토큰은 기록하지 않는다.

**완료 기준:** 같은 절차로 baseline과 strict를 재현할 수 있다. 실패한 실행이 latest 정상 결과를 덮어쓰지 않는다. 실험 이후 strict 보안 상태가 복원된다.

근거: [성능 recipe](../zta-project/Makefile), [시나리오 성능 수집](../zta-project/scripts/perf_scenarios.sh), [기존 baseline](../zta-project/evidence/perf-baseline-latest.txt), [기존 ZTA 결과](../zta-project/evidence/perf-zta-latest.txt).

### W09. 실행 환경·컨테이너의 최소 보완 — 후반

**작업**

- [ ] 설치·실행 의존성과 버전을 명시하고, Flask/requests 등 실제 사용 항목의 버전을 재현 가능하게 고정한다.
- [ ] 이미지와 실행 파일의 현재 지원 여부는 별도 확인 후 갱신한다. 코드만 보고 취약 버전이라고 단정하지 않는다.
- [ ] 같은 이미지 태그가 존재한다는 이유만으로 변경된 앱의 빌드를 건너뛰지 않는다. 변경 시 rebuild 또는 commit 기반 태그를 사용하고, 배포된 image digest/revision이 해당 실행의 소스와 일치하는지 확인한다.
- [ ] 가능한 컨테이너부터 non-root, 불필요한 capability 제거, 불필요한 service-account token 자동 마운트 제거를 적용한다.
- [ ] requests/limits와 readiness/liveness를 설정하되, Istio 및 각 프로세스 동작과 충돌하지 않게 검증한다.
- [ ] ServiceAccount 권한을 검토한다. 임의 pod가 frontend-sa로 실행될 수 있다면 workload identity allowlist의 한계를 문서화하고 Kubernetes RBAC/생성 권한까지 확인한다.
- [ ] 오래된 사용자 경로, WSL 실행 경로, 필수 도구와 실패 안내를 실제 개선본 위치에 맞춘다.

**완료 기준:** 깨끗한 개선본 checkout에서 동일한 실행 흐름을 재현하고 배포 revision이 기록된 소스와 일치한다. 설정 동기화 실패 시 실행을 중단한다. 제한을 적용한 컨테이너도 정상 동작한다. 실행 계정의 실제 권한 범위를 설명할 수 있다.

환경 변경: resource 설정·RBAC·namespace·배포 변경은 구현 단계에서 영향과 범위를 확인하고 진행한다.

근거: [Dockerfile](../zta-project/app/Dockerfile), [workload manifest](../zta-project/k8s/k8s-manifest.yaml), [Keycloak manifest](../zta-project/k8s/keycloak.yaml), [실행 안내](../zta-project/CLAUDE.md).

### W10. 문서·증거·관측 결과 연결 — 전체 단계 공통

**작업**

- [ ] 각 시나리오에 위협, 사전 조건, 요청, 기대, 관측값, 원인, 한계를 기록한다.
- [ ] request/run ID로 테스트 결과와 Envoy/OPA 로그를 연결한다.
- [ ] 과거 A–E와 새 strict 시나리오의 대응표를 만든다. legacy-demo 성공을 strict의 보안 증거로 합산하지 않는다.
- [ ] 구현과 README·체크리스트·Markdown 보고서·LaTeX 원문 사이의 설명 차이를 맞춘다.
- [ ] 구성요소 조합 자체로 얻는 보장과 실제 검증한 보장을 구분한다. VPN·proxy·firewall 일반 제품 전체에 대한 불가능 주장을 로컬 실험 결과로 단정하지 않는다.
- [ ] 성능 수치는 측정 조건에 한정한다. 생산 환경 latency·일반 사용자 체감·순수 정책 비용으로 확대 해석하지 않는다.
- [ ] baseline→v2의 변경과 새 실험 결과를 기록한다. 결과를 얻기 전에 개선 수치를 작성하지 않는다.
- [ ] PDF는 검증 완료 후 별도 생성한다. Markdown/LaTeX 수정만으로 기존 PDF도 갱신됐다고 표시하지 않는다.

**완료 기준:** 보고서의 핵심 주장마다 설정·실행 결과·제한이 연결된다. 시뮬레이션·실측·미검증 계획이 구분되고, 증거에 비밀값이 없다.

근거: [위협 모델](../zta-project/docs/02-threat-model.md), [체크리스트](../zta-project/docs/05-checklist.md), [보고서 초안](../zta-project/docs/06-final-report-draft.md), [LaTeX 원문](../zta-project/docs/CSE487-MinsooAhn-ZTA.tex).

## 5. 추가할 시나리오 목록

아래 표는 새 테스트의 설계안이다. 아직 구현·실행한 결과가 아니다. 결과 판정은 HTTP 코드만으로 하지 않고, 관련 계층 로그와 정상 대조 요청을 함께 사용한다.

| ID | 시나리오 | 기대 및 검증 핵심 | 작업 |
|---|---|---|---|
| S01 | 무토큰 + role:admin | 인증 부재로 거부; OPA 헤더 allow로 통과하지 않음 | W01 |
| S02 | viewer JWT + role:admin | admin 읽기·쓰기 거부; signed role만 반영 | W01 |
| S03 | 정상 viewer 읽기 / admin 읽기·쓰기 | 적절한 요청만 실제 backend 성공 및 결과 본문 확인 | W01–03 |
| S04 | 유효 토큰의 role 하나만 변조 | 원본 서명 유지; 서명 변조 원인으로 거부 | W05 |
| S05 | 정상 서명 구조 + 다른 issuer | issuer가 다른 이유로 거부. test IdP/키 조건을 기록 | W05 |
| S06 | 같은 issuer + 다른 audience | 다른 client/서비스 대상 토큰 거부 | W05 |
| S07 | 만료 JWT / 미래 nbf | exp/nbf 거부; 정상 token control과 clock 차이 기록 | W05 |
| S08 | unsigned·형식 오류·잘못된 Authorization | 인증 실패/인가 실패를 구분하고 명확하게 거부 | W05 |
| S09 | Keycloak 서명 키 교체 | 새 키 토큰 허용; 이전 키는 명시한 유예/폐기 계약대로 처리 | W05 |
| S10 | 로그아웃 후 access-token 재사용 | TTL 방식의 실제 한계 관측. 즉시 회수 모드를 추가한 경우만 별도 회수 SLA로 거부 | W05 |
| S11 | sidecar 없는 rogue pod | 정상 backend 가용성 확인 후 mTLS 차단 원인 입증 | W02 |
| S12 | sidecar는 있지만 허용되지 않은 SA | mTLS 성공 여부와 SPIFFE 인가 거부를 분리 | W02–03 |
| S13 | backend Service 및 pod-IP 직접 접근 | 두 경로 모두 동일한 경계 적용; DNS/timeout과 혼동하지 않음 | W02 |
| S14 | 침해된 frontend-sa의 backend admin/write 직접 호출 | 기존 위임 권한을 먼저 관측. backend 인가 확장 후 사용자 증거 없으면 거부 | W03 |
| S15 | frontend-sa가 viewer token을 backend로 전달 | workload 신원은 유효해도 admin 작업은 거부 | W03 |
| S16 | 비인가 pod의 OPA 관리 API 접근 | 조회·무해한 정책/데이터 변경이 거부됨 | W04 |
| S17 | OPA 중단·timeout | 허가 판단을 받을 수 없으면 요청을 처리하지 않음; transport/서비스 실패로 기록 | W02·04 |
| S18 | policy 변경 직후 요청 | 허용→거부 및 복원 반영 지연을 측정. 즉시 반영으로 가정하지 않음 | W04·10 |
| S19 | 불량 posture + admin / viewer | 정의한 보호 자원에서 두 역할 모두 거부 | W06 |
| S20 | posture 누락·enabled 헤더 위조 | 필수 상태 누락/위조로 우회할 수 없음 | W06 |
| S21 | 만료 또는 다른 주체의 signed posture | freshness·subject binding 위반으로 거부 | W06 |
| S22 | backend 403/503·응답 지연·중단 | frontend가 실패를 정상 200으로 숨기지 않음 | W02–03 |
| S23 | frontend/OPA 재시작 후 재검증 | readiness 및 정책 반영 확인 후 정상 요청만 성공 | W04·09 |
| S24 | Keycloak 일시 중단 | 이미 검증 키가 있는 유효 token과 신규 발급/키 갱신 실패를 구분; 사전 정의한 계약과 비교 | W05 |
| S25 | 경로·method 경계 | `/api/admin/`, 중복 slash, percent encoding, query, HEAD/OPTIONS 등을 일관되게 해석. 존재하지 않는 경로의 404를 인가 거부 성공으로 세지 않음 | W01–03 |
| S26 | 중복 Authorization/role/posture 헤더 | 인증·정책 입력의 해석 불일치로 우회하지 못함 | W01·05·06 |
| S27 | 다른 출처에서 dashboard 명령 실행 | 외부 Origin/Host의 실행 요청 거부; SSE로 실행을 시작할 수 없음 | W07 |
| S28 | HTML이 들어 있는 공격 요청 로그 | dashboard에서 문자가 보이며 실행되지 않음 | W07 |
| S29 | 두 dashboard/test 작업 동시 실행 | 두 번째 충돌 작업 거부; 결과·정책 상태가 섞이지 않음 | W07 |
| S30 | raw decision log·실패 diagnostics 수집 | Bearer token 등 비밀값이 없음. 검사 출력에도 token을 노출하지 않음 | W04·10 |
| S31 | 성능 실행 실패·mixed status·실행 취소 | 유효 결과로 저장하지 않고 strict 상태 복원 | W08 |
| S32 | 단계별 보안 제어 및 동시성 비교 | 적용 config 확인 후 반복 측정; security test가 보장하는 범위와 비용을 함께 보고 | W08 |
| S33 | mesh sync timeout·필요 proxy 누락 | setup/test/perf가 실패 종료하며 오래된 설정으로 측정하지 않음 | W08·09 |
| S34 | 앱 소스 변경 후 재배포 | 기존 태그가 있어도 변경된 이미지가 배포됨; revision/digest와 동작 확인 | W09 |

### 후속 선택 시나리오

- **즉시 권한 회수:** 단순 로그아웃/TTL 결과와 구분해서, 권한 변경·사용자 비활성화가 정한 시간 안에 기존 token에도 반영되는지 검증한다. introspection/상태 조회 방식은 부하와 IdP 장애 정책도 함께 정한다.
- **실제 endpoint posture:** signed 테스트 claim 단계가 끝난 뒤, 실제 장치 검사 결과를 연결한다. freshness, 위조, replay와 검사 시스템 장애를 검증한다.
- **부하 중 정책 장애:** 기능 정확성과 기본 성능 실험이 끝난 뒤, 부하 상태에서 OPA 장애·정책 변경이 허용/거부와 latency에 미치는 영향을 측정한다.

즉시 회수와 실제 endpoint 통합은 외부 상태·운영 복잡도를 늘린다. 첫 v2의 필수 완료와 별도 milestone으로 구분하며, 단순 테스트 claim을 실제 endpoint 연동이라고 표시하지 않는다.

## 6. 진행 순서와 단계별 산출물

| 단계 | 할 일 | 단계 종료 기준 |
|---|---|---|
| 0. 분리·현재 상태 재현 | worktree 생성, 실행 환경 분리 결정, 원본 A–E와 신규 우회 케이스 관측 | 기준 commit/config/result 확보; 발견을 재현 또는 미재현으로 분류 |
| 1. 핵심 정확성 | W01·W02·W03의 오류 전달 및 문서 정합성 | 우회 거부, 정상 요청 E2E 성공, 장애가 PASS로 기록되지 않음 |
| 2. 보안 구성 보호 | W04·W05·W07 | OPA API 제한, 로그 마스킹, token edge case, dashboard 안전한 실행 |
| 3. 경계 확장 | W03 backend 사용자 인가·W06 signed posture | frontend 침해·viewer 위임·posture 위조 시나리오 통과 |
| 4. 재현·측정 | W08·W09 | 반복 가능한 보안 실험 및 성능 결과, strict 복원, 최소 환경 보완 |
| 5. 보고서 정리 | W10 및 전체 회귀 검증 | 기존→개선본 대응표, 새 evidence, 주장과 한계 정합성 |

먼저 모든 기능을 바꾸고 마지막에 테스트하는 방식으로 진행하지 않는다. 각 단계에서 필요한 작은 검증을 실행하고, 통과한 기준 위에 다음 확장을 추가한다.

## 7. 구현 전 환경에서 확인할 항목

아래 항목은 계획서 작성에 필요하지 않으므로 현재 변경하지 않았다. 실제 구현·실험 전에 범위를 확인한다.

- 원본과 v2가 같은 클러스터를 공유할지, 별도 minikube profile/context를 사용할지. 권장안은 별도 실험 환경이며 PC 메모리·Docker 자원을 보고 결정한다.
- namespace, frontend/Keycloak/dashboard 포트, 이미지 태그, JWT issuer/audience를 어떻게 구분할지.
- NetworkPolicy를 집행할 CNI 도입·변경 여부. 이는 클러스터 네트워크 변경이다.
- Keycloak realm/client/key 변경은 원본 환경에 적용하지 않고 개선본 실험 환경에 한정할지.
- RBAC·리소스 배정·보안 context 변경 범위와 정상 동작에 필요한 예외.
- 즉시 token 회수와 실제 장치 검사 연동을 첫 v2에 포함할지 별도 단계로 할지.

외부 웹 조사·새 connector·외부 서비스·CI publishing은 현재 범위에 없다. 버전 지원 확인이나 실제 endpoint 연동이 필요해지면 그 작업의 목적과 접근 범위를 먼저 확인한다.

## 8. 최종 완료 체크리스트

- [ ] 원본 파일·과거 evidence가 보존되고 개선본 branch/worktree가 구분된다.
- [ ] W01–W10의 필수 작업이 완료되고, 후속 선택 범위의 상태도 명시된다.
- [ ] 실행 가능한 시나리오는 기대·실측·원인·한계가 연결된다. 아직 못 실행한 항목은 PASS로 표시하지 않는다.
- [ ] 인증·인가 우회, backend 장애, OPA 장애를 정상적으로 구분한다.
- [ ] 장치 상태의 실제 신뢰 수준과 token 회수 모델을 설명할 수 있다.
- [ ] OPA·dashboard·로그의 보안 경계가 검증된다.
- [ ] 성능 결과는 반복·조건·오류율을 포함하고 보안 정책이 복원된다.
- [ ] README·위협 모델·보고서·새 evidence가 최종 구현과 맞는다.

## 9. 현재 파일의 검증 상태

- 이 파일만 새 개선 폴더에 작성했다. `source/` worktree·branch·클러스터 설정은 아직 생성/변경하지 않았다.
- 원본 저장소의 위치·기준 commit·Git 상태를 확인했다.
- 계획의 근거 파일 링크, W01–W10 작업 ID, S01–S34 시나리오 ID를 로컬 검사한다.
- 현재의 문서 검증은 구현 완료나 보안 테스트 통과를 의미하지 않는다.
