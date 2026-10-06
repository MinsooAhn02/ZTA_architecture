# 현재 PC의 ZTA 실행 환경

확인일: 2026-10-06
상태: 기본 셋업 완료 / 기존 18개 시나리오 실행 완료
원본: `C:/Users/Minsoo/minsoo_security/projects/zta-project`
원본 기준 commit: `49daa49e49dc1a7a626ff998cf2038983fd63eef`

## 지금 접속할 주소

| 화면 | 주소 | 확인 결과 |
|---|---|---|
| ZTA 대시보드 | <http://localhost:5001> | HTTP 200, API에 현재 18개 PASS 표시 |
| Keycloak | <http://localhost:18080> | master realm HTTP 200 |
| Kiali | <http://localhost:20000> | HTTP 200 |
| Grafana | <http://localhost:20002> | health API HTTP 200 |

ZTA 대시보드는 localhost에만 바인딩해서 백그라운드로 실행했다. 이 PC에서 실행 중인 Docker/WSL/minikube가 유지되는 동안 사용할 수 있다. 재부팅 후에는 아래 실행 명령을 사용한다.

## 설치·실행 구성

| 항목 | 현재 확인한 값 |
|---|---|
| Docker Desktop engine | 29.8.2, Linux containers, WSL integration 정상 |
| WSL distro | Ubuntu 26.04.1 LTS, WSL2, 사용자 minsoo |
| minikube | 이번에 설치한 v1.39.0, 공식 다운로드의 SHA-256 검증 완료 |
| Kubernetes | v1.34.0, minikube profile `minikube` |
| 클러스터 자원 | 4 CPU / 8192 MB |
| 노드 컨테이너 runtime | containerd |
| Istio | 실제 istiod 이미지 `docker.io/istio/pilot:1.28.3` 확인 |
| kubectl | ZTA 실행 파일에서는 `minikube kubectl`의 v1.34.0 사용 |
| PyYAML | 기존 설치 6.0.3 확인 |
| 기본 앱 구성 | frontend, backend, Keycloak, OPA, 테스트 client 3종 |

Docker Desktop이 제공한 기존 kubectl v1.36.1은 변경하지 않았다. 프로젝트 실행 때만 setup/bin의 wrapper로 클러스터와 일치하는 kubectl을 사용한다.

## PowerShell에서 다시 실행

먼저 Docker Desktop을 실행한다. 아래 변수는 새 PowerShell 창마다 한 번 지정한다.

```powershell
$ztaLauncher = 'C:\Users\Minsoo\minsoo_security\projects\zta-improvements\setup\Launch-ZTA.ps1'
```

클러스터·앱·포트 연결 준비:

```powershell
& $ztaLauncher start
```

현재 상태 확인:

```powershell
& $ztaLauncher status
```

기존 보안 테스트 실행, 그 결과와 실제 backend 응답 검증:

```powershell
& $ztaLauncher test
& $ztaLauncher verify
```

`verify`는 최신 test 결과가 있는 상태에서 실행한다. 토큰은 임시 cache를 사용하고, stdout에 출력하지 않는다. 검증 이후 임시 token 파일을 정리한다.

대시보드 실행:

```powershell
& $ztaLauncher dashboard
```

이 명령은 터미널에서 대시보드를 유지한다. 종료하려면 Ctrl+C를 누른다. 이미 http://localhost:5001이 열려 있으면 두 번째 서버를 실행할 필요가 없다.

ZTA 대시보드와 minikube 중단:

```powershell
& $ztaLauncher stop
```

`stop`은 기록된 ZTA 대시보드 프로세스를 확인해서 종료하고 minikube를 정지한다. Docker Desktop 전체나 다른 Docker container는 종료하지 않는다. 프로젝트/클러스터를 삭제하는 clean-all은 실행하지 않았다.

## 이번에 해결한 기본 환경 문제

### 1. minikube 미설치

Docker·WSL·make·Python·curl·kubectl은 있었지만 minikube가 없었다. 공식 바이너리와 checksum을 받아 검증 후 `/usr/local/bin/minikube`에 설치했다. 설치 작업 기록은 [의존성 준비 스크립트](setup/install-prerequisites.sh)에 있다.

### 2. Docker runtime 전제의 이미지 빌드

기존 Makefile의 `minikube docker-env` 기반 빌드는 현재 containerd 환경에서 buildkit image inspect 오류로 실패했다. [로컬 Makefile](setup/Makefile.local)이 이미지 빌드를 `minikube image build`로 수행한다. 원본 Makefile은 변경하지 않았다.

### 3. 현재 PC와 다른 사용자 경로

원본 `make view`에는 `/mnt/c/Users/dksal/...` 경로가 남아 있다. [PowerShell 실행 파일](setup/Launch-ZTA.ps1)과 [WSL 실행 파일](setup/run-zta.sh)은 자신의 위치로부터 현재 원본 프로젝트 경로를 계산해서 사용한다.

### 4. kubectl 버전 차이

Docker Desktop kubectl은 v1.36.1이므로, v1.34.0 클러스터용 kubectl을 ZTA 실행 범위에서만 사용한다. 시스템 전체 PATH나 Docker Desktop의 도구를 덮어쓰지 않았다.

### 5. 테스트 summary 경로 전달 차이

Makefile은 `TEST_SUMMARY_FILE`, runner는 `SUMMARY`를 사용한다. 두 값을 같은 generated 파일로 맞춰 18개의 현재 결과가 CLI와 대시보드에 동일하게 표시되도록 했다. 실행 후 [최신 결과 사본](setup/latest-test-summary.log)을 별도 setup 폴더에도 저장한다.

### 6. 대시보드의 로컬 실행

[대시보드 실행 파일](setup/dashboard-local.py)은 원본 server와 자체 self-check를 재사용하면서 `127.0.0.1:5001`에 바인딩한다. 원본 UI·정책·시나리오를 수정하지 않았다. 다음 개선 단계의 출처 검증·로그 HTML 처리·동시성 제어는 별도 작업이다.

## 검증 결과와 한계

- 필요한 default deployment 7개가 모두 available이며 frontend/backend/client의 Istio sidecar도 실행 중이다.
- Istio mTLS STRICT, backend allowlist, frontend CUSTOM·JWT 정책이 생성되어 있다.
- 기존 시나리오 A–E의 서로 다른 18개 결과가 모두 기존 판정 기준으로 PASS다.
- 그중 EW 2개는 HTTP `000`이다. 이는 기존 runner의 PASS 기준이며, 실제 mTLS 차단 원인과 일반 연결 장애의 구분은 개선 계획 W02에서 보완한다.
- fresh JWT를 발급받아 frontend `/api/data`를 호출했고 실제 backend `sensor-data`와 예상 데이터 내용까지 확인했다.
- Windows에서 대시보드·Keycloak·Kiali·Grafana 응답을 확인했다. 대시보드 `/api/data`에는 현재 시나리오 18개가 모두 PASS로 표시된다.
- Bash/PowerShell/Python 실행 파일의 구문 및 실제 verify 동작을 확인했다.
- 원본 저장소의 tracked 코드·manifest·과거 evidence는 변경하지 않았고 Git 상태는 clean이다. 정상 실행으로 갱신되는 ignored summary/JWKS fingerprint 등의 파일은 별도로 존재한다.

이 결과는 기본 실행 환경과 기존 동작 확인이다. [개선·확장 계획](IMPROVEMENT_PLAN.md)의 JWT 우회 제거·OPA 보호·신뢰된 posture·실험 개선은 아직 구현하지 않았다.

Keycloak은 기존 dev 배포 설정을 유지했다. pod 재생성으로 realm/key가 바뀔 수 있으므로, 재시작 후에는 `start`와 `test`를 실행해서 초기화 및 JWKS 갱신을 확인한다. 즉시 JWT 철회나 production readiness를 검증한 것으로 해석하지 않는다.

## 작업 파일

- [PowerShell 실행 파일](setup/Launch-ZTA.ps1): start / test / verify / dashboard / status / stop.
- [WSL 실행 파일](setup/run-zta.sh): 현재 프로젝트 경로와 kubectl scope, token cache, summary를 연결.
- [로컬 이미지 빌드 설정](setup/Makefile.local): containerd에 맞는 native minikube image build.
- [대시보드 실행 파일](setup/dashboard-local.py): localhost 실행.
- [실행 검증](setup/verify-runtime.py): 실제 배포·18개 결과·backend 데이터 확인.
- [기본 셋업 로그](setup/setup.log).
- [최신 보안 테스트 로그](setup/test.log).
- [최신 결과 사본](setup/latest-test-summary.log).

설치와 기본 셋업에 필요한 공식 배포 파일·container image는 내려받았다. 웹 검색·외부 계정 연결·v2 worktree 생성은 수행하지 않았다. Docker가 이미 실행 중이어서 컴퓨터 UI 조작은 필요하지 않았다.
