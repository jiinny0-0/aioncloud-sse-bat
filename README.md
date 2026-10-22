# AIONCLOUD SSE BAT

AIONCLOUD SSE의 보안 기능이 실제 사용자·단말·네트워크 환경에서 동작하는지 검증하는
BAT(Business Acceptance Test) 자동화입니다. API 테스트(응답·CRUD)나 UI 테스트(화면 요소)를
대체하지 않고, "실제 트래픽이 허용·차단되고 이벤트가 남는가"를 봅니다.

```text
정책 설정(API) → 실제 트래픽(단말·브라우저) → 보안 동작
   → 사용자 가시 결과 → 이벤트/로그 검증 → 리소스 회수
```

대상 제품: basic, swg, dlp, fwaas, casb, genai, ztna, cross (edr, rbi는 보류)

---

## 설치

프로젝트 루트(`pyproject.toml`이 있는 폴더)에서:

```powershell
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

수동 설치:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
python -m playwright install chromium
pip install pywinrm          # 원격 단말(WinRM)을 쓸 때만
```

새 터미널마다 `.\.venv\Scripts\Activate.ps1`이 필요합니다. 활성화 없이 쓰려면
`python -m bat.cli ...`로 호출합니다.

---

## 설정

```powershell
copy env.example .env
copy config\environments.example.yaml config\environments.yaml
```

| 파일 | 내용 |
| --- | --- |
| `.env` | 콘솔 계정, Open API 토큰, 단말 WinRM 계정. git과 리포트에 남지 않음 |
| `config/environments.yaml` | 스테이지마다 블록 하나: URL, 워크스페이스, 단말 |

스테이지는 `bat run --profile <이름>` 또는 `BAT_PROFILE=<이름>`으로 고릅니다. 스테이지별
자격증명은 블록의 `env_file:`(예: `.env.qa`)에 두고, 없는 값은 공용 `.env`에서 읽습니다.
`env_file:`을 생략하면 `.env.<스테이지 이름>`을 씁니다.

Open API 토큰은 콘솔에서 워크스페이스별로 발급합니다.

```ini
BAT_CONSOLE_USER=...
BAT_CONSOLE_PASSWORD=...
BAT_OPENAPI_TOKEN=...                 # 공용
BAT_OPENAPI_TOKEN_<WORKSPACE>=...     # 워크스페이스별 (우선)
```

| 변수 | 기본값 |
| --- | --- |
| `BAT_PROFILE` | `qa` |
| `BAT_EVENT_TIMEOUT_SEC` / `BAT_POLICY_TIMEOUT_SEC` | 30 / 20 |
| `BAT_TOKEN_BUDGET` | 10 |

---

## 실행

```powershell
bat doctor                           # 인증·REST·로그 조회 점검
bat login                            # 콘솔 세션 저장 (커넥터를 내린 상태에서)
bat sweep --delete                   # 이전 실행이 남긴 BAT 리소스 정리

bat run                              # 기본 실행 (manual, crud, parked 제외)
bat run --product swg --product dlp
bat run --tag critical               # P0
bat run --tag smoke                  # 제품별 대표 케이스
bat run --case BAT-SWG-001,BAT-SWG-002   # 제품이 섞이면 --product도 지정
bat run --case BAT-SWG-001 --headed  # 브라우저 표시
bat run --profile <스테이지>
bat run --dry-run                    # 계획만 출력

bat progress                         # 진행 중인 실행의 현황 (reports/run-progress.md)
```

`bat run`은 시작 전에 연결을 점검합니다. 워크스페이스마다 LOGGING 정책을 하나 걸고 단말에서
요청을 보내, 60초 안에 그 워크스페이스 로그에 이벤트가 남지 않으면 종료 코드 7로 멈춥니다.
커넥터가 꺼져 있거나 다른 워크스페이스에 로그인돼 있을 때, 또는 다른 정책이 점검 대상
호스트를 먼저 가져갈 때 이렇게 됩니다. 점검을 건너뛰려면 `--skip-preflight`.

환경 없이 프레임워크만 점검: `pytest tests/test_selfcheck.py`

### 기타 명령

| 명령 | 하는 일 |
| --- | --- |
| `bat lanes` | 레인 배정과 예상 실행 시간 |
| `bat traffic` | 단말 트래픽이 SSE를 지나는지 |
| `bat inspect [--id N \| --dlp \| --predefined \| --genai \| --casb \| --saas-access \| --rbi]` | 콘솔에 저장된 정책 JSON |
| `bat probe` / `bat schema` | 콘솔 GraphQL 구조 확인 (introspection이 막혀 있음) |
| `bat diagnose-user` | 사용자 생성 실패 원인 구분 |

---

## 동작 방식

**레인과 동시 실행.** 단말 하나에는 커넥터가 하나뿐이라 단말 수가 병렬도를 정합니다.

```text
Lane b   basic, swg, fwaas, cross
Lane c   dlp, rbi
Lane d   casb, genai
Lane e   ztna, edr
```

단말이 레인보다 적으면 레인이 병합됩니다. BAT 정책은 워크스페이스의 모든 사용자에게
걸리므로, 같은 워크스페이스를 쓰는 케이스는 단말이 달라도 동시에 돌지 않습니다.

**정책은 API로, 판정은 실제 트래픽으로.** 정책은 REST와 콘솔 GraphQL로 만들고, 결과는
단말의 curl·브라우저 요청과 보안 로그로 확인합니다. 정책 반영과 이벤트는 폴링으로 기다립니다.

**판정.** 케이스는 선언한 기준(사용자 가시 결과, 이벤트)마다 통과한 확인이 있어야 PASS입니다.
확인할 수단이 없으면 UNVERIFIED, 대상 기능이 탐지하지 않는 환경이면 SKIP입니다. 환경 점검 케이스(basic)는
점검이 모두 통과하면 PASS입니다. 확인 중인 제품 문제로 표시한 케이스(`@pytest.mark.known_issue`)는 실패해도
FAIL 대신 UNVERIFIED로 기록되고, 원래 실패 이유가 함께 남습니다.

**리소스 회수.** 생성물은 모두 `BAT-<PRODUCT>-<NNN>-<run_id>` 이름을 갖고, 실패해도
삭제를 시도합니다. 삭제 실패는 `cleanup_warnings`로 남고, `bat sweep`이 남은 것을 찾습니다.
Signature Management 차단 목록에는 케이스 동안만 BAT 전용 항목을 넣었다 뺍니다.

**안전.** 넓은 범위의 BLOCK은 만들지 않습니다. 러너의 API 호출도 커넥터를 지나므로,
출발지 IP·국가나 메서드처럼 요청 전체에 걸리는 조건은 LOGGING으로만 확인합니다.
테스트 데이터는 전부 합성값입니다.

**민감정보.** 토큰, JWT, 비밀번호류 값은 리포트 저장 직전에 마스킹됩니다.

---

## 실행 결과

`bat run`이 끝날 때마다 `reports/result/<YYYYMMDD>-<스테이지>-bat-test-result.xlsx`를 만듭니다
(예: `20261022-qa-bat-test-result.xlsx`). 같은 날 같은 스테이지를 다시 돌리면 덮어씁니다.

| 열 | 내용 |
| --- | --- |
| Product | 제품 |
| Status | 그 스테이지에서 케이스의 가장 최근 결과 (PASS / FAIL / UNVERIFIED / SKIP / ERROR / 미실행) |
| Scenario | 케이스가 확인하는 동작 |
| Test Steps | 진행 순서 |
| Test Parameters | 정책 조건과 설정 값 |
| Test Data | 요청 대상과 전송 데이터 |
| Expected Results | 기대 결과 |
| Actual Result | 실제 결과 |

Test Steps ~ Expected Results와, PASS가 아닐 때의 Actual Result 설명은 `tests/case_descriptions.yaml`에
있습니다. 케이스를 추가하면 이 파일에도 항목을 추가합니다.

---

## 문제 해결

| 증상 | 확인 |
| --- | --- |
| 종료 코드 7 (preflight) | 커넥터가 켜져 있고 그 워크스페이스에 로그인돼 있는지, 대상 호스트를 막는 다른 정책이 없는지 |
| GraphQL 케이스가 `Duplicate login`으로 실패 | 같은 계정의 다른 로그인이 세션을 대체한 것. `bat login` |
| 모든 요청이 403 + HTML | SSE 차단 페이지. `bat sweep --delete` 후 다시 실행 |
| 이벤트가 안 잡힘 | 로그 조회는 UTC 기준. `bat traffic`으로 트래픽 경로 확인 |
