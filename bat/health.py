"""서버 다운 점검과 기준선 판정.

배포 직후 가장 큰 장애는 콘솔·관리 API가 내려간 것이다. 그런데 실패를 그냥 "실행 실패"로
끝내면 제품 장애인지 설정 문제인지 가릴 수 없다. 그래서 실패 원인을 둘로 나눈다.

DOWN    연결 실패, 타임아웃, HTTP 5xx. 제품 장애다(gate FAIL).
CONFIG  401/403, 토큰·비밀번호 오류, 설정 누락, API가 아닌 응답. BAT 쪽 문제(BAT_ERROR)다.

`bat doctor`와 BAT-BASIC-007(서버 다운 점검 케이스)이 같은 점검(probe_servers)을 쓴다.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

OK, DOWN, CONFIG = "OK", "DOWN", "CONFIG"

# bat doctor 종료 코드.
DOCTOR_OK = 0
DOCTOR_SERVER_DOWN = 20
DOCTOR_CONFIG = 21

REST_HEALTH_PATH = "/sia/v1/user/group/list"
# 로그인 없이도 스키마가 확인된 가벼운 조회(SIA.common.browser_info).
GRAPHQL_HEALTH_QUERY = "{ SIA { common { browser_info { id } } } }"


@dataclass
class Probe:
    name: str  # console / rest / graphql
    state: str  # OK / DOWN / CONFIG
    detail: str
    responded: bool = True  # False: 연결 실패·타임아웃처럼 서버에서 아무 응답도 못 받음


def classify_failure(exc: BaseException) -> str:
    """점검 요청이 던진 예외가 제품 장애(DOWN)인지 BAT 쪽 문제(CONFIG)인지."""
    from bat.verdict import product_failure

    return DOWN if product_failure(exc) else CONFIG


def no_response(exc: BaseException) -> bool:
    """서버에서 아무 응답도 못 받은 실패인가(연결 실패, 타임아웃, 이름 해석 실패).

    이런 실패는 서버가 죽었을 수도 있고 이 PC의 네트워크가 끊겼을 수도 있다.
    5xx처럼 응답이 온 실패는 서버까지 닿은 것이라 이 PC 탓이 아니다.
    """
    import httpx

    return isinstance(exc, httpx.TransportError)


def _probe(name: str, call) -> Probe:
    try:
        detail = call()
    except Exception as exc:  # noqa: BLE001 - 무엇이 실패했는지가 점검 결과다
        return Probe(name, classify_failure(exc), f"{type(exc).__name__}: {str(exc)[:300]}",
                     responded=not no_response(exc))
    return Probe(name, OK, detail or "answered")


# -- 이 PC의 네트워크 ----------------------------------------------------------------
#
# 서버가 응답하지 않을 때 서버가 죽은 건지 이 PC의 네트워크가 끊긴 건지 가른다. 인터넷 쪽
# 요청은 전부 커넥터(SSE)를 지나므로 SSE가 죽어도 실패한다. 그래서 SSE를 지나지 않는 것,
# 즉 기본 게이트웨이(공유기·사내망 장비)가 응답하는지만 본다. ping이 막힌 게이트웨이도
# 있어서 ping 뒤 ARP 표에서 게이트웨이가 Reachable이면 살아 있는 것으로 본다.
# 사내 회선만 끊기고 LAN은 살아 있으면 구분하지 못한다(서버 다운으로 남는다).
#
# cmd.exe가 감싸는 한 줄 명령이라 큰따옴표와 줄바꿈을 쓰지 않는다.
PC_NETWORK_SCRIPT = (
    "$r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue"
    " | Where-Object { $_.NextHop -ne '0.0.0.0' }"
    " | Sort-Object { $_.RouteMetric + $_.InterfaceMetric } | Select-Object -First 1;"
    " if (-not $r) { 'NOGATEWAY' } else {"
    " $gw = $r.NextHop;"
    " $ping = [bool](Test-Connection -ComputerName $gw -Count 2 -Quiet -ErrorAction SilentlyContinue);"
    " $arp = [bool](Get-NetNeighbor -IPAddress $gw -ErrorAction SilentlyContinue"
    " | Where-Object { $_.State -in 'Reachable','Permanent' });"
    " 'GATEWAY ' + $gw + ' PING ' + $ping + ' ARP ' + $arp }"
)


@dataclass
class PcNetwork:
    ok: bool | None  # True 살아 있음, False 끊김, None 확인 못 함
    detail: str


def parse_pc_network(stdout: str) -> PcNetwork:
    import re

    text = (stdout or "").strip()
    if "NOGATEWAY" in text:
        return PcNetwork(False, "this PC has no default gateway (network adapter down or no IP)")
    match = re.search(r"GATEWAY (\S+) PING (\w+) ARP (\w+)", text)
    if not match:
        return PcNetwork(None, f"PC network check gave no usable output: {text[:200]!r}")
    gateway, ping, arp = match.group(1), match.group(2) == "True", match.group(3) == "True"
    if ping or arp:
        return PcNetwork(True, f"gateway {gateway} answers (ping {ping}, arp {arp})")
    return PcNetwork(False, f"gateway {gateway} does not answer (no ping, no ARP reply)")


def pc_network(executor) -> PcNetwork:
    """executor가 도는 PC의 네트워크(기본 게이트웨이)가 살아 있는가."""
    try:
        result = executor.run_powershell(PC_NETWORK_SCRIPT, timeout_sec=30)
    except Exception as exc:  # noqa: BLE001 - 확인 못 했다는 것만 남긴다
        return PcNetwork(None, f"PC network check failed to run: {type(exc).__name__}: {exc}"[:300])
    return parse_pc_network(result.stdout)


def runner_executor():
    """테스트 러너가 도는 이 PC에서 명령을 실행한다(관리 API 요청은 이 PC에서 나간다)."""
    from types import SimpleNamespace

    from bat.endpoint.base import LocalExecutor

    return LocalExecutor(SimpleNamespace(name="runner"))


def probe_servers(profile, workspace) -> list[Probe]:
    """콘솔 웹, REST(Open API), 콘솔 GraphQL이 응답하는지. 각자의 상태를 돌려준다."""
    import httpx

    from bat.clients.errors import ApiError
    from bat.clients.graphql import GraphQLClient
    from bat.clients.rest import RestClient
    from bat.clients.tokens import load_console_token

    def console() -> str:
        with httpx.Client(verify=profile.verify_tls, timeout=15, follow_redirects=True) as client:
            response = client.get(profile.console_url)
        if response.status_code >= 500:
            raise ApiError(f"GET {profile.console_url} -> HTTP {response.status_code}",
                           status_code=response.status_code)
        return f"HTTP {response.status_code}"

    def rest() -> str:
        token = workspace.openapi_token
        if not token:
            # 토큰은 콘솔 세션으로도 발급받으니 설정 문제가 아니다. 서버가 응답하는지만 본다.
            url = profile.rest_base_url.rstrip("/") + REST_HEALTH_PATH
            with httpx.Client(verify=profile.verify_tls, timeout=15) as client:
                response = client.get(url)
            if response.status_code >= 500:
                raise ApiError(f"GET {url} -> HTTP {response.status_code}", status_code=response.status_code)
            return f"reachable without a token (HTTP {response.status_code})"
        with RestClient(profile, token, timeout_sec=15) as client:
            client.get(REST_HEALTH_PATH, params={"offset": 1, "limit": 1})
        return f"GET {REST_HEALTH_PATH} answered"

    def graphql() -> str:
        with GraphQLClient(profile, workspace.name) as client:
            token = load_console_token(workspace.name)
            if token:
                client.use_token(token)
                client.execute(GRAPHQL_HEALTH_QUERY)
                return "query answered (cached session)"
            if not workspace.has_console_credentials:
                raise ApiError("no cached console session and no BAT_CONSOLE_USER / BAT_CONSOLE_PASSWORD")
            client.login(workspace.login_id, workspace.password)
            return "signed in"

    return [_probe("console", console), _probe("rest", rest), _probe("graphql", graphql)]


def doctor_exit_code(states: Iterable[str]) -> int:
    """하나라도 DOWN이면 20(서버 다운), 아니고 하나라도 문제가 있으면 21(설정·인증), 아니면 0."""
    states = list(states)
    if DOWN in states:
        return DOCTOR_SERVER_DOWN
    if any(state != OK for state in states):
        return DOCTOR_CONFIG
    return DOCTOR_OK


# -- 기준선 ----------------------------------------------------------------------

PASS_ALL, PARTIAL, ALL_FAILED, USER_POLICY = "pass", "partial", "all_failed", "user_policy"


@dataclass
class BaselineOutcome:
    target: str
    delivered: bool
    detail: str
    blocked_by: str = ""  # 차단 페이지가 밝힌 규칙 이름
    responded: bool = True  # False: HTTP 응답을 하나도 못 받음(curl 000)


def judge_baseline(outcomes: list[BaselineOutcome], is_bat_name) -> tuple[str, str]:
    """BAT 정책이 없는 상태에서 일반 대상에 보낸 요청들의 판정.

    전부 통과면 PASS_ALL, 일부만 막히면 PARTIAL. 전부 막혔는데 차단 페이지가 BAT가 아닌
    정책 이름을 밝히면 그 테넌트의 사용자 정책 탓이라 USER_POLICY(제품 결함 근거 없음),
    아니면 ALL_FAILED다.
    """
    failed = [o for o in outcomes if not o.delivered]
    summary = "; ".join(f"{o.target}: {o.detail}" + (f" (blocked by {o.blocked_by})" if o.blocked_by else "")
                        for o in outcomes)
    if not failed:
        return PASS_ALL, summary
    if len(failed) < len(outcomes):
        return PARTIAL, summary
    named = [o.blocked_by for o in failed if o.blocked_by]
    if named and not any(is_bat_name(name) for name in named):
        return USER_POLICY, summary
    return ALL_FAILED, summary
