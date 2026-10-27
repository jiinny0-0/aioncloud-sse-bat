"""실행 전 점검: 각 단말의 트래픽이 실제로 테스트 대상 워크스페이스에 도착하는가?

커넥터가 다른 워크스페이스에 로그인돼 있어도 터널은 돌고 로그 API도 응답하므로,
다른 점검으로는 알아채지 못한다. 그래서 `bat run`은 테스트 호스트 하나에 LOGGING
정책을 만들고, 단말에서 마커를 단 요청을 보내고, 이 워크스페이스의 보안로그에 그
정책의 이벤트가 찍히기를 기다린다. 호스트 하나에 건 LOGGING은 아무것도 막지 않고
러너를 잠그지도 않는다. 이벤트가 끝내 안 나오면 실행을 멈춘다.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Callable

log = logging.getLogger(__name__)

PREFLIGHT_CASE = "BAT-BASIC-004"
TIMEOUT_SEC = 60
INTERVAL_SEC = 5


@dataclass
class PreflightResult:
    workspace: str
    endpoint: str
    ok: bool
    detail: str


def traffic_reaches(policies, executor, web_log, policy_name: str, host: str, *,
                    timeout_sec: float = TIMEOUT_SEC, interval_sec: float = INTERVAL_SEC,
                    sleep: Callable[[float], None] = time.sleep,
                    clock: Callable[[], float] = time.monotonic) -> tuple[bool, str]:
    """`host`에 LOGGING 정책을 만들고, 마커를 단 요청을 보내고, 그 이벤트를 기다린다.

    정책 자체가 전파되는 데 시간이 걸리므로 `interval_sec`마다 요청을 다시 보낸다.
    정책은 결과와 상관없이 지워진다(temporary()).
    """
    from bat.events.web_log import matches_policy
    from bat.fixtures.enums import Condition, RiskLevel, Subject
    from bat.fixtures.policies import WebPolicyFactory
    from bat.traffic.http import curl_status

    rule = WebPolicyFactory.build_rule(Subject.HTTP_HOST, Condition.IS, [host])
    match = matches_policy(policy_name)
    marker = f"bat={policy_name.lower()}-"
    with policies.temporary(policy_name, [rule], action_type="LOGGING", risk_level=RiskLevel.MINOR):
        began = clock()
        sent = 0
        while True:
            traffic = curl_status(executor, f"https://{host}/get?{marker}{sent + 1}")
            sent += 1
            events = web_log.security_events(lookback_min=10)
            hit = next((e for e in events if match(e)), None)
            if hit is not None:
                return True, (f"event {hit.event_id} under {policy_name} after {clock() - began:.0f}s "
                              f"({sent} request(s), last HTTP {traffic.status_code})")
            if clock() - began >= timeout_sec:
                # 우리가 마커를 단 요청이 다른 정책 이름으로 기록됐다. 단말은 이
                # 워크스페이스에 있지만 그 정책이 테스트 호스트를 먼저 가져가므로,
                # 그 호스트를 쓰는 케이스는 전부 그 정책 기준으로 판정된다.
                taken = next((e for e in events if marker in str(e.get("full_uri", "request_uri") or "")
                              and e.get("policy_name") != policy_name), None)
                if taken is not None:
                    return False, (f"connected, but policy '{taken.get('policy_name')}' "
                                   f"(id {taken.get('policy_id')}, {taken.get('action')}) takes "
                                   f"{host} ahead of BAT's policies — disable it before running "
                                   f"({sent} request(s), last HTTP {traffic.status_code})")
                return False, (f"no event under {policy_name} within {timeout_sec:.0f}s "
                               f"({sent} request(s), last HTTP {traffic.status_code})")
            sleep(interval_sec)


def check(context, run_id: str) -> list[PreflightResult]:
    """실행의 레인이 쓰는 (워크스페이스, 단말) 쌍마다 점검을 하나씩 한다."""
    from bat.cli import _console_for, _rest_for
    from bat.endpoint.base import build_executor
    from bat.events.web_log import WebLogReader
    from bat.fixtures.naming import resource_name
    from bat.fixtures.policies import WebPolicyFactory
    from bat.fixtures.testdata import BLOCK_TARGET_HOST
    from bat.scheduler import build_lanes
    from bat.settings import env

    results, seen = [], set()
    for lane in build_lanes(context):
        if not lane.endpoint or (lane.workspace.name, lane.endpoint.name) in seen:
            continue
        seen.add((lane.workspace.name, lane.endpoint.name))
        name = resource_name(PREFLIGHT_CASE, run_id, f"preflight-{lane.name}")
        try:
            executor = build_executor(lane.endpoint, username=env("BAT_ENDPOINT_USER"),
                                      password=env("BAT_ENDPOINT_PASSWORD"))
            with _rest_for(context, lane.workspace) as rest, _console_for(context, lane.workspace) as gql:
                ok, detail = traffic_reaches(WebPolicyFactory(rest), executor, WebLogReader(gql),
                                             name, BLOCK_TARGET_HOST)
        except Exception as exc:  # noqa: BLE001 - 여기서 무엇이 실패하든 "동작이 확인되지 않음"을 뜻한다
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        results.append(PreflightResult(lane.workspace.name, lane.endpoint.name, ok, detail))
    return results
