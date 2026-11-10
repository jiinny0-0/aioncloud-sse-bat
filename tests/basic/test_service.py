"""서비스 점검: 서버 다운과 기준선("다 막아버림").

배포 직후 가장 먼저 봐야 하는 두 가지다. `bat run`이 다른 케이스보다 먼저(run_start)
그리고 모든 케이스와 정리가 끝난 뒤에(run_end) 따로 돌린다. --product로 일부 제품만 돌려도
항상 돈다.

BAT-BASIC-007  콘솔 웹·REST·GraphQL이 응답하는가. 연결 실패·타임아웃·5xx면 FAIL,
               인증·설정 문제면 BAT_ERROR.
BAT-BASIC-008  실행 처음, BAT 정책이 없는 상태에서 일반 대상이 정상 응답하는가.
BAT-BASIC-009  실행 마지막, 모든 BAT 정책을 지운 뒤에도 일반 대상이 정상 응답하는가.
               정리 뒤에도 막혀 있으면 정책 삭제가 반영되지 않은 것이다.
기준선은 전부 막히면 FAIL, 일부만 막히면 WARN, 커넥터가 꺼져 있거나 curl이 요청을 보내지 못했으면
(사용법 오류, 실행 파일 없음) BAT_ERROR다.
"""
from __future__ import annotations

import logging
import time

import pytest

from bat.endpoint.base import connector_state
from bat.fixtures.naming import is_bat_resource
from bat.fixtures.testdata import ECHO_HOSTS
from bat.health import (
    ALL_FAILED,
    DOWN,
    OK,
    PARTIAL,
    PASS_ALL,
    USER_POLICY,
    BaselineOutcome,
    judge_baseline,
    probe_servers,
)
from bat.models import Kind, Step
from bat.verdict import MinorFailure
from tests.support import (
    CurlToolError,
    block_page_rule,
    environment_error,
    fetch_page,
    pass_case,
    unverified,
)

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.product("basic"),
    pytest.mark.lane("b"),
    pytest.mark.xdist_group("lane-b"),
]

# 실행 처음엔 정상 상태를 한 번 확인하면 되지만, 마지막엔 직전에 지운 정책이 전파될 시간을 준다.
START_BUDGET_SEC = 10
RETRY_GAP_SEC = 3


@pytest.mark.case("BAT-BASIC-007")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P0")
@pytest.mark.gate
@pytest.mark.run_start
def test_management_servers_answer(case, run_context, lane):
    """콘솔 웹·Open API(REST)·콘솔 GraphQL 서버가 응답한다(서버 다운 감지)."""
    probes = probe_servers(run_context.profile, lane.workspace)
    for probe in probes:
        case.record(
            Step.ACTION, ok=probe.state == OK, kind=Kind.EVIDENCE,
            detail=f"{probe.name}: {probe.state} - {probe.detail}",
        )
    down = [p for p in probes if p.state == DOWN]
    summary = "; ".join(f"{p.name} {p.state}: {p.detail}" for p in probes)
    case.record(
        Step.USER_RESULT, ok=not down, kind=Kind.ASSERTION,
        detail=summary, expected="console, REST and GraphQL answer", actual=[f"{p.name}={p.state}" for p in probes],
    )
    assert not down, f"server down: {', '.join(p.name for p in down)} — {summary}"
    config = [p for p in probes if p.state != OK]
    if config:
        environment_error(f"servers are up, but BAT cannot use them (auth/config): {summary}")
    pass_case(case)


def _check_targets(case, run_context, executor, phase: str, budget_sec: float) -> None:
    process = run_context.profile.connector_process
    state = connector_state(executor, process)
    if state.lower() != "running":
        environment_error(f"{process} is {state}; the baseline needs traffic through the connector")

    outcomes = []
    for host in ECHO_HOSTS:
        url = f"https://{host}/get?bat=baseline-{phase}-{run_context.run_id}"
        deadline = time.monotonic() + budget_sec
        while True:
            try:
                traffic, body = fetch_page(executor, url)
            except CurlToolError as exc:
                # 요청을 보내지도 못했으니 제품 응답이 하나도 없다: 판정 근거가 없는 BAT 쪽 문제다.
                environment_error(f"the baseline request to {host} was never sent: {exc}")
            if traffic.delivered or time.monotonic() >= deadline:
                break
            time.sleep(RETRY_GAP_SEC)
        rule = block_page_rule(body) if traffic.blocked else ""
        outcomes.append(BaselineOutcome(host, traffic.delivered, traffic.detail, rule))
        case.record(
            Step.ACTION, ok=traffic.delivered, kind=Kind.EVIDENCE,
            detail=f"{url}: {traffic.detail}" + (f", block page names {rule!r}" if rule else ""),
        )

    verdict, summary = judge_baseline(outcomes, is_bat_resource)
    if verdict == USER_POLICY:
        unverified(case, Step.USER_RESULT,
                   f"every target was blocked, but by a policy that is not BAT's: {summary}")
    case.record(
        Step.USER_RESULT, ok=verdict == PASS_ALL, kind=Kind.ASSERTION, detail=summary,
        expected="every target answers normally with no BAT policy in place",
        actual=[f"{o.target}: {o.detail}" for o in outcomes],
    )
    if verdict == PARTIAL:
        raise MinorFailure(f"some targets failed with no BAT policy in place: {summary}",
                           "only some baseline targets failed")
    assert verdict != ALL_FAILED, f"every target is blocked or unreachable with no BAT policy in place: {summary}"
    pass_case(case)


@pytest.mark.case("BAT-BASIC-008")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P0")
@pytest.mark.gate
@pytest.mark.run_start
def test_baseline_traffic_passes_before_the_run(case, run_context, executor):
    """실행 처음, BAT 정책이 없는 상태에서 일반 대상 요청이 정상 응답한다(다 막아버림 감지)."""
    _check_targets(case, run_context, executor, "start", START_BUDGET_SEC)


@pytest.mark.case("BAT-BASIC-009")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P0")
@pytest.mark.gate
@pytest.mark.run_end
def test_baseline_traffic_passes_after_cleanup(case, run_context, executor):
    """실행 마지막, 모든 BAT 정책을 지운 뒤에도 일반 대상 요청이 정상 응답한다(정책 삭제 미반영 감지)."""
    _check_targets(case, run_context, executor, "end", run_context.policy_propagation_timeout_sec + 10)
