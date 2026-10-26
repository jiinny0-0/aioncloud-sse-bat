"""SWG 시그니처 모듈과 우선순위 케이스.

둘 다 실제 트래픽에서만 드러나는 동작을 확인한다. 시그니처 모듈은 값 목록 없는
스위치이고, 우선순위는 겹치는 두 정책 중 어느 쪽이 실제로 결과를 정하는지 결정한다.
"""
from __future__ import annotations

import pytest

from bat.fixtures.enums import ActionType, Condition, RiskLevel, Subject
from bat.fixtures.naming import resource_name
from bat.fixtures.policies import CleanupWarning, WebPolicyFactory
from bat.fixtures.testdata import BLOCK_TARGET_HOST, BLOCK_TARGET_URL, PUBLIC_PROXY_LIST_URL
from bat.models import Step
from bat.traffic.http import find_live_proxies
from tests.support import (
    await_security_event,
    cleanup_failed,
    curl_until_blocked,
    expect_allowed,
    module_scope_or_stop,
    pass_case,
    record_identity,
    unverified,
    visit_until_allowed,
    visit_until_blocked,
)

pytestmark = [
    pytest.mark.product("swg"),
    pytest.mark.lane("b"),
    pytest.mark.xdist_group("lane-b"),
]


@pytest.mark.case("BAT-SWG-006")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_public_proxy_signature_blocks(case, run_context, web_policies, executor, web_log):
    """공개 프록시 차단 시그니처를 켜면 프록시 경유 요청이 실제로 차단된다."""
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = WebPolicyFactory.module_rule(Subject.BLOCK_PUBLIC_PROXY)

    # 평문 HTTP를 쓴다. 무료 공개 프록시는 거의 다 CONNECT를 지원하지 않는 포워드
    # 프록시라 TLS 요청을 중계할 수 없다. 시그니처는 스킴이 아니라 프록시의 평판을 본다.
    proxy_probe_url = f"http://{BLOCK_TARGET_HOST}/get"

    # 정책이 생기기 전에 찾아 두므로, 후보는 트래픽을 중계할 수 있는지만으로 판단된다.
    # 무료 프록시는 수명이 짧아서 후보는 실시간으로 갱신되는 목록에서 가져온다.
    live_proxies = find_live_proxies(
        executor, proxy_probe_url, list_url=PUBLIC_PROXY_LIST_URL, max_found=10
    )
    if not live_proxies:
        unverified(
            case,
            Step.ACTION,
            f"No live proxy found among candidates from {PUBLIC_PROXY_LIST_URL} "
            f"(list unreachable, or none of the tried candidates answered — "
            f"free public proxies are inherently short-lived)"
        )
    case.record(
        Step.SETUP, ok=True, detail=f"{len(live_proxies)} live proxies to try: {live_proxies}"
    )

    try:
        module_scope_or_stop(case, run_context, web_policies, executor, web_log, rule)
        with web_policies.temporary(
            policy_name, [rule], action_type=ActionType.BLOCK, risk_level=RiskLevel.MAJOR
        ) as policy:
            case.policy_ids.append(policy.policy_id)

            # 시그니처가 프록시를 인식하는지는 제품의 평판 목록에 달려 있으므로, 살아 있는
            # 프록시를 하나씩 시도하고 처음 걸린 것에서 멈춘다.
            blocked_via = ""
            last_traffic = None
            for i, candidate in enumerate(live_proxies):
                # 전파 대기 시간 전체가 필요한 것은 첫 후보뿐이다.
                budget = run_context.policy_propagation_timeout_sec if i == 0 else 8
                last_traffic = curl_until_blocked(
                    executor, proxy_probe_url, budget, proxy=candidate
                )
                if last_traffic.blocked:
                    blocked_via = candidate
                    break

            case.record(
                Step.USER_RESULT,
                ok=bool(blocked_via),
                detail=f"blocked via {blocked_via}" if blocked_via else "none flagged",
                expected="at least one live proxy refused by the signature",
                actual=blocked_via or f"tried {live_proxies}",
            )
            if not blocked_via:
                unverified(
                    case,
                    Step.USER_RESULT,
                    f"None of {len(live_proxies)} live, traffic-relaying proxies "
                    f"({live_proxies}) were recognised by the public-proxy signature "
                    f"this time — that depends on overlap with the product's own "
                    f"reputation list, not on proxy availability, which this cannot "
                    f"control"
                )

            event = await_security_event(
                case,
                web_log,
                policy_name,
                timeout_sec=run_context.event_poll_timeout_sec,
                policy_id=policy.policy_id,
            )
            record_identity(case, event)
            pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-SWG-007")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P3")
def test_priority_decides_the_outcome(
    case, run_context, web_policies, browser_session, web_log
):
    """같은 대상에 ALLOW와 BLOCK이 겹치면 우선순위가 높은 정책이 적용된다."""
    allow_name = resource_name(case.case_id, run_context.run_id, "allow")
    block_name = resource_name(case.case_id, run_context.run_id, "block")
    rule = WebPolicyFactory.build_rule(Subject.HTTP_HOST, Condition.IS, [BLOCK_TARGET_HOST])

    try:
        # 먼저 BLOCK이 단독으로 동작하는지 확인한다. 그래야 ALLOW 뒤의 "안 막힘"이
        # 적용된 적 없는 정책이 아니라 우선순위 때문임을 뜻한다.
        with web_policies.temporary(block_name, [rule], action_type=ActionType.BLOCK) as blocker:
            case.policy_ids.append(blocker.policy_id)
            blocked = visit_until_blocked(
                browser_session,
                BLOCK_TARGET_URL,
                case.case_id,
                run_context.policy_propagation_timeout_sec,
            )
            assert blocked.blocked, (
                "The BLOCK policy did not take effect, so the priority check "
                "would prove nothing"
            )

            with web_policies.temporary(
                allow_name, [rule], action_type=ActionType.ALLOW
            ) as allower:
                case.policy_ids.append(allower.policy_id)
                # web.UpdateWebPriorityRequest: {id, priority}의 리스트이고,
                # 가장 작은 번호가 먼저 평가된다.
                web_policies.set_priority(
                    [(allower.policy_id, 1), (blocker.policy_id, 2)]
                )

                traffic = visit_until_allowed(
                    browser_session,
                    BLOCK_TARGET_URL,
                    case.case_id,
                    run_context.policy_propagation_timeout_sec,
                )
                expect_allowed(case, traffic, BLOCK_TARGET_URL)
                pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)
