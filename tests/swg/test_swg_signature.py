"""SWG 시그니처 모듈 케이스.

시그니처 모듈은 값 목록 없는 스위치라 실제 트래픽에서만 동작이 드러난다.
"""
from __future__ import annotations

import pytest

from bat.fixtures.enums import ActionType, RiskLevel, Subject
from bat.fixtures.naming import resource_name
from bat.fixtures.policies import CleanupWarning, WebPolicyFactory
from bat.fixtures.testdata import BLOCK_TARGET_HOST, PUBLIC_PROXY_LIST_URL
from bat.models import Step
from bat.traffic.http import find_live_proxies
from tests.support import (
    await_security_event,
    cleanup_failed,
    curl_until_blocked,
    module_scope_or_stop,
    pass_case,
    record_identity,
    unverified,
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
    """공개 프록시 차단 시그니처를 켜면 프록시 경유 요청이 실제로 차단된다.

    공개 프록시 자신도 403을 돌려줄 수 있으므로, 응답 본문에 SSE 차단 페이지 문구
    (profile.block_page_marker)가 있어야 차단으로 센다.
    """
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
                    executor, proxy_probe_url, budget, proxy=candidate,
                    block_text=run_context.profile.block_page_marker,
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
