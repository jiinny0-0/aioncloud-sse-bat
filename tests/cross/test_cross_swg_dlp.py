"""SWG + DLP 제품 간 cross 케이스.

넓은 HTTP_HOST ALLOW를 DLP 연결 BLOCK 정책보다 위에 두고, 그것이 조용한 DLP 사각지대를
만드는지 확인한다. 모든 페이로드는 합성값이다.
"""
from __future__ import annotations

import pytest

from bat.fixtures.enums import ActionType, Condition, RiskLevel, Subject
from bat.fixtures.naming import resource_name
from bat.fixtures.policies import CleanupWarning, DlpPolicyFactory, WebPolicyFactory
from bat.fixtures.testdata import BLOCK_TARGET_HOST, POST_TARGET_URL, keyword_payload, marker
from bat.models import Step
from bat.traffic.http import curl_status
from tests.support import (
    await_security_event,
    cleanup_failed,
    curl_until_blocked,
    expect_hold,
    hold_after_change,
    marked_url,
    pass_case,
    policy_changed,
)

pytestmark = [
    pytest.mark.product("cross"),
    pytest.mark.lane("b"),
    pytest.mark.xdist_group("lane-b"),
]


@pytest.mark.case("BAT-X-001")
@pytest.mark.known_issue(
    "우선순위 높은 ALLOW가 DLP 차단을 무력화함",
    match=r"A higher-priority ALLOW policy on \S+ let the DLP-flagged payload through",
)
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_dlp_block_survives_a_higher_priority_allow(
    case, run_context, rest, web_policies, executor, web_log
):
    """DLP 탐지로 걸리는 웹정책보다 우선순위 높은 ALLOW가 있어도 DLP 차단은 유지된다."""
    dlp = DlpPolicyFactory(rest)
    token = marker(case.case_id, run_context.run_id)
    dlp_name = resource_name(case.case_id, run_context.run_id, "dlp")
    block_name = resource_name(case.case_id, run_context.run_id, "block")
    allow_name = resource_name(case.case_id, run_context.run_id, "allow")

    try:
        with dlp.temporary(
            dlp_name, [DlpPolicyFactory.keyword_rule("bat-token", [token])]
        ) as rule:
            case.policy_ids.append(f"dlp:{rule.policy_id}")

            with web_policies.temporary(
                block_name,
                [WebPolicyFactory.dlp_rule(rule.policy_id)],
                action_type=ActionType.BLOCK,
                risk_level=RiskLevel.MAJOR,
            ) as blocker:
                case.policy_ids.append(blocker.policy_id)

                # 먼저 DLP 연결 정책이 단독으로 막는지 증명한다. 아니면 우선순위
                # 부분은 아무것도 증명하지 못한다.
                blocked = curl_until_blocked(
                    executor,
                    POST_TARGET_URL,
                    run_context.policy_propagation_timeout_sec,
                    method="POST",
                    data=keyword_payload(token),
                )
                assert blocked.blocked, (
                    "The DLP-linked policy never took effect on its own, so testing "
                    "it against a higher-priority ALLOW would prove nothing"
                )

                allow_rule = WebPolicyFactory.build_rule(
                    Subject.HTTP_HOST, Condition.IS, [BLOCK_TARGET_HOST]
                )
                with web_policies.temporary(
                    allow_name, [allow_rule], action_type=ActionType.ALLOW
                ) as allower:
                    case.policy_ids.append(allower.policy_id)
                    # 가장 작은 번호가 먼저 평가된다.
                    web_policies.set_priority(
                        [(allower.policy_id, 1), (blocker.policy_id, 2)]
                    )
                    change = policy_changed(case, "ALLOW raised above the DLP-linked BLOCK")

                    # 이미 막고 있던 상태라 변경 직후의 첫 403은 아무것도 증명하지 않는다.
                    # 전파 예산이 지난 뒤에도 연속해서 막혀야 하고, 이벤트는 그 마지막
                    # 요청(마커) 자신의 행이어야 한다.
                    sent: list[str] = []

                    def check():
                        url = marked_url(POST_TARGET_URL, case, run_context, f"after{len(sent) + 1}")
                        sent.append(url)
                        return curl_status(executor, url, method="POST", data=keyword_payload(token))

                    hold = hold_after_change(
                        check, want=lambda t: t.blocked, against=lambda t: t.delivered,
                        changed_at=change.at, budget_sec=run_context.policy_propagation_timeout_sec,
                    )
                    expect_hold(
                        case, hold,
                        expected="blocked (DLP holds despite the higher-priority ALLOW) after the propagation budget",
                        failure=f"A higher-priority ALLOW policy on {BLOCK_TARGET_HOST} let the "
                        f"DLP-flagged payload through -- a broad ALLOW policy can create a silent DLP blind spot",
                    )

                    await_security_event(
                        case,
                        web_log,
                        block_name,
                        timeout_sec=run_context.event_poll_timeout_sec,
                        policy_id=blocker.policy_id,
                        marker_url=sent[-1],
                    )
                    pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)
