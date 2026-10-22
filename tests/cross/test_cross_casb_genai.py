"""트래픽을 애플리케이션으로 분류하는 두 제품의 cross 케이스.

CASB와 GenAI는 요청이 어디로 가는지가 아니라 무엇인지를 판단하므로 웹정책 계층과
겹친다. 이 케이스들은 둘이 같은 요청에 함께 적용될 때 어떻게 되는지 확인한다.
"""
from __future__ import annotations

import pytest

from bat.fixtures.enums import ActionType, Condition, Subject
from bat.fixtures.naming import resource_name
from bat.fixtures.policies import CleanupWarning, WebPolicyFactory
from bat.fixtures.testdata import (
    CASB_SAAS_APP_ID,
    CASB_SAAS_APP_NAME,
    CASB_SAAS_HOST,
    CASB_SAAS_URL,
)
from bat.models import Step
from tests.support import (
    await_security_event,
    cleanup_failed,
    expect_casb_block,
    pass_case,
    policy_changed,
    visit_until_blocked,
)

pytestmark = [
    pytest.mark.product("cross"),
    pytest.mark.lane("d"),
    pytest.mark.xdist_group("lane-d"),
]


@pytest.mark.case("BAT-X-006")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_casb_block_survives_a_higher_priority_web_allow(
    case, run_context, web_policies, saas_access, browser_session, casb_log
):
    """CASB 앱 차단은 같은 호스트를 허용하는 우선순위 높은 웹정책이 있어도 유지된다.

    판정은 BAT-CASB-004와 같다(화면 차단과 그 요청의 BLOCK 행). 전파 예산은 ALLOW를
    우선순위 1로 올린 시각부터 재고, CASB 정책 생성 시각도 리포트에 남긴다.
    """
    allow_name = resource_name(case.case_id, run_context.run_id, "allow")
    block_name = resource_name(case.case_id, run_context.run_id, "casb")
    allow_rule = WebPolicyFactory.build_rule(Subject.HTTP_HOST, Condition.IS, [CASB_SAAS_HOST])

    try:
        with saas_access.temporary(
            block_name, [CASB_SAAS_APP_ID], action_type="BLOCK", risk_level="Major"
        ) as blocker:
            casb_created = policy_changed(case, f"SaaS Access BLOCK {block_name} created")
            case.policy_ids.append(blocker.policy_id)

            with web_policies.temporary(
                allow_name, [allow_rule], action_type=ActionType.ALLOW
            ) as allower:
                case.policy_ids.append(allower.policy_id)
                web_policies.set_priority([(allower.policy_id, 1)])
                raised = policy_changed(case, f"web ALLOW {allow_name} raised to priority 1")
                case.record(
                    Step.SETUP,
                    ok=True,
                    detail=f"web ALLOW on {CASB_SAAS_HOST} at priority 1, "
                    f"CASB BLOCK on {CASB_SAAS_APP_NAME}",
                )

                expect_casb_block(
                    case,
                    browser_session,
                    casb_log,
                    block_name,
                    CASB_SAAS_URL,
                    changed=raised,
                    created=casb_created,
                    propagation_timeout_sec=run_context.policy_propagation_timeout_sec,
                    event_timeout_sec=run_context.event_poll_timeout_sec,
                    expected_service=CASB_SAAS_APP_NAME,
                    failure=f"A higher-priority web ALLOW on {CASB_SAAS_HOST} got past the "
                    f"CASB block -- as with BAT-X-001, a broad ALLOW policy can silently "
                    f"disable another product's enforcement",
                )
                pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-X-009")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P2")
def test_web_policy_blocks_a_genai_host_that_genai_policies_cannot(
    case, run_context, web_policies, browser_session, web_log
):
    """GenAI 정책이 못 막는 AI 서비스도 웹정책 호스트 차단으로는 막힌다.

    GenAI 정책은 프롬프트 내용을 검사할 뿐 페이지 접속은 막지 않는다. 차단과 이벤트는
    웹 계층(웹 보안 로그)에서 확인한다.
    """
    policy_name = resource_name(case.case_id, run_context.run_id)
    host = "chatgpt.com"
    rule = WebPolicyFactory.build_rule(Subject.HTTP_HOST, Condition.IS, [host])

    try:
        with web_policies.temporary(
            policy_name, [rule], action_type=ActionType.BLOCK
        ) as policy:
            case.policy_ids.append(policy.policy_id)

            traffic = visit_until_blocked(
                browser_session,
                f"https://{host}/",
                case.case_id,
                run_context.policy_propagation_timeout_sec,
            )
            case.record(
                Step.USER_RESULT,
                ok=traffic.blocked,
                detail=traffic.detail,
                expected="block page",
                actual="block page" if traffic.blocked else "page rendered",
            )
            if traffic.artifact:
                case.artifacts.append(traffic.artifact)
            assert traffic.blocked, (
                f"A web policy blocking {host} did not stop the page loading, so the "
                f"web layer cannot stand in for GenAI enforcement here: {traffic.detail}"
            )

            await_security_event(
                case,
                web_log,
                policy_name,
                timeout_sec=run_context.event_poll_timeout_sec,
                expected_target=host,
                target_in_search=True,
                policy_id=policy.policy_id,
            )
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)
