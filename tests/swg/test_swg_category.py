"""SWG 카테고리 케이스.

카테고리 정책은 호스트 정책보다 움직이는 부분이 하나 더 있다. 카테고리가 있어야
하고, URL이 그 카테고리에 배정돼야 하며, 그래야 정책이 그것으로 매칭할 수 있다.
이 케이스들은 그 연결 전체가 실제 트래픽까지 이어지는지 확인한다.
"""
from __future__ import annotations

import pytest

from bat.events.poller import PollTimeout
from bat.events.web_log import matches_policy
from bat.fixtures.categories import CustomCategoryFactory, UserRuleFactory
from bat.fixtures.enums import ActionType, Condition, RiskLevel, Subject
from bat.fixtures.naming import resource_name
from bat.fixtures.policies import CleanupWarning, WebPolicyFactory
from bat.fixtures.testdata import BLOCK_TARGET_HOST, BLOCK_TARGET_URL
from bat.models import Step
from tests.support import (
    await_security_event,
    cleanup_failed,
    environment_error,
    expect_allowed,
    expect_block,
    pass_case,
    visit_until_blocked,
)

pytestmark = [
    pytest.mark.product("swg"),
    pytest.mark.lane("b"),
    pytest.mark.xdist_group("lane-b"),
]


@pytest.mark.case("BAT-SWG-003")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P0")
@pytest.mark.critical
def test_builtin_category_matches_traffic(
    case, run_context, web_policies, browser_session, web_log
):
    """내장 HTTP 카테고리 조건이 실제 트래픽에 매칭되고 이벤트에 기록된다."""
    # 대상의 카테고리를 추측하지 않고 probe 이벤트로 알아낸다. 잘못 추측하면
    # 아무것도 매칭하지 않는 정책이 된다.
    probe_name = resource_name(case.case_id, run_context.run_id, "probe")
    host_rule = WebPolicyFactory.build_rule(
        Subject.HTTP_HOST, Condition.IS, [BLOCK_TARGET_HOST]
    )

    with web_policies.temporary(
        probe_name, [host_rule], action_type="LOGGING", risk_level=RiskLevel.MINOR
    ):
        browser_session.visit(BLOCK_TARGET_URL, case_id=case.case_id)
        try:
            probe_event = web_log.wait_for_security_event(
                matches_policy(probe_name),
                timeout_sec=run_context.event_poll_timeout_sec,
                description="probe event carrying the target's category",
            )
        except PollTimeout as timeout:
            environment_error(
                f"Could not observe {BLOCK_TARGET_HOST} to learn its category: {timeout}"
            )

    categories = [
        item for item in (probe_event.get("categories") or []) if isinstance(item, dict)
    ]
    if not categories:
        environment_error(
            f"The event for {BLOCK_TARGET_HOST} carries no categories, so a category "
            f"policy cannot be targeted at it"
        )

    category = categories[0]
    case.record(
        Step.SETUP,
        ok=True,
        detail=f"{BLOCK_TARGET_HOST} is categorised as "
        f"{category.get('name')} (id={category.get('id')})",
    )

    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = WebPolicyFactory.build_rule(
        Subject.HTTP_CATEGORY, Condition.IN, [str(category["id"])]
    )

    try:
        # BLOCK이 아니라 LOGGING이다. 카테고리 전체에는 관리 API 호스트가 포함될 수
        # 있고 러너는 같은 커넥터를 거쳐 그곳에 접속하므로, BLOCK은 정책을 지우는
        # 요청까지 막는다.
        with web_policies.temporary(
            policy_name, [rule], action_type="LOGGING", risk_level=RiskLevel.MINOR
        ) as policy:
            case.policy_ids.append(policy.policy_id)

            traffic = browser_session.visit(BLOCK_TARGET_URL, case_id=case.case_id)
            case.record(Step.ACTION, ok=True, detail=f"browser visited {BLOCK_TARGET_URL}")
            expect_allowed(case, traffic, BLOCK_TARGET_URL)

            event = await_security_event(
                case,
                web_log,
                policy_name,
                timeout_sec=run_context.event_poll_timeout_sec,
                expected_action="LOGGING",
                expected_target=BLOCK_TARGET_HOST,
                # 카테고리가 관리 API 호스트도 덮으므로, 이 정책 이름을 단 가장 최근
                # 이벤트는 러너 자신의 트래픽인 경우가 많다.
                target_in_search=True,
                policy_id=policy.policy_id,
            )

            names = [
                str(item.get("name", ""))
                for item in (event.get("categories") or [])
                if isinstance(item, dict)
            ]
            case.record(
                Step.EVENT,
                ok=bool(names),
                detail=f"categories on the event: {names}",
                expected=f"contains {category.get('name')}",
                actual=names,
            )
            assert names, (
                f"Event {event.event_id} matched the category policy but records no "
                f"categories, so category attribution cannot be verified"
            )
            pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-SWG-005")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_custom_category_block(case, run_context, rest, web_policies, browser_session, web_log):
    """직접 만든 카테고리에 URL을 등록하면 그 카테고리 정책으로 차단된다."""
    categories = CustomCategoryFactory(rest)
    user_rules = UserRuleFactory(rest)

    category_name = resource_name(case.case_id, run_context.run_id, "cat")
    policy_name = resource_name(case.case_id, run_context.run_id)

    try:
        with categories.temporary(category_name) as category:
            case.policy_ids.append(f"category:{category.policy_id}")

            with user_rules.temporary(
                category.policy_id, [UserRuleFactory.rule(BLOCK_TARGET_HOST)]
            ) as user_rule:
                case.policy_ids.append(f"rule:{user_rule.policy_id}")

                rule = WebPolicyFactory.build_rule(
                    Subject.HTTP_CATEGORY, Condition.IN, [str(category.policy_id)]
                )
                with web_policies.temporary(
                    policy_name, [rule], action_type=ActionType.BLOCK
                ) as policy:
                    case.policy_ids.append(policy.policy_id)

                    traffic = visit_until_blocked(
                        browser_session,
                        BLOCK_TARGET_URL,
                        case.case_id,
                        run_context.policy_propagation_timeout_sec,
                    )
                    expect_block(case, traffic, BLOCK_TARGET_URL)

                    await_security_event(
                        case,
                        web_log,
                        policy_name,
                        timeout_sec=run_context.event_poll_timeout_sec,
                        expected_target=BLOCK_TARGET_HOST,
                        policy_id=policy.policy_id,
                    )
                    pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)
