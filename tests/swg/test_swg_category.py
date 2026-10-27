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
from bat.fixtures.testdata import ECHO_HOSTS, echo_url
from bat.models import Step
from tests.support import (
    across_targets,
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
    """내장 HTTP 카테고리 조건이 실제 트래픽에 매칭되고 이벤트에 기록된다.

    대상 호스트마다(ECHO_HOSTS) 그 호스트의 카테고리로 정책을 만들어 같은 확인을 한다.
    카테고리를 알아내지 못한 호스트는 기록만 하고 빼며, 하나도 없으면 실행 조건 미비다.
    """
    targets: dict[str, dict] = {}
    for host in ECHO_HOSTS:
        category = _category_of(case, run_context, web_policies, browser_session, web_log, host)
        if category:
            targets[host] = category
    if not targets:
        environment_error(f"No category could be learned for any of {list(ECHO_HOSTS)}")

    def check(host: str) -> None:
        category, url = targets[host], echo_url(host)
        policy_name = resource_name(case.case_id, run_context.run_id, host.split(".")[0])
        rule = WebPolicyFactory.build_rule(
            Subject.HTTP_CATEGORY, Condition.IN, [str(category["id"])]
        )
        # BLOCK이 아니라 LOGGING이다. 카테고리 전체에는 관리 API 호스트가 포함될 수
        # 있고 러너는 같은 커넥터를 거쳐 그곳에 접속하므로, BLOCK은 정책을 지우는
        # 요청까지 막는다.
        with web_policies.temporary(
            policy_name, [rule], action_type="LOGGING", risk_level=RiskLevel.MINOR
        ) as policy:
            case.policy_ids.append(policy.policy_id)

            traffic = browser_session.visit(url, case_id=case.case_id)
            case.record(Step.ACTION, ok=True, detail=f"browser visited {url}")
            expect_allowed(case, traffic, url)

            event = await_security_event(
                case,
                web_log,
                policy_name,
                timeout_sec=run_context.event_poll_timeout_sec,
                expected_action="LOGGING",
                expected_target=host,
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
                detail=f"categories on the event for {host}: {names}",
                expected=f"contains {category.get('name')}",
                actual=names,
            )
            assert names, (
                f"Event {event.event_id} matched the category policy but records no "
                f"categories, so category attribution cannot be verified"
            )

    try:
        across_targets(case, list(targets), check, what="built-in category match")
        pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


def _category_of(case, run_context, web_policies, browser_session, web_log, host: str) -> dict | None:
    """probe 이벤트로 그 호스트의 카테고리를 알아낸다. 추측하면 아무것도 매칭하지 않는 정책이 된다."""
    probe_name = resource_name(case.case_id, run_context.run_id, f"probe-{host.split('.')[0]}")
    host_rule = WebPolicyFactory.build_rule(Subject.HTTP_HOST, Condition.IS, [host])
    with web_policies.temporary(
        probe_name, [host_rule], action_type="LOGGING", risk_level=RiskLevel.MINOR
    ):
        browser_session.visit(echo_url(host), case_id=case.case_id)
        try:
            probe_event = web_log.wait_for_security_event(
                matches_policy(probe_name),
                timeout_sec=run_context.event_poll_timeout_sec,
                description=f"probe event carrying the category of {host}",
            )
        except PollTimeout as timeout:
            case.record(Step.SETUP, ok=True, detail=f"{host}: category not observed ({timeout}); left out")
            return None

    categories = [
        item for item in (probe_event.get("categories") or []) if isinstance(item, dict)
    ]
    if not categories:
        case.record(Step.SETUP, ok=True, detail=f"{host}: the event carries no categories; left out")
        return None
    category = categories[0]
    case.record(
        Step.SETUP,
        ok=True,
        detail=f"{host} is categorised as {category.get('name')} (id={category.get('id')})",
    )
    return category


@pytest.mark.case("BAT-SWG-005")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_custom_category_block(case, run_context, rest, web_policies, browser_session, web_log):
    """직접 만든 카테고리에 URL을 등록하면 그 카테고리 정책으로 차단된다.

    대상 호스트마다(ECHO_HOSTS) 카테고리·user rule·정책을 하나씩 만들어 같은 확인을 한다.
    """
    categories = CustomCategoryFactory(rest)
    user_rules = UserRuleFactory(rest)

    def check(host: str) -> None:
        label = host.split(".")[0]
        url = echo_url(host)
        category_name = resource_name(case.case_id, run_context.run_id, f"cat-{label}")
        policy_name = resource_name(case.case_id, run_context.run_id, label)
        with categories.temporary(category_name) as category:
            case.policy_ids.append(f"category:{category.policy_id}")

            with user_rules.temporary(
                category.policy_id, [UserRuleFactory.rule(host)]
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
                        browser_session, url, case.case_id,
                        run_context.policy_propagation_timeout_sec,
                    )
                    expect_block(case, traffic, url)

                    await_security_event(
                        case,
                        web_log,
                        policy_name,
                        timeout_sec=run_context.event_poll_timeout_sec,
                        expected_target=host,
                        policy_id=policy.policy_id,
                    )

    try:
        across_targets(case, ECHO_HOSTS, check, what="custom category block")
        pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)
