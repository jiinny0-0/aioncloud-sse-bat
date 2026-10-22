"""RBI 케이스.

사이트를 격리로 보내는 것은 웹 정책 필드가 아니라 RBI 정책 자신의 `rules`
(SPECIFIC_WEBSITE/ALL_WEBSITE)다. 격리된 방문은 `https://<isolation-host>/view?url=<jwt>`에
도착한다. rule의 subject와 condition은 GraphQL enum이라 `RbiPolicyFactory.website_rule()`이
따옴표 없이 렌더링한다.
"""
from __future__ import annotations

import pytest

from bat.fixtures.naming import resource_name
from bat.fixtures.policies import CleanupWarning, RbiPolicyFactory
from bat.fixtures.testdata import BLOCK_TARGET_HOST, BLOCK_TARGET_URL
from bat.models import Step
from tests.support import (
    cleanup_failed,
    expect_delivered,
    pass_case,
    visit_until_isolated,
    visit_until_not_isolated,
)

pytestmark = [
    pytest.mark.product("rbi"),
    pytest.mark.lane("c"),
    pytest.mark.xdist_group("lane-c"),
    # 보류: 기본 실행과 현황 엑셀에서 빠진다.
    pytest.mark.parked,
]


@pytest.fixture
def rbi_policies(console) -> RbiPolicyFactory:
    return RbiPolicyFactory(console)


#: rb_options 다섯 필드 전부. 모든 필드가 "OFF"면 아무 효과가 없는 값이다.
KNOWN_RB_OPTIONS_SHAPE = {"print": "OFF", "watermark": "OFF", "clip": "OFF", "dn": "OFF", "up": "OFF"}


@pytest.fixture
def rb_options_shape() -> dict:
    """모든 옵션을 끈 rb_options."""
    return dict(KNOWN_RB_OPTIONS_SHAPE)


@pytest.mark.case("BAT-RBI-002")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P2")
@pytest.mark.smoke
def test_rbi_policies_are_readable(case, console):
    """RBI 정책 목록을 조회할 수 있다."""
    from bat.fixtures.graphql_policies import RbiPolicyReader

    rows = RbiPolicyReader(console).list()
    case.record(
        Step.USER_RESULT,
        ok=isinstance(rows, list),
        detail=f"{len(rows)} policy/policies; fields: "
        f"{sorted(rows[0]) if rows else '(none to inspect)'}",
        expected="a list",
        actual=type(rows).__name__,
    )
    assert isinstance(rows, list), "No RBI policy list could be read"
    pass_case(case)


@pytest.mark.case("BAT-RBI-001")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P0")
@pytest.mark.critical
def test_specific_website_rule_isolates_the_site(
    case, run_context, rbi_policies, browser_session, rb_options_shape
):
    """RBI 정책에 특정 사이트를 지정하면 실제로 격리 세션으로 렌더링된다."""
    rbi_name = resource_name(case.case_id, run_context.run_id, "rbi")
    rule = RbiPolicyFactory.website_rule([BLOCK_TARGET_HOST])

    try:
        with rbi_policies.temporary(
            rbi_name, [rule], rb_options=rb_options_shape, users=[0], user_groups=[0]
        ) as rbi:
            case.policy_ids.append(f"rbi:{rbi.policy_id}")
            case.record(
                Step.SETUP,
                ok=True,
                detail=f"RBI policy {rbi_name} scoped to {BLOCK_TARGET_HOST}",
            )

            traffic = visit_until_isolated(
                browser_session,
                BLOCK_TARGET_URL,
                case.case_id,
                run_context.policy_propagation_timeout_sec,
            )
            case.record(
                Step.USER_RESULT,
                ok=traffic.isolated,
                detail=traffic.detail,
                expected="landed on the isolation host, not the origin",
                actual=traffic.detail,
            )
            assert traffic.isolated, (
                f"Visiting {BLOCK_TARGET_URL} under an RBI rule did not redirect to an "
                f"isolation host ({traffic.detail}) — the site rendered directly"
            )
            pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-X-004")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P2")
def test_removing_the_rule_restores_direct_access(
    case, run_context, rbi_policies, browser_session, rb_options_shape
):
    """RBI 정책을 지우면 같은 사이트가 다시 직접 렌더링된다."""
    rbi_name = resource_name(case.case_id, run_context.run_id, "rbi")
    rule = RbiPolicyFactory.website_rule([BLOCK_TARGET_HOST])

    with rbi_policies.temporary(
        rbi_name, [rule], rb_options=rb_options_shape, users=[0], user_groups=[0]
    ) as rbi:
        case.policy_ids.append(f"rbi:{rbi.policy_id}")
        isolated = visit_until_isolated(
            browser_session,
            BLOCK_TARGET_URL,
            case.case_id,
            run_context.policy_propagation_timeout_sec,
        )
        assert isolated.isolated, (
            "The RBI rule never took effect, so removing it would prove nothing"
        )

    # 이 시점에는 컨텍스트 매니저가 정책을 이미 지웠다.
    direct = visit_until_not_isolated(
        browser_session,
        BLOCK_TARGET_URL,
        case.case_id,
        run_context.policy_propagation_timeout_sec,
    )
    expect_delivered(
        case,
        direct,
        expected="renders directly once the RBI rule is gone",
        failure=f"{BLOCK_TARGET_URL} is still routed through isolation after the RBI "
        f"policy was deleted",
    )
    pass_case(case)
