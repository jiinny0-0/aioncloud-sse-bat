"""트래픽 로깅과 사용자 스코프 정책 케이스.

커넥터 사용자는 설정으로 받지 않고 LOGGING 이벤트에서 알아낸다.
"""
from __future__ import annotations

import logging

import pytest

from bat.fixtures.enums import ActionType, Condition, RiskLevel, Subject
from bat.fixtures.naming import resource_name
from bat.fixtures.policies import CleanupWarning, WebPolicyFactory
from bat.fixtures.testdata import BLOCK_TARGET_HOST, BLOCK_TARGET_URL
from bat.fixtures.users import UserFactory
from bat.events.poller import PollTimeout, poll_until
from bat.events.web_log import matches_policy
from bat.models import Kind, Step
from tests.support import (
    await_security_event,
    cleanup_failed,
    environment_error,
    expect_allowed,
    expect_block,
    pass_case,
    record_identity,
    visit_until_blocked,
)

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.product("swg"),
    pytest.mark.lane("b"),
    pytest.mark.xdist_group("lane-b"),
]

LOGGING_ACTION = "LOGGING"


@pytest.mark.case("BAT-SWG-008")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P2")
@pytest.mark.critical
def test_allowed_traffic_is_logged(case, run_context, web_policies, browser_session, web_log):
    """커넥터를 켠 상태에서 허용된 트래픽도 로그에 기록되고, 사용자가 식별된다."""
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = WebPolicyFactory.build_rule(Subject.HTTP_HOST, Condition.IS, [BLOCK_TARGET_HOST])

    try:
        with web_policies.temporary(
            policy_name, [rule], action_type=LOGGING_ACTION, risk_level=RiskLevel.MINOR
        ) as policy:
            case.policy_ids.append(policy.policy_id)
            case.record(
                Step.SETUP, ok=True, detail=f"LOGGING policy {policy_name} on {BLOCK_TARGET_HOST}"
            )

            traffic = browser_session.visit(BLOCK_TARGET_URL, case_id=case.case_id)
            case.record(Step.ACTION, ok=True, detail=f"browser visited {BLOCK_TARGET_URL}")
            expect_allowed(case, traffic, BLOCK_TARGET_URL)

            event = await_security_event(
                case,
                web_log,
                policy_name,
                timeout_sec=run_context.event_poll_timeout_sec,
                expected_action=LOGGING_ACTION,
                expected_target=BLOCK_TARGET_HOST,
                policy_id=policy.policy_id,
            )
            record_identity(case, event)

            user_name = event.get("user_name")
            assert user_name, (
                "The event records no user. Traffic reached SSE but was not attributed "
                "to the signed-in connector account, so user-scoped policies cannot work."
            )
            log.info("Connector traffic is attributed to user %r", user_name)
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


def _discover_connector_user(case, run_context, web_policies, browser_session, web_log) -> dict:
    """커넥터가 어느 사용자로 로그인돼 있는지 LOGGING 이벤트로 알아낸다."""
    probe_name = resource_name(case.case_id, run_context.run_id, "probe")
    rule = WebPolicyFactory.build_rule(Subject.HTTP_HOST, Condition.IS, [BLOCK_TARGET_HOST])

    with web_policies.temporary(
        probe_name, [rule], action_type=LOGGING_ACTION, risk_level=RiskLevel.MINOR
    ):
        browser_session.visit(BLOCK_TARGET_URL, case_id=case.case_id)
        try:
            event = web_log.wait_for_security_event(
                matches_policy(probe_name),
                timeout_sec=run_context.event_poll_timeout_sec,
                description="probe event naming the connector user",
            )
        except PollTimeout as timeout:
            environment_error(
                f"Could not determine the connector user: {timeout}. "
                f"Check that the connector is connected and signed into this workspace."
            )

    user_id = event.get("user_id")
    user_name = event.get("user_name")
    if user_id in (None, ""):
        environment_error("The security event carries no user_id, so user scoping cannot be verified")
    return {"id": int(user_id), "name": user_name}


@pytest.mark.case("BAT-SWG-004")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_policy_applies_only_to_its_users(
    case, run_context, rest, web_policies, browser_session, web_log
):
    """정책에 지정한 사용자에게만 적용되고, 다른 사용자에게는 적용되지 않는다."""
    users = UserFactory(rest)

    connector_user = _discover_connector_user(
        case, run_context, web_policies, browser_session, web_log
    )
    case.user = str(connector_user["name"] or connector_user["id"])

    # 스코프 확인에는 두 번째 신원만 있으면 되므로 기존 계정을 빌린다.
    bystander_id = _find_other_user(users, exclude=connector_user["id"])
    if bystander_id is None:
        environment_error(
            "Only one user exists in this workspace, so there is no second "
            "identity to prove the policy does not reach"
        )

    case.record(
        Step.SETUP,
        ok=True,
        detail=f"connector user id={connector_user['id']}, bystander id={bystander_id}",
    )

    rule = WebPolicyFactory.build_rule(Subject.HTTP_HOST, Condition.IS, [BLOCK_TARGET_HOST])

    try:
        # 다른 사람으로 스코프했다. 우리 트래픽은 그대로 통과해야 한다.
        other_name = resource_name(case.case_id, run_context.run_id, "other")
        with web_policies.temporary(
            other_name,
            [rule],
            action_type=ActionType.BLOCK,
            users=[bystander_id],
            user_groups=[],
        ) as other_policy:
            case.policy_ids.append(other_policy.policy_id)

            traffic = browser_session.visit(BLOCK_TARGET_URL, case_id=case.case_id)
            expect_allowed(case, traffic, BLOCK_TARGET_URL)
            case.record(
                Step.USER_RESULT,
                ok=True,
                detail=f"policy scoped to user {bystander_id} did not affect "
                f"user {connector_user['id']}",
                expected="not blocked for a different user",
                actual="not blocked",
                kind=Kind.EVIDENCE,
            )

        # 이제 우리로 스코프한다. 같은 요청이 막혀야 한다.
        mine_name = resource_name(case.case_id, run_context.run_id, "mine")
        with web_policies.temporary(
            mine_name,
            [rule],
            action_type=ActionType.BLOCK,
            users=[connector_user["id"]],
            user_groups=[],
        ) as my_policy:
            case.policy_ids.append(my_policy.policy_id)

            blocked = visit_until_blocked(
                browser_session,
                BLOCK_TARGET_URL,
                case.case_id,
                run_context.policy_propagation_timeout_sec,
            )
            expect_block(case, blocked, BLOCK_TARGET_URL)

            event = await_security_event(
                case,
                web_log,
                mine_name,
                timeout_sec=run_context.event_poll_timeout_sec,
                expected_target=BLOCK_TARGET_HOST,
                policy_id=my_policy.policy_id,
            )
            assert str(event.get("user_id")) == str(connector_user["id"]), (
                f"The event names user {event.get('user_id')}, expected "
                f"{connector_user['id']}"
            )
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


def _find_other_user(users: UserFactory, *, exclude: int) -> int | None:
    """커넥터가 로그인하는 사용자가 아닌 기존 사용자를 아무나 하나 반환한다."""
    payload = users.rest.get("/sia/v1/user/all", params={"offset": 1, "limit": 200})
    rows = payload.get("users") or payload.get("items") or payload.get("list") or []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        user_id = row.get("id") or row.get("user_id")
        if user_id is not None and int(user_id) != int(exclude):
            return int(user_id)
    return None


@pytest.mark.case("BAT-SWG-009")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P1")
def test_new_user_can_be_created_and_targeted(case, run_context, rest, web_policies):
    """새로 만든 사용자를 정책 대상으로 지정할 수 있고, 삭제까지 정상 처리된다."""
    users = UserFactory(rest)
    login_id = f"bat-{case.case_id.lower()}-{run_context.run_id[-6:]}@bat.local"
    policy_name = resource_name(case.case_id, run_context.run_id)

    try:
        with users.temporary(login_id) as user:
            case.policy_ids.append(f"user:{user.user_id}")
            case.record(Step.SETUP, ok=True, detail=f"created user {login_id} (id={user.user_id})")

            fetched = users.find_by_id(user.user_id)
            assert fetched, f"User {user.user_id} was created but cannot be read back"

            rule = WebPolicyFactory.build_rule(
                Subject.HTTP_HOST, Condition.IS, [BLOCK_TARGET_HOST]
            )
            with web_policies.temporary(
                policy_name,
                [rule],
                action_type=ActionType.BLOCK,
                users=[int(user.user_id)],
                user_groups=[],
            ) as policy:
                case.policy_ids.append(policy.policy_id)

                stored = web_policies.get(policy)
                targeted = stored.get("users") or []
                case.record(
                    Step.USER_RESULT,
                    ok=int(user.user_id) in [int(u) for u in targeted if str(u).isdigit()],
                    detail=f"policy targets users {targeted}",
                    expected=[int(user.user_id)],
                    actual=targeted,
                )
                assert any(str(u) == str(user.user_id) for u in targeted), (
                    f"Policy {policy_name} was created with user {user.user_id} but stores "
                    f"{targeted}"
                )
                pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)
