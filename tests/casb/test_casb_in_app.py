"""CASB in-app control 케이스.

In-App Control의 `application` 인자는 내부가 드러나지 않는 입력 타입이라, 케이스는
testdata.CASB_IN_APP_ALL_APPS의 전체 앱 값을 쓴다. `saas_desc_id: 1`은 특정 앱이 아니라
카탈로그의 "전체 앱" 센티널이다.

앱별 카탈로그 id는 스키마에 없지만 CASB 보안로그에 `in_app_service { id name }`로
나타난다. 알려진 값은 testdata.CASB_SAAS_APPS에 있다.
"""
from __future__ import annotations

import pytest

from bat.fixtures.naming import resource_name
from bat.fixtures.policies import CleanupWarning, InAppControlFactory
from bat.events.casb_log import in_app_service_name, matches_rule
from bat.events.poller import PollTimeout, poll_until
from bat.fixtures.testdata import (
    CASB_IN_APP_ALL_APPS,
    CASB_OTHER_APP_NAME,
    CASB_OTHER_APP_URL,
    CASB_SAAS_APP_ID,
    CASB_SAAS_APP_NAME,
    CASB_SAAS_URL,
)
from bat.models import Kind, Step
from tests.support import (
    expect_values,
    row_named,
    stored,
    unverified,
    await_casb_event,
    cleanup_failed,
    expect_casb_block,
    expect_delivered,
    pass_case,
    policy_changed,
)

pytestmark = [
    pytest.mark.product("casb"),
    pytest.mark.lane("d"),
    pytest.mark.xdist_group("lane-d"),
]


@pytest.fixture
def in_app_control(console) -> InAppControlFactory:
    return InAppControlFactory(console)


@pytest.fixture
def application_shape() -> object:
    """In-App Control `application`: 콘솔의 function을 모두 단 전체 SaaS 앱."""
    return CASB_IN_APP_ALL_APPS


@pytest.mark.case("BAT-CASB-005")
@pytest.mark.diagnostic
@pytest.mark.priority("P2")
@pytest.mark.smoke
def test_in_app_control_is_readable(case, in_app_control):
    """CASB In-App Control 정책 목록을 조회할 수 있다(환경 점검, 보안 동작이 아님).

    조회가 오류 없이 답하면 통과다. 조회가 실패하면 예외로 BAT_ERROR가 된다.
    """
    from bat.fixtures.graphql_policies import InAppControlReader

    rows = InAppControlReader(in_app_control.gql).list()
    case.record(
        Step.ACTION,
        ok=True,
        kind=Kind.ASSERTION,
        detail=f"SIA.casb.in_app_control answered: {len(rows)} policy/policies; fields: "
        f"{sorted(rows[0]) if rows else '(none to inspect)'}",
        expected="the list query answers",
        actual=f"{len(rows)} row(s)",
    )
    pass_case(case)


@pytest.mark.case("BAT-CASB-001")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P1")
@pytest.mark.critical
def test_in_app_control_policy_round_trip(
    case, run_context, in_app_control, application_shape
):
    """CASB 정책을 생성하면 요청한 내용대로 저장되고, 삭제하면 사라진다.

    생성 직후 목록을 다시 읽어 action_type·risk_level이 요청값과 같은지 본다(목록에 있다는 것은
    생성이 이미 확인한다). 삭제는 팩토리가 목록에서 사라진 것까지 확인한다.
    """
    from bat.fixtures.graphql_policies import InAppControlReader

    policy_name = resource_name(case.case_id, run_context.run_id)

    try:
        with in_app_control.temporary(
            policy_name,
            application_shape,
            action_type="LOGGING",
            risk_level="Minor",
            users=[0],
            user_groups=[0],
        ) as handle:
            case.policy_ids.append(handle.policy_id)
            case.record(
                Step.SETUP,
                ok=True,
                detail=f"in-app control {policy_name} (id={handle.policy_id})",
            )

            row = row_named(InAppControlReader(in_app_control.gql).list(), policy_name)
            expect_values(case, f"in-app control {policy_name} as read back", {
                "action_type": ("LOGGING", stored(row, "action_type")),
                "risk_level": ("Minor", stored(row, "risk_level")),
            })
            pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-CASB-002")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P1")
def test_saas_access_policy_round_trip(case, run_context, saas_access):
    """CASB SaaS Access 정책을 생성하면 요청한 내용대로 저장되고, 삭제하면 사라진다.

    생성 직후 목록을 다시 읽어 action_type·risk_level·application(앱 id)이 요청값과 같은지 본다.
    application이 객체로 읽히면 saas_desc_id(없으면 id)를 앱 id로 본다.
    """
    policy_name = resource_name(case.case_id, run_context.run_id)

    try:
        with saas_access.temporary(
            policy_name,
            [CASB_SAAS_APP_ID],
            action_type="LOGGING",
            risk_level="Minor",
        ) as handle:
            case.policy_ids.append(handle.policy_id)
            case.record(
                Step.SETUP,
                ok=True,
                detail=f"saas access {policy_name} (id={handle.policy_id}, "
                f"application=[{CASB_SAAS_APP_ID}])",
            )

            row = row_named(saas_access.list(), policy_name)
            apps = stored(row, "application")
            if isinstance(apps, list):
                apps = [a.get("saas_desc_id", a.get("id")) if isinstance(a, dict) else a for a in apps]
            expect_values(case, f"SaaS Access {policy_name} as read back", {
                "action_type": ("LOGGING", stored(row, "action_type")),
                "risk_level": ("Minor", stored(row, "risk_level")),
                "application": ([CASB_SAAS_APP_ID], apps),
            })
            pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-CASB-003")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_saas_access_detects_only_the_app_it_names(
    case, run_context, saas_access, browser_session, casb_log
):
    """CASB SaaS Access가 지정한 SaaS 앱만 탐지하고 다른 앱은 건드리지 않는다.

    한 앱으로 좁힌 정책을 걸고 그 앱과 다른 앱을 둘 다 방문한다. 두 방문 모두 렌더링돼야 하고
    (LOGGING), 그 앱의 행이 남아야 한다. 다른 앱의 행이 없다는 판정은 그 뒤에 보낸 표지 방문
    (그 앱)의 새 행이 나타난 다음에 한다. CASB 앱 분류는 curl이 아니라 실제 브라우저 방문에만
    걸린다.
    """
    policy_name = resource_name(case.case_id, run_context.run_id)

    try:
        with saas_access.temporary(
            policy_name, [CASB_SAAS_APP_ID], action_type="LOGGING", risk_level="Minor"
        ) as policy:
            case.policy_ids.append(policy.policy_id)
            case.record(
                Step.SETUP,
                ok=True,
                detail=f"saas access scoped to {CASB_SAAS_APP_NAME} (id={CASB_SAAS_APP_ID})",
            )

            traffic = browser_session.visit(CASB_SAAS_URL, case_id=case.case_id)
            other = browser_session.visit(CASB_OTHER_APP_URL, case_id=case.case_id)
            # fatal=False: 여기서 차단되면 실패로 기록은 되지만, 아래 이벤트 검사는
            # 그대로 실행된다.
            expect_delivered(
                case,
                traffic,
                expected="page rendered (LOGGING does not block)",
                failure=f"A LOGGING policy blocked {CASB_SAAS_URL}",
                fatal=False,
            )
            expect_delivered(
                case,
                other,
                expected=f"{CASB_OTHER_APP_NAME} rendered (the policy names only {CASB_SAAS_APP_NAME})",
                failure=f"A LOGGING policy scoped to {CASB_SAAS_APP_NAME} blocked {CASB_OTHER_APP_URL}",
                fatal=False,
            )

            await_casb_event(
                case,
                casb_log,
                policy_name,
                timeout_sec=run_context.event_poll_timeout_sec,
                expected_service=CASB_SAAS_APP_NAME,
            )

            mine = matches_rule(policy_name)
            seen = {e.event_id for e in casb_log.events() if mine(e)}
            browser_session.visit(CASB_SAAS_URL, case_id=case.case_id)  # 표지 방문
            try:
                poll_until(
                    lambda: next(
                        (e for e in casb_log.events() if mine(e) and e.event_id not in seen
                         and in_app_service_name(e) == CASB_SAAS_APP_NAME), None,
                    ),
                    timeout_sec=run_context.event_poll_timeout_sec,
                    description=f"a new {CASB_SAAS_APP_NAME} row after the sentinel visit",
                )
            except PollTimeout as timeout:
                unverified(
                    case, Step.EVENT,
                    f"the sentinel visit to {CASB_SAAS_URL} left no new row, so whether "
                    f"{CASB_OTHER_APP_NAME} was recorded cannot be judged: {timeout}",
                )
            others = {
                in_app_service_name(event)
                for event in casb_log.events()
                if mine(event)
            } - {CASB_SAAS_APP_NAME}
            case.record(
                Step.EVENT,
                ok=not others,
                detail=f"other apps recorded under this policy: {sorted(others) or 'none'}",
                expected=f"only {CASB_SAAS_APP_NAME}",
                actual=sorted(others) or [CASB_SAAS_APP_NAME],
            )
            assert not others, (
                f"A policy scoped to {CASB_SAAS_APP_NAME} also recorded {sorted(others)}, "
                f"so the application scope is not being honoured"
            )
            pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-CASB-004")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P0")
@pytest.mark.gate
def test_saas_access_block_records_a_block_event(
    case, run_context, saas_access, browser_session, casb_log
):
    """CASB SaaS Access를 BLOCK으로 걸면 해당 앱 접속이 실제로 막히고, 그 요청이 BLOCK으로 기록된다.

    화면 차단과 그 요청 자신(marker)의 BLOCK 행을 둘 다 본다. 판정 기준은
    tests.support.expect_casb_block 참조.
    """
    policy_name = resource_name(case.case_id, run_context.run_id)

    try:
        with saas_access.temporary(
            policy_name, [CASB_SAAS_APP_ID], action_type="BLOCK", risk_level="Major"
        ) as policy:
            created = policy_changed(case, f"SaaS Access BLOCK {policy_name} created")
            case.policy_ids.append(policy.policy_id)

            expect_casb_block(
                case,
                browser_session,
                casb_log,
                policy_name,
                CASB_SAAS_URL,
                changed=created,
                propagation_timeout_sec=run_context.policy_propagation_timeout_sec,
                event_timeout_sec=run_context.event_poll_timeout_sec,
                expected_service=CASB_SAAS_APP_NAME,
                failure=f"The SaaS Access BLOCK on {CASB_SAAS_APP_NAME} did not hold",
            )
            pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)
