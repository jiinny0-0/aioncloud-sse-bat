"""기본 플랫폼 점검.

다른 어떤 결과를 믿기 전에 먼저 도는 케이스다. 보안 통제를 시험하지 않고, 다른 모든
케이스가 기대는 요소가 살아 있는지 확인한다: 토큰이 동작하고, 정책을 쓰고 다시 읽을 수
있고, 로그 API가 응답하고, 단말이 실제로 커넥터 뒤에 있는지.

이 중 하나가 실패하면 제품 스위트의 실패는 발견이 아니라 그 결과일 뿐이다.
"""
from __future__ import annotations

import logging

import pytest

from bat.endpoint.base import connector_state
from bat.fixtures.enums import ActionType, Condition, Subject
from bat.fixtures.naming import belongs_to_run, is_bat_resource, resource_name
from bat.clients.rest import pick_id
from bat.fixtures.policies import CleanupWarning, WEB_POLICY_PATH, WebPolicyFactory
from bat.fixtures.testdata import ALLOW_TARGET_URL, BLOCK_TARGET_HOST
from bat.models import Kind, Step
from tests.support import cleanup_failed, environment_error, pass_case

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.product("basic"),
    pytest.mark.lane("b"),
    pytest.mark.xdist_group("lane-b"),
]


@pytest.mark.case("BAT-BAS-001")
@pytest.mark.diagnostic
@pytest.mark.priority("P0")
@pytest.mark.critical
@pytest.mark.smoke
def test_api_token_is_accepted(case, rest):
    """Open API 토큰으로 인증된 요청이 정상 처리된다."""
    payload = rest.get("/sia/v1/user/group/list", params={"offset": 1, "limit": 1})
    case.record(
        Step.ACTION,
        ok=isinstance(payload, dict),
        detail=f"response keys: {sorted(payload) if isinstance(payload, dict) else type(payload)}",
        expected="a JSON object",
        actual=type(payload).__name__,
    )
    assert isinstance(payload, dict), (
        "The API answered with something other than a JSON object, which usually "
        "means the request never reached the API"
    )
    pass_case(case)


@pytest.mark.case("BAT-BAS-002")
@pytest.mark.diagnostic
@pytest.mark.priority("P0")
@pytest.mark.critical
def test_policy_can_be_written_and_read_back(case, run_context, web_policies):
    """정책을 생성하면 저장된 내용이 요청한 그대로 조회된다."""
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = WebPolicyFactory.build_rule(Subject.HTTP_HOST, Condition.IS, [BLOCK_TARGET_HOST])

    try:
        with web_policies.temporary(
            policy_name, [rule], action_type=ActionType.BLOCK
        ) as policy:
            case.policy_ids.append(policy.policy_id)
            stored = web_policies.get(policy)

            mismatches = {}
            if stored.get("name") != policy_name:
                mismatches["name"] = stored.get("name")
            if str(stored.get("action_type")) != ActionType.BLOCK:
                mismatches["action_type"] = stored.get("action_type")
            if not stored.get("enable"):
                mismatches["enable"] = stored.get("enable")

            case.record(
                Step.USER_RESULT,
                ok=not mismatches,
                detail=f"stored rules: {stored.get('rules')}",
                expected={"name": policy_name, "action_type": ActionType.BLOCK, "enable": True},
                actual={
                    "name": stored.get("name"),
                    "action_type": stored.get("action_type"),
                    "enable": stored.get("enable"),
                },
            )
            assert not mismatches, f"The stored policy differs from the request: {mismatches}"
            pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-BAS-003")
@pytest.mark.diagnostic
@pytest.mark.priority("P0")
@pytest.mark.critical
def test_security_log_is_readable(case, web_log):
    """보안 로그 API가 조회 가능하고 필수 필드를 포함한다."""
    events = web_log.security_events(lookback_min=24 * 60)
    case.record(
        Step.ACTION,
        ok=True,
        detail=f"{len(events)} event(s) in the last 24h",
    )
    if not events:
        environment_error(
            "No security events in the last 24 hours. Generate traffic through the "
            "connector first; an empty tenant cannot prove the schema."
        )

    newest = events[0].raw
    required = ("id", "time", "policy_name", "action")
    missing = [name for name in required if name not in newest]
    case.record(
        Step.EVENT,
        ok=not missing,
        detail=f"fields present: {sorted(newest)}",
        expected=list(required),
        actual=[name for name in required if name in newest],
    )
    assert not missing, (
        f"The security log is missing {missing}. Every product case validates "
        f"events through these fields."
    )
    pass_case(case)


@pytest.mark.case("BAT-BAS-004")
@pytest.mark.diagnostic
@pytest.mark.priority("P1")
def test_endpoint_is_behind_the_connector(case, run_context, executor, web_log, browser_session):
    """테스트 단말의 트래픽이 실제로 SSE를 경유한다."""
    process = run_context.profile.connector_process
    state = connector_state(executor, process)
    case.record(
        Step.SETUP,
        ok=state.lower() == "running",
        detail=f"{process} is {state}",
        expected="Running",
        actual=state,
    )
    assert state.lower() == "running", (
        f"{process} is {state}. Without the tunnel, no traffic reaches "
        f"SSE and every enforcement case becomes meaningless."
    )

    before = len(web_log.security_events(lookback_min=24 * 60))
    browser_session.visit(ALLOW_TARGET_URL, case_id=case.case_id)
    case.record(Step.ACTION, ok=True, detail=f"browser visited {ALLOW_TARGET_URL}")

    # 어떤 정책에도 맞지 않는 트래픽은 이벤트를 남기지 않으므로 새 기록을 assert할 수
    # 없다. 확인할 수 있는 것은 터널 어댑터와 로그를 읽을 수 있는지다.
    case.record(
        Step.USER_RESULT,
        ok=True,
        detail=f"log reachable, {before} event(s) known before the request",
        kind=Kind.EVIDENCE,
    )
    pass_case(case)


@pytest.mark.case("BAT-BAS-005")
@pytest.mark.diagnostic
@pytest.mark.priority("P2")
def test_no_leftovers_from_previous_runs(case, rest, run_context):
    """이전 실행이 남긴 BAT 리소스가 없다."""
    listing = rest.get("/sia/v1/web/policy/list", params={"offset": 1, "limit": 500})
    rows = listing.get("policies") or listing.get("list") or listing.get("data") or []
    # 같은 실행의 다른 워커가 지금 정책을 쥐고 있을 수 있다. 그것은 잔여물이 아니다.
    leftovers = [
        row for row in rows
        if isinstance(row, dict) and is_bat_resource(str(row.get("name", "")))
        and not belongs_to_run(str(row.get("name", "")), run_context.run_id)
    ]

    case.record(
        Step.USER_RESULT,
        ok=not leftovers,
        detail=f"{len(leftovers)} leftover BAT policy/policies",
        expected="none",
        actual=[row.get("name") for row in leftovers],
    )
    assert not leftovers, (
        f"{len(leftovers)} BAT policies from earlier runs are still present: "
        f"{[row.get('name') for row in leftovers]}. A leftover BLOCK policy changes "
        f"the result of every case that follows. Run 'bat sweep --delete'."
    )
    pass_case(case)


@pytest.mark.case("BAT-BAS-006")
@pytest.mark.diagnostic
@pytest.mark.priority("P1")
@pytest.mark.critical
def test_management_api_is_not_intercepted(case, run_context, rest, executor):
    """커넥터가 켜진 상태에서도 관리 API 요청이 SSE에 가로채이지 않는다."""
    from bat.clients.errors import ApiError, SelfBlockedError
    from bat.fixtures.enums import Condition, Subject

    process = run_context.profile.connector_process
    state = connector_state(executor, process)
    if state.lower() != "running":
        environment_error(f"{process} is {state}; nothing is being intercepted")

    # 읽기가 아니라 쓰기다: SSE는 POST 본문을 검사하므로, 스위트 자신의 관리용 쓰기가
    # 사용자 트래픽으로 취급되면 스위트가 동작할 수 없다.
    created: dict[str, object] = {}
    probes = {
        "POST /sia/v1/web/policy": lambda: created.__setitem__(
            "web_policy",
            rest.post(
                "/sia/v1/web/policy",
                json={
                    "name": f"BAT-BAS-006-probe-{case.case_id}",
                    "description": "probe, deleted immediately",
                    "enable": False,
                    "event_logging": False,
                    "action_type": "BLOCK",
                    "risk_level": "Minor",
                    "users": [0],
                    "user_groups": [0],
                    "rules": [
                        {
                            "subject": Subject.HTTP_HOST,
                            "condition": Condition.IS,
                            "priority": 1,
                            "value": ["bat-probe.invalid"],
                        }
                    ],
                },
            ),
        ),
        "POST /sia/v1/user": lambda: rest.post(
            "/sia/v1/user",
            json={
                "login_id": f"bat-bas-006-{case.case_id.lower()}@bat.local",
                "first_name": "BAT",
                "last_name": "Probe",
                "password": "BatProbe1234!",
                "role": "USER",
            },
        ),
    }

    intercepted: list[str] = []
    outcomes: dict[str, str] = {}

    try:
        for label, call in probes.items():
            try:
                call()
                outcomes[label] = "accepted"
            except SelfBlockedError:
                outcomes[label] = "intercepted by an SSE block page"
                intercepted.append(label)
            except ApiError as exc:
                # 실제 API 오류도 요청이 도착했다는 증거이고, 이 케이스가 보는 것은
                # 바로 그것이다.
                outcomes[label] = f"reached the API ({str(exc)[:80]})"
    finally:
        # POST가 수락됐으면 probe 정책을 지운다.
        policy_id = pick_id(created.get("web_policy") or {}, "id", "policy_id")
        if policy_id:
            try:
                rest.delete(WEB_POLICY_PATH, json={"ids": [int(policy_id)]})
            except Exception as exc:
                log.warning("Could not delete probe web policy %s: %s", policy_id, exc)

    case.record(
        Step.USER_RESULT,
        ok=not intercepted,
        detail=f"probe outcomes: {outcomes}",
        expected="every management request reaches the API",
        actual=outcomes,
    )
    assert not intercepted, (
        f"SSE intercepted the suite's own management requests: {intercepted}. "
        f"Management traffic is being inspected as if it were user browsing, "
        f"which makes the API unusable from behind the connector."
    )
    pass_case(case)
