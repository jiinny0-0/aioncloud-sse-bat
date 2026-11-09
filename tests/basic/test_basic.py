"""기본 플랫폼 점검.

다른 어떤 결과를 믿기 전에 먼저 도는 케이스다. 보안 통제를 시험하지 않고, 다른 모든
케이스가 기대는 요소가 살아 있는지 확인한다: 토큰이 동작하고, 정책을 쓰고 다시 읽을 수
있고, 로그 API가 응답하고, 단말이 실제로 커넥터 뒤에 있는지.

이 중 하나가 실패하면 제품 스위트의 실패는 발견이 아니라 그 결과일 뿐이다.
"""
from __future__ import annotations

import logging
from urllib.parse import urlsplit

import pytest

from bat.endpoint.base import connector_state
from bat.fixtures.enums import ActionType, Condition, Subject
from bat.fixtures.naming import belongs_to_run, resource_name
from bat.clients.rest import pick_id
from bat.fixtures.policies import CleanupWarning, WEB_POLICY_PATH, WebPolicyFactory
from bat.fixtures.testdata import ALLOW_TARGET_URL, BLOCK_TARGET_HOST
from bat.events.web_log import all_of, matches_policy, matches_target
from bat.models import Kind, Step
from tests.support import (
    cleanup_failed,
    environment_error,
    marked_url,
    pass_case,
    request_until_logged,
    unverified,
)

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.product("basic"),
    pytest.mark.lane("b"),
    pytest.mark.xdist_group("lane-b"),
]


@pytest.mark.case("BAT-BASIC-001")
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


@pytest.mark.case("BAT-BASIC-002")
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


@pytest.mark.case("BAT-BASIC-003")
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


@pytest.mark.case("BAT-BASIC-004")
@pytest.mark.diagnostic
@pytest.mark.priority("P1")
def test_endpoint_is_behind_the_connector(
    case, run_context, executor, web_log, browser_session, web_policies
):
    """테스트 단말의 트래픽이 실제로 SSE를 경유한다.

    커넥터 프로세스가 떠 있는지만으로는 모른다. ALLOW_TARGET 호스트에 LOGGING 정책을 걸고
    단말 브라우저로 마커를 단 요청을 보내, 그 요청 자신의 행이 보안 로그에 찍혀야 한다.
    """
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

    policy_name = resource_name(case.case_id, run_context.run_id)
    host = urlsplit(ALLOW_TARGET_URL).hostname
    rule = WebPolicyFactory.build_rule(Subject.HTTP_HOST, Condition.IS, [host])
    try:
        with web_policies.temporary(policy_name, [rule], action_type="LOGGING") as policy:
            case.policy_ids.append(policy.policy_id)
            logged = request_until_logged(
                web_log,
                lambda url: browser_session.visit(url, case_id=case.case_id),
                match=matches_policy(policy_name, policy.policy_id),
                url_for=lambda n: marked_url(ALLOW_TARGET_URL, case, run_context, f"via{n}"),
                budget_sec=run_context.policy_propagation_timeout_sec,
                event_timeout_sec=run_context.event_poll_timeout_sec,
            )
            case.record(
                Step.USER_RESULT,
                ok=logged is not None,
                kind=Kind.ASSERTION,
                detail=f"{logged[0]} was logged under {policy_name}" if logged
                else f"none of the marked requests to {host} reached the security log",
                expected="this endpoint's own marked request appears in the SSE log",
            )
            assert logged, (
                f"{process} is running but none of this endpoint's marked requests to {host} "
                f"appeared under the LOGGING policy {policy_name}, so its traffic is not going through SSE"
            )
            event = web_log.wait_for_security_event(
                all_of(matches_policy(policy_name, policy.policy_id), matches_target(logged[0])),
                timeout_sec=run_context.event_poll_timeout_sec,
            )
            case.event_ids.append(event.event_id)
            case.record(
                Step.EVENT, ok=True, kind=Kind.EVIDENCE,
                detail=f"row id={event.event_id} device_id={event.get('device_id')} "
                f"user={event.get('user_name')} src_ip={event.get('src_ip')}",
            )
            pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-BASIC-005")
@pytest.mark.diagnostic
@pytest.mark.priority("P2")
def test_no_leftovers_from_previous_runs(case, rest, console, run_context):
    """이전 실행이 남긴 BAT 리소스가 없다.

    모든 정책 종류(웹, DLP, GenAI, CASB 두 종류, RBI, DNS/Application Firewall, ZTNA 접근제어·
    터널·접근정책)를 읽는다. 웹·DLP 목록은 total로 전체를 읽었는지 확인한다. 남은 것이 있으면
    FAIL, 남은 것은 없지만 읽지 못한 목록이 있으면 UNVERIFIED다.
    """
    from bat.leftovers import scan

    # 같은 실행의 다른 워커가 지금 리소스를 쥐고 있을 수 있다. 그것은 잔여물이 아니다.
    leftovers, unread = scan(rest, console, lambda name: not belongs_to_run(name, run_context.run_id))
    case.record(
        Step.USER_RESULT,
        ok=not leftovers,
        kind=Kind.ASSERTION,
        detail=f"{len(leftovers)} leftover BAT resource(s)",
        expected="none",
        actual=leftovers,
    )
    assert not leftovers, (
        f"{len(leftovers)} BAT resources from earlier runs are still present: {leftovers}. A "
        f"leftover BLOCK policy changes the result of every case that follows. Run 'bat sweep --delete'."
    )
    if unread:
        unverified(case, Step.USER_RESULT, f"no leftovers in what could be read, but these lists were not confirmed: {unread}")
    pass_case(case)


def _html_answer(payload: object) -> bool:
    """REST 클라이언트가 JSON으로 읽지 못해 원문으로 돌려준 HTML 페이지인가."""
    if not isinstance(payload, dict) or set(payload) != {"_raw"}:
        return False
    head = str(payload["_raw"])[:400].lower()
    return "<html" in head or "<!doctype html" in head


@pytest.mark.case("BAT-BASIC-006")
@pytest.mark.diagnostic
@pytest.mark.priority("P1")
@pytest.mark.critical
def test_management_api_is_not_intercepted(case, run_context, rest, executor):
    """커넥터가 켜진 상태에서도 관리 API 요청이 SSE에 가로채이지 않는다.

    API 오류(JSON)는 요청이 API에 닿았다는 뜻이라 통과다. SSE 차단 페이지(HTML)는 상태 코드와
    상관없이 가로챔이다: 2xx로 HTML이 돌아와도 가로챔으로 본다. probe로 만든 웹 정책과 사용자는
    끝나면 지우고, 사라졌는지 다시 확인한다.
    """
    from bat.clients.errors import ApiError, SelfBlockedError
    from bat.fixtures.enums import Condition, Subject

    process = run_context.profile.connector_process
    state = connector_state(executor, process)
    if state.lower() != "running":
        environment_error(f"{process} is {state}; nothing is being intercepted")

    # 읽기가 아니라 쓰기다: SSE는 POST 본문을 검사하므로, 스위트 자신의 관리용 쓰기가
    # 사용자 트래픽으로 취급되면 스위트가 동작할 수 없다.
    from bat.fixtures.users import USER_PATH, UserFactory

    probe_login = f"bat-bas-006-{case.case_id.lower()}@bat.local"
    created: dict[str, object] = {}
    probes = {
        "POST /sia/v1/web/policy": lambda: created.__setitem__(
            "web_policy",
            rest.post(
                "/sia/v1/web/policy",
                json={
                    "name": f"BAT-BASIC-006-probe-{case.case_id}",
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
        "POST /sia/v1/user": lambda: created.__setitem__("user", rest.post(
            "/sia/v1/user",
            json={
                "login_id": probe_login,
                "first_name": "BAT",
                "last_name": "Probe",
                "password": "BatProbe1234!",
                "role": "USER",
            },
        )),
    }

    intercepted: list[str] = []
    outcomes: dict[str, str] = {}

    try:
        for label, call in probes.items():
            try:
                call()
                key = "web_policy" if "policy" in label else "user"
                if _html_answer(created.get(key)):
                    # 2xx로 돌아왔지만 JSON이 아니라 HTML 페이지다. API가 아니라 SSE가 답했다.
                    outcomes[label] = "intercepted (2xx HTML page instead of the API's JSON)"
                    intercepted.append(label)
                else:
                    outcomes[label] = "accepted"
            except SelfBlockedError:
                outcomes[label] = "intercepted by an SSE block page"
                intercepted.append(label)
            except ApiError as exc:
                # 실제 API 오류도 요청이 도착했다는 증거이고, 이 케이스가 보는 것은
                # 바로 그것이다.
                outcomes[label] = f"reached the API ({str(exc)[:80]})"
    finally:
        # POST가 수락됐으면 probe 정책과 사용자를 지우고, 사라졌는지 다시 확인한다.
        policy_id = pick_id(created.get("web_policy") or {}, "id", "policy_id")
        if policy_id:
            try:
                rest.delete(WEB_POLICY_PATH, json={"ids": [int(policy_id)]})
                rows, _ = WebPolicyFactory(rest).list()
                if any(str(row.get("id")) == str(policy_id) for row in rows):
                    raise RuntimeError("still listed after delete")
            except Exception as exc:
                case.cleanup_warnings.append(f"probe web policy {policy_id}: {exc}")
                log.warning("Could not delete probe web policy %s: %s", policy_id, exc)
        users = UserFactory(rest)
        try:
            user_id = pick_id(created.get("user") or {}, "id", "user_id") or users.find_id_by_login(probe_login)
            if user_id:
                rest.delete(f"{USER_PATH}/{user_id}")
                if users.find_id_by_login(probe_login):
                    raise RuntimeError("still listed after delete")
        except Exception as exc:
            case.cleanup_warnings.append(f"probe user {probe_login}: {exc}")
            log.warning("Could not delete probe user %s: %s", probe_login, exc)

    case.record(
        Step.USER_RESULT,
        ok=not intercepted,
        kind=Kind.ASSERTION,
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
