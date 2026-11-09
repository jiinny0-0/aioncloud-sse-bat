"""ZTNA 케이스.

테스트 테넌트에 보호 대상 애플리케이션이 없으므로, 접근 정책 케이스는 정책이
적용되는지가 아니라 정책이 수락되고 콘솔에 보이는지를 검증한다.
"""
from __future__ import annotations

import logging
from datetime import timezone
from urllib.parse import urlsplit

import pytest

from bat.endpoint.base import connector_running, connector_state
from bat.events.auth_log import AuthLogReader
from bat.fixtures.graphql_policies import AccessPolicyFactory
from bat.fixtures.naming import resource_name
from bat.fixtures.policies import CleanupWarning
from bat.models import Kind, Step
from bat.events.web_log import matches_policy
from bat.fixtures.enums import Condition, Subject
from bat.fixtures.policies import WebPolicyFactory
from bat.fixtures.testdata import ALLOW_TARGET_URL
from bat.traffic.http import curl_status
from tests.support import (
    as_list,
    cleanup_failed,
    describe,
    endpoint_device_id,
    environment_error,
    expect_values,
    marked_url,
    pass_case,
    request_until_logged,
    stored,
    unverified,
)

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.product("ztna"),
    pytest.mark.lane("e"),
    pytest.mark.xdist_group("lane-e"),
]


@pytest.fixture
def access_policies(console) -> AccessPolicyFactory:
    return AccessPolicyFactory(console)


LOOKUP_USERS = """
query BatLookupUsers { SIA { user { users { id name login_id } } } }
"""


def _first_directory_user(access_policies: AccessPolicyFactory, events) -> tuple:
    """실제 디렉터리 사용자가 남긴 가장 최근 인증 이벤트의 (event, user_id)를 반환한다.

    auth_log에는 user_id가 없고 login_id/user_name만 있으므로, 각각을 사용자 디렉터리와
    대조한다. 가장 최근 행은 서버 터널처럼 사람이 아닌 세션의 것일 수 있다.
    """
    if not events:
        return None, None
    try:
        data = access_policies.gql.execute(LOOKUP_USERS)
    except Exception as exc:
        log.info("Could not list users to resolve auth log identities: %s", exc)
        return None, None

    from bat.fixtures.graphql_policies import _flatten_rows

    directory: dict[str, int] = {}
    for row in _flatten_rows((data.get("SIA") or {}).get("user")):
        if row.get("id") is None:
            continue
        for field in ("login_id", "name"):
            value = str(row.get(field) or "").lower()
            if value:
                directory.setdefault(value, int(row["id"]))

    for event in events:
        for field in ("login_id", "user_name"):
            value = str(event.get(field) or "").lower()
            if value in directory:
                return event, directory[value]
    return None, None


# 세션이 수립됐음을 보여주는 auth_result 값: 로그인, 그다음 터널 연결
# (AUTH_DISCONNECT_VPN은 세지 않는다).
SESSION_ESTABLISHED = ("AUTH_SUCCESS_SDP", "AUTH_CONNECT_VPN")


@pytest.mark.case("BAT-ZTNA-001")
@pytest.mark.verifies(Step.EVENT)
@pytest.mark.priority("P0")
@pytest.mark.critical
@pytest.mark.smoke
def test_connector_session_is_recorded(case, run_context, lane, auth_log: AuthLogReader, executor):
    """커넥터가 연결된 상태이고, 그 인증이 감사 로그에 기록되어 있다.

    이 단말 device_id의 행만 본다. 가장 최근 행이 연결 해제(AUTH_DISCONNECT_VPN)면 세션이
    끊긴 것이라 FAIL이다. 그렇지 않으면 로그인 또는 터널 연결 행이 있어야 PASS이고, 그런 행이
    없으면 원인을 가릴 수 없어 UNVERIFIED다. 그 행이 이번 실행이 시작된 뒤의 것인지는 근거로
    남긴다(세션은 보통 실행 전에 맺어진다).
    """
    process = run_context.profile.connector_process
    state = connector_state(executor, process)
    case.record(
        Step.ACTION,
        ok=state.lower() == "running",
        detail=f"{process} is {state}",
        expected="Running",
        actual=state,
    )
    assert connector_running(executor, process), (
        f"The connector process {process} is {state}. Without it, no "
        f"traffic reaches SSE and every other case is meaningless."
    )

    device, source = endpoint_device_id(lane, executor)
    if not device:
        unverified(
            case,
            Step.EVENT,
            f"No device id for this endpoint ({source}), so no auth_log row can be "
            f"tied to its connector. Set endpoints[].device_id in config/environments.yaml",
        )
    case.record(Step.SETUP, ok=True, detail=f"endpoint device_id {device} ({source})")

    # 이번 실행 전에 시작된 세션도 덮도록 24시간을 거슬러 본다. 서버가 이 단말로
    # 필터링하고 여기서 한 번 더 확인하므로, 서버가 필터를 무시해도 통과할 수 없다.
    everyone = auth_log.events(lookback_min=24 * 60)
    mine = sorted(
        (
            event
            for event in auth_log.events(lookback_min=24 * 60, device_id=device)
            if str(event.get("device_id") or "") == device
        ),
        key=lambda event: str(event.get("time") or ""),
        reverse=True,
    )
    if mine and str(mine[0].get("auth_result") or "") == "AUTH_DISCONNECT_VPN":
        case.record(
            Step.EVENT, ok=False, kind=Kind.ASSERTION,
            detail=f"auth_log_id={mine[0].event_id}: the newest row of device {device} is a disconnect "
            f"at {mine[0].get('time')}",
            expected="the newest row is a sign-in or a tunnel connect",
            actual={"auth_result": mine[0].get("auth_result"), "time": mine[0].get("time")},
        )
        raise AssertionError(
            f"The connector process is running but the newest auth_log row of this endpoint "
            f"(device_id {device}) is AUTH_DISCONNECT_VPN at {mine[0].get('time')}"
        )
    established = [e for e in mine if str(e.get("auth_result") or "") in SESSION_ESTABLISHED]
    if not established:
        seen = sorted({str(e.get("auth_result")) for e in mine})
        unverified(
            case,
            Step.EVENT,
            f"No auth_log row in the last 24h ties a sign-in to this endpoint "
            f"(device_id {device}): {len(mine)} row(s) from this device"
            f"{f' {seen}' if seen else ''}, none of them {list(SESSION_ESTABLISHED)}; "
            f"{len(everyone)} row(s) from any device on the newest page, which say "
            f"nothing about this connector.",
        )

    newest = established[0]
    run_began = run_context.started_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    case.record(
        Step.SETUP, ok=True, kind=Kind.EVIDENCE,
        detail=f"newest sign-in/connect row at {newest.get('time')}; this run began at {run_began}Z "
        f"({'during' if str(newest.get('time') or '') >= run_began else 'before'} this run)",
    )
    case.event_ids.append(newest.event_id)
    case.record(
        Step.EVENT,
        ok=True,
        detail=f"auth_log_id={newest.event_id}: {newest.get('auth_result')} at {newest.get('time')}",
        expected={"device_id": device, "auth_result": list(SESSION_ESTABLISHED)},
        actual={
            "device_id": newest.get("device_id"),
            "auth_result": newest.get("auth_result"),
            "time": newest.get("time"),
        },
        kind=Kind.ASSERTION,
    )
    identity = {
        "user": newest.get("login_id", "user_name"),
        "device": newest.get("device_id"),
        "src_ip": newest.get("client_ip", "src_ip"),
        "result": newest.get("auth_result", "result"),
        "os": newest.get("platform", "os"),
    }
    missing = [name for name, value in identity.items() if value in (None, "", [])]
    case.record(
        Step.EVENT,
        ok=not missing,
        detail=f"authentication identity: {identity}",
        expected=sorted(identity),
        actual=identity,
        kind=Kind.EVIDENCE,
    )
    if missing:
        log.warning("Authentication event %s is missing %s", newest.event_id, missing)
    pass_case(case)


@pytest.mark.case("BAT-ZTNA-004")
@pytest.mark.diagnostic
@pytest.mark.priority("P3")
def test_protected_resource_catalog_is_queryable(case, console):
    """ZTNA의 보호 대상 리소스(tunnel/gateway) 목록을 조회할 수 있다(환경 점검).

    빈 목록도 정상이다. 조회가 답하면 통과이고, 실패하면 예외로 ERROR가 된다.
    """
    query = """
    query BatZtnaProtectedResources {
      SIA { ztna {
        tunnel { list { id name description } }
        gateway { list { id name description } }
      } }
    }
    """
    data = console.execute(query)
    ztna = ((data.get("SIA") or {}).get("ztna")) or {}
    tunnels = ((ztna.get("tunnel") or {}).get("list")) or []
    gateways = ((ztna.get("gateway") or {}).get("list")) or []

    case.record(
        Step.ACTION,
        ok=True,
        kind=Kind.ASSERTION,
        detail=f"tunnel: {len(tunnels)} entr(y/ies), gateway: {len(gateways)} entr(y/ies)",
        expected="both list queries answer",
        actual={"tunnel": tunnels, "gateway": gateways},
    )
    if not tunnels and not gateways:
        log.info(
            "No ZTNA protected resource (tunnel/gateway) is configured in this "
            "tenant yet — the real allow/block cases stay blocked until one exists"
        )
    pass_case(case)


@pytest.mark.case("BAT-ZTNA-002")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P3")
def test_access_policy_round_trip(case, run_context, access_policies):
    """ZTNA 접근 정책을 BLOCK·ALLOW로 만들면 각각 요청한 내용대로 저장되고, 삭제하면 사라진다.

    보호 대상 애플리케이션이 없어 실효는 검증하지 않고 생성·조회·삭제만 본다. 다시 읽은
    action_type과 rule의 국가가 요청값과 같아야 한다(목록에 있다는 것은 생성이 이미 확인한다).
    삭제 확인이 시나리오의 일부라 pass_case는 두 정책을 다 지운 뒤에 부른다.
    """
    # 테스트 트래픽이 출발할 일 없는 국가라서, 정책이 있는 동안 아무것에도 영향을
    # 줄 수 없다.
    rules = [AccessPolicyFactory.rule(countries=["AQ"])]

    for action in ("BLOCK", "ALLOW"):
        policy_name = resource_name(case.case_id, run_context.run_id, action.lower())
        try:
            with access_policies.temporary(policy_name, rules, action_type=action) as policy:
                case.policy_ids.append(policy.policy_id)
                case.record(
                    Step.SETUP,
                    ok=True,
                    detail=f"{action} access policy {policy_name} (id={policy.policy_id})",
                )

                saved = _read_policy(access_policies, policy_name)
                rule = _first_rule(saved)
                expect_values(case, f"{action} access policy {policy_name} as read back", {
                    "action_type": (action, stored(saved, "action_type")),
                    "country": (["AQ"], as_list(stored(rule, "country"))),
                })

        except CleanupWarning as warning:
            cleanup_failed(case, warning)
            return

        remaining = [row.get("name") for row in access_policies.list()]
        case.record(
            Step.CLEANUP,
            ok=policy_name not in remaining,
            detail=f"{action} policy removed from the console view",
            expected=f"{policy_name} gone",
            actual=remaining,
        )
        assert policy_name not in remaining, (
            f"{action} access policy {policy_name} still appears after deletion"
        )
    pass_case(case)


@pytest.mark.case("BAT-ZTNA-003")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P1")
def test_user_scoped_access_policy_is_accepted(
    case, run_context, access_policies, auth_log: AuthLogReader
):
    """실제 커넥터 사용자를 대상으로 한 접근 정책이 정상 생성된다.

    다시 읽은 정책의 action_type, rule의 사용자 id와 국가가 요청값과 같아야 한다.
    """
    events = auth_log.events(lookback_min=24 * 60)
    if not events:
        environment_error("No authentication events, so no real user id is available to target")

    event, user_id = _first_directory_user(access_policies, events)
    if user_id is None:
        environment_error(
            "No authentication event belongs to a directory user, so a "
            "user-scoped policy cannot be targeted"
        )

    policy_name = resource_name(case.case_id, run_context.run_id)
    rules = [AccessPolicyFactory.rule(user_ids=[user_id], countries=["AQ"])]

    try:
        with access_policies.temporary(policy_name, rules, action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)
            case.user = str(event.get("login_id") or user_id)
            case.record(
                Step.SETUP,
                ok=True,
                detail=f"access policy scoped to user {user_id}",
            )

            saved = _read_policy(access_policies, policy_name)
            rule = _first_rule(saved)
            expect_values(case, f"access policy {policy_name} as read back", {
                "action_type": ("BLOCK", stored(saved, "action_type")),
                "user": ([user_id], as_list(stored(rule, "user"))),
                "country": (["AQ"], as_list(stored(rule, "country"))),
            })
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


READ_ACCESS_POLICY = """
query BatReadAccessPolicy {
  SIA { ztna { accessPolicy {
    id name action_type
    rules { ip country user { id name } }
  } } }
}
"""


def _first_rule(policy: dict | None) -> dict | None:
    """다시 읽은 접근 정책의 첫 rule. 케이스는 rule을 하나만 만든다."""
    rules = (policy or {}).get("rules")
    return rules[0] if isinstance(rules, list) and rules and isinstance(rules[0], dict) else None


def _read_policy(access_policies: AccessPolicyFactory, name: str) -> dict | None:
    """접근 정책 하나를 서버가 저장한 그대로 다시 읽는다.

    읽기 쪽은 rule의 사용자를 `user { id name }`로 부르고, mutation은
    `user_id: [Int]`를 받는다.
    """
    data = access_policies.gql.execute(READ_ACCESS_POLICY)
    rows = ((data.get("SIA") or {}).get("ztna") or {}).get("accessPolicy") or []
    for row in rows:
        if isinstance(row, dict) and row.get("name") == name:
            return row
    return None


@pytest.mark.case("BAT-ZTNA-005")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_identity_chain_round_trip_leaves_the_session_healthy(
    case, run_context, access_policies, auth_log: AuthLogReader, executor, web_policies, web_log
):
    """인증 로그에서 실사용자를 찾아 정책을 걸고 지운 뒤에도 커넥터 세션은 멀쩡하다.

    access policy rule은 커넥터 세션 자체를 스코프하므로, country를 AQ로 좁혀도
    실제 사용자 id를 쓴 정책이 세션에 영향을 주지 않았는지 마지막에 확인한다. 다시 읽은
    정책의 action_type, rule의 사용자 id와 국가가 요청값과 같아야 하고, 정책을 지운 뒤
    커넥터 프로세스가 돌고 있으며 이 단말이 보낸 마커 요청이 LOGGING 웹 정책으로 보안 로그에
    찍혀야 한다(트래픽이 여전히 SSE를 지난다).
    """
    process = run_context.profile.connector_process
    state_before = connector_state(executor, process)
    events_before = auth_log.events(lookback_min=24 * 60)
    if not events_before:
        environment_error("No authentication events, so no real user id is available to target")

    event, user_id = _first_directory_user(access_policies, events_before)
    if user_id is None:
        environment_error("No authentication event belongs to a directory user")
    login_id = event.get("login_id") or event.get("user_name")
    case.record(
        Step.SETUP,
        ok=True,
        detail=f"resolved real user id {user_id} from the auth log ({login_id!r})",
    )

    policy_name = resource_name(case.case_id, run_context.run_id)
    rules = [AccessPolicyFactory.rule(user_ids=[user_id], countries=["AQ"])]

    try:
        with access_policies.temporary(policy_name, rules, action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)

            saved = _read_policy(access_policies, policy_name)
            rule = _first_rule(saved)
            expect_values(case, f"access policy {policy_name} as read back", {
                "action_type": ("BLOCK", stored(saved, "action_type")),
                "user": ([user_id], as_list(stored(rule, "user"))),
                "country": (["AQ"], as_list(stored(rule, "country"))),
            })

        # 이 시점에는 정책이 지워졌다(목록에서 사라진 것까지 확인). 이 테스트가 user id를
        # 얻어 온 세션으로 트래픽이 여전히 SSE를 지나는지 확인한다.
        state_after = connector_state(executor, process)
        reach_name = resource_name(case.case_id, run_context.run_id, "reach")
        host = urlsplit(ALLOW_TARGET_URL).hostname
        reach_rule = WebPolicyFactory.build_rule(Subject.HTTP_HOST, Condition.IS, [host])
        with web_policies.temporary(reach_name, [reach_rule], action_type="LOGGING") as reach:
            case.policy_ids.append(reach.policy_id)
            logged = request_until_logged(
                web_log,
                lambda url: curl_status(executor, url),
                match=matches_policy(reach_name, reach.policy_id),
                url_for=lambda n: marked_url(ALLOW_TARGET_URL, case, run_context, f"after{n}"),
                budget_sec=run_context.policy_propagation_timeout_sec,
                event_timeout_sec=run_context.event_poll_timeout_sec,
            )
            healthy = state_after.lower() == "running" and connector_running(executor, process) and bool(logged)
            case.record(
                Step.EVENT,
                ok=healthy,
                kind=Kind.ASSERTION,
                detail=f"connector {state_after}; "
                + (f"{logged[0]} logged under {reach_name}" if logged else f"no marked request reached {reach_name}"),
                expected="connector still Running and this endpoint's marked request in the SSE log",
                actual={"connector": state_after, "logged": logged[0] if logged else None},
            )
            assert healthy, (
                f"After creating and deleting a policy scoped to this session's own user id, the "
                f"connector is {state_after} (was {state_before}) and "
                + ("its traffic still reaches SSE" if logged else "none of its marked requests reached the SSE log")
                + " — a policy meant to be inert may have touched the session it was resolved from"
            )
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


ACCESS_CONTROL_QUERY = """
query BatAccessControlCatalog {
  SIA { ztna { accessControl {
    id name enable type priority
    users { id name }
    user_groups { id name }
    application { id ip domain port }
  } } }
}
"""


@pytest.mark.case("BAT-ZTNA-006")
@pytest.mark.diagnostic
@pytest.mark.priority("P3")
def test_protected_resource_entries_are_fully_readable(case, console):
    """accessControl(개별 보호 리소스)의 세부 필드를 전부 읽을 수 있다(환경 점검).

    조회가 답하면 통과이고, 항목이 있으면 첫 항목에 id/name/enable/type/application이 있어야
    한다. 리소스가 없는 테넌트에서는 조회 응답만으로 통과한다.
    """
    data = console.execute(ACCESS_CONTROL_QUERY)
    entries = ((data.get("SIA") or {}).get("ztna") or {}).get("accessControl") or []

    case.record(
        Step.ACTION,
        ok=True,
        kind=Kind.ASSERTION,
        detail=f"{len(entries)} access control entr(y/ies)",
        expected="the accessControl query answers",
        actual=entries,
    )
    if entries:
        sample = entries[0]
        missing = [key for key in ("id", "name", "enable", "type", "application") if key not in sample]
        case.record(
            Step.ACTION, ok=not missing, kind=Kind.ASSERTION,
            detail=f"first entry fields: {sorted(sample)}",
            expected="id/name/enable/type/application", actual=missing or "all present",
        )
        assert not missing, f"An accessControl entry is missing expected fields: {missing} ({sample})"
        log.info("Protected resources in this tenant: %s", [e.get("name") for e in entries])
    else:
        log.info("No ZTNA protected resource (accessControl) configured in this tenant yet")
    pass_case(case)


@pytest.mark.case("BAT-ZTNA-007")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P3")
def test_protected_resource_is_reachable_through_the_gateway(case, console, executor):
    """등록된 보호 리소스(HTTPS 타입)가 실제로 게이트웨이를 통해 도달 가능하다.

    첫 HTTPS 타입 리소스의 `application` 주소로 curl을 보내, 요청이 전달(delivered: 403/451·5xx가
    아닌 HTTP 응답)되는지 본다. 응답이 없거나 그 밖의 코드면 FAIL이다.
    """
    data = console.execute(ACCESS_CONTROL_QUERY)
    entries = ((data.get("SIA") or {}).get("ztna") or {}).get("accessControl") or []
    https_entries = [e for e in entries if e.get("type") == "HTTPS" and e.get("application")]
    if not https_entries:
        environment_error(
            "No HTTPS-type accessControl resource configured in this tenant yet "
            "— nothing to probe reachability against"
        )

    resource = https_entries[0]
    app = resource["application"][0]
    # 리소스는 IP나 도메인 중 하나를 가리킨다(다른 하나는 비어 있다).
    host = app.get("ip") or app.get("domain")
    if not host:
        unverified(case, Step.USER_RESULT,
                   f"{resource.get('name')!r} names neither an IP nor a domain: {app}")
        return
    scheme = "https" if resource.get("type") == "HTTPS" else "http"
    url = f"{scheme}://{host}:{app['port']}/" if app.get("port") else f"{scheme}://{host}/"
    case.record(
        Step.SETUP, ok=True, detail=f"probing {resource.get('name')!r} at {url}"
    )

    traffic = curl_status(executor, url, timeout_sec=15)
    case.record(
        Step.USER_RESULT,
        ok=traffic.delivered,
        kind=Kind.ASSERTION,
        detail=describe(traffic),
        expected="delivered through the ZTNA gateway (a 2xx-4xx answer other than 403/451)",
        actual=describe(traffic),
    )
    assert traffic.delivered, (
        f"{resource.get('name')!r} at {url} did not answer with a delivered response through the "
        f"gateway ({describe(traffic)}) — either the gateway tunnel is down, the resource is "
        f"misconfigured, or something is already restricting access"
    )
    pass_case(case)


@pytest.mark.case("BAT-ZTNA-008")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P3")
def test_dynamic_connector_catalog_is_queryable(case, console):
    """`SIA.ztna.dynamic_connector`도 tunnel/gateway와 같은 방식으로 조회할 수 있다."""
    found = False
    shape: dict = {}
    for selection in ("list { id name }", "id name", "list { id }"):
        query = f"query {{ SIA {{ ztna {{ dynamic_connector {{ {selection} }} }} }} }}"
        try:
            data = console.execute(query)
            found = True
            shape = ((data.get("SIA") or {}).get("ztna") or {}).get("dynamic_connector")
            break
        except Exception as exc:  # noqa: BLE001 - 다른 형태를 일부러 시도한다
            last_error = str(exc)

    case.record(
        Step.USER_RESULT,
        ok=found,
        detail=str(shape) if found else last_error[:200],
        expected="queryable in some shape",
        actual=shape if found else "not queryable",
    )
    assert found, f"SIA.ztna.dynamic_connector could not be queried in any tried shape: {last_error}"
    pass_case(case)
