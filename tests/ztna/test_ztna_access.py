"""ZTNA 케이스.

테스트 테넌트에 보호 대상 애플리케이션이 없으므로, 접근 정책 케이스는 정책이
적용되는지가 아니라 정책이 수락되고 콘솔에 보이는지를 검증한다.
"""
from __future__ import annotations

import logging
import re

import pytest

from bat.endpoint.base import CONNECTOR_SERVICE, connector_running, service_state
from bat.events.auth_log import AuthLogReader
from bat.fixtures.graphql_policies import AccessPolicyFactory
from bat.fixtures.naming import resource_name
from bat.fixtures.policies import CleanupWarning
from bat.models import Kind, Step
from tests.support import cleanup_failed, pass_case, unverified

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


# 커넥터의 device_id는 하드웨어(SMBIOS) UUID다. 단말에 device_id가 설정돼 있으면
# 그 값이 우선한다.
DEVICE_ID_SCRIPT = "(Get-CimInstance Win32_ComputerSystemProduct).UUID"
_UUID_RE = re.compile(r"^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$")

# 세션이 수립됐음을 보여주는 auth_result 값: 로그인, 그다음 터널 연결
# (AUTH_DISCONNECT_VPN은 세지 않는다).
SESSION_ESTABLISHED = ("AUTH_SUCCESS_SDP", "AUTH_CONNECT_VPN")


def _endpoint_device_id(lane, executor) -> tuple[str, str]:
    """레인 단말의 (device_id, 그 값의 출처)를 반환한다. 모르면 ""이다."""
    configured = str(getattr(lane.endpoint, "device_id", "") or "").strip()
    if configured:
        return configured, "configured device_id"
    value = executor.run_powershell(DEVICE_ID_SCRIPT).stdout.strip()
    # 값을 설정한 적 없는 펌웨어는 전부 F나 전부 0을 보고하는데, 이는 어떤 기기도 가리키지 않는다.
    if _UUID_RE.match(value) and len(set(value.replace("-", ""))) > 1:
        return value, "hardware UUID"
    return "", f"hardware UUID unusable: {value[:40]!r}"


@pytest.mark.case("BAT-ZTNA-001")
@pytest.mark.verifies(Step.EVENT)
@pytest.mark.priority("P0")
@pytest.mark.critical
@pytest.mark.smoke
def test_connector_session_is_recorded(case, run_context, lane, auth_log: AuthLogReader, executor):
    """커넥터가 연결된 상태이고, 그 인증이 감사 로그에 기록되어 있다.

    이 단말 device_id의 로그인 또는 터널 연결 행이 있어야 PASS다. 그런 행이 없으면
    원인을 가릴 수 없어 UNVERIFIED다.
    """
    state = service_state(executor, CONNECTOR_SERVICE)
    case.record(
        Step.ACTION,
        ok=state.lower() == "running",
        detail=f"{CONNECTOR_SERVICE} is {state}",
        expected="Running",
        actual=state,
    )
    assert connector_running(executor), (
        f"The connector service {CONNECTOR_SERVICE} is {state}. Without it, no "
        f"traffic reaches SSE and every other case is meaningless."
    )

    device, source = _endpoint_device_id(lane, executor)
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
    mine = [
        event
        for event in auth_log.events(lookback_min=24 * 60, device_id=device)
        if str(event.get("device_id") or "") == device
    ]
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
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P3")
def test_protected_resource_catalog_is_queryable(case, console):
    """ZTNA의 보호 대상 리소스(tunnel/gateway) 목록을 조회할 수 있다.

    빈 목록도 정상이다. 항목이 생기면 실제 허용/차단 검증을 할 수 있다.
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

    ok = isinstance(tunnels, list) and isinstance(gateways, list)
    case.record(
        Step.USER_RESULT,
        ok=ok,
        detail=f"tunnel: {len(tunnels)} entr(y/ies), gateway: {len(gateways)} entr(y/ies)",
        expected="both queryable as lists",
        actual={"tunnel": tunnels, "gateway": gateways},
    )
    assert ok, "Could not read the tunnel/gateway resource lists as lists"
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
    """ZTNA 접근 정책을 BLOCK·ALLOW로 만들면 각각 콘솔 조회에 반영되고, 삭제하면 사라진다.

    보호 대상 애플리케이션이 없어 실효는 검증하지 않고 생성·조회·삭제만 본다.
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

                names = [row.get("name") for row in access_policies.list()]
                case.record(
                    Step.USER_RESULT,
                    ok=policy_name in names,
                    detail=f"{action}: policies now visible: {names}",
                    expected=f"contains {policy_name}",
                    actual=names,
                )
                assert policy_name in names, (
                    f"{action} access policy {policy_name} was created but the console "
                    f"query does not list it"
                )

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
    """실제 커넥터 사용자를 대상으로 한 접근 정책이 정상 생성된다."""
    events = auth_log.events(lookback_min=24 * 60)
    if not events:
        pytest.skip("No authentication events, so no real user id is available to target")

    event, user_id = _first_directory_user(access_policies, events)
    if user_id is None:
        pytest.skip(
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

            names = [row.get("name") for row in access_policies.list()]
            case.record(
                Step.USER_RESULT,
                ok=policy_name in names,
                detail=f"policy with a real user id ({user_id}) in its rules: "
                f"{'listed' if policy_name in names else 'not listed'}",
                expected=f"contains {policy_name}",
                actual=names,
            )
            assert policy_name in names, (
                f"User-scoped access policy {policy_name} was accepted but is not listed"
            )
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
    case, run_context, access_policies, auth_log: AuthLogReader, executor
):
    """인증 로그에서 실사용자를 찾아 정책을 걸고 지운 뒤에도 커넥터 세션은 멀쩡하다.

    access policy rule은 커넥터 세션 자체를 스코프하므로, country를 AQ로 좁혀도
    실제 사용자 id를 쓴 정책이 세션에 영향을 주지 않았는지 마지막에 확인한다.
    """
    state_before = service_state(executor, CONNECTOR_SERVICE)
    events_before = auth_log.events(lookback_min=24 * 60)
    if not events_before:
        pytest.skip("No authentication events, so no real user id is available to target")

    event, user_id = _first_directory_user(access_policies, events_before)
    if user_id is None:
        pytest.skip("No authentication event belongs to a directory user")
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

            stored = _read_policy(access_policies, policy_name)
            assert stored, f"{policy_name} was created but cannot be read back"
            case.record(
                Step.USER_RESULT,
                ok=stored.get("action_type") == "BLOCK",
                detail=f"read back: {stored}",
                expected="action_type BLOCK",
                actual=stored.get("action_type"),
            )

        # 이 시점에는 정책이 지워졌다. 이 테스트가 user id를 얻어 온 세션이 여전히
        # 이전과 똑같이 정상인지 확인한다.
        state_after = service_state(executor, CONNECTOR_SERVICE)
        events_after = auth_log.events(lookback_min=24 * 60)
        healthy = (
            state_after.lower() == "running"
            and connector_running(executor)
            and bool(events_after)
        )
        case.record(
            Step.EVENT,
            ok=healthy,
            detail=f"connector {state_after}, {len(events_after)} auth event(s) still visible",
            expected="connector still Running, auth log still readable",
            actual={"connector": state_after, "auth_events": len(events_after)},
        )
        assert healthy, (
            f"The connector or auth log looks different after creating and "
            f"deleting a policy scoped to this session's own user id "
            f"(before: {state_before}/{len(events_before)} events, after: "
            f"{state_after}/{len(events_after)} events) — a policy meant to be "
            f"inert may have touched the session it was resolved from"
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
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P3")
def test_protected_resource_entries_are_fully_readable(case, console):
    """accessControl(개별 보호 리소스)의 세부 필드를 전부 읽을 수 있다.

    리소스가 없는 테넌트에서는 빈 리스트로 통과한다.
    """
    data = console.execute(ACCESS_CONTROL_QUERY)
    entries = ((data.get("SIA") or {}).get("ztna") or {}).get("accessControl") or []

    ok = isinstance(entries, list)
    case.record(
        Step.USER_RESULT,
        ok=ok,
        detail=f"{len(entries)} access control entr(y/ies)",
        expected="queryable as a list, each with id/name/enable/type/priority/"
        "users/user_groups/application",
        actual=entries,
    )
    assert ok, "Could not read SIA.ztna.accessControl as a list"
    if entries:
        sample = entries[0]
        has_shape = all(key in sample for key in ("id", "name", "enable", "type", "application"))
        assert has_shape, f"An accessControl entry is missing expected fields: {sample}"
        log.info("Protected resources in this tenant: %s", [e.get("name") for e in entries])
    else:
        log.info("No ZTNA protected resource (accessControl) configured in this tenant yet")
    pass_case(case)


@pytest.mark.case("BAT-ZTNA-007")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P3")
def test_protected_resource_is_reachable_through_the_gateway(case, console, executor):
    """등록된 보호 리소스(HTTPS 타입)가 실제로 게이트웨이를 통해 도달 가능하다.

    첫 HTTPS 타입 리소스의 `application` 주소로 curl을 보내 응답이 오는지 본다.
    """
    data = console.execute(ACCESS_CONTROL_QUERY)
    entries = ((data.get("SIA") or {}).get("ztna") or {}).get("accessControl") or []
    https_entries = [e for e in entries if e.get("type") == "HTTPS" and e.get("application")]
    if not https_entries:
        pytest.skip(
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

    from bat.traffic.http import curl_status

    traffic = curl_status(executor, url, timeout_sec=15)
    case.record(
        Step.USER_RESULT,
        ok=bool(traffic.status_code),
        detail=f"HTTP {traffic.status_code}" if traffic.status_code else "connection refused",
        expected="reachable through the ZTNA gateway (no policy currently restricts it)",
        actual=f"HTTP {traffic.status_code}" if traffic.status_code else "connection refused",
    )
    assert traffic.status_code, (
        f"{resource.get('name')!r} at {url} was not reachable through the gateway "
        f"(connection refused) — either the gateway tunnel is down or something "
        f"is already restricting access"
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
