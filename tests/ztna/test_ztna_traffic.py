"""ZTNA 트래픽 케이스: 접근제어로 내부 서버가 실제로 열리고 막히는지 본다.

대상 서버는 설정 없이 찾는다(`_gateway_target`): 게이트웨이 서버 목록(id 순)에서 흔한 웹
포트 중 규칙 없이 처음 열리는 서버와 포트, 그 페이지의 <title>, 콘솔이 그 서버에 붙인
도메인(커넥터가 직접 답하는 이름), 같은 포트로 열리는 다른 서버. 스테이지 블록의 `ztna:`
(server_ip, domain, port, page_text, other_ip)에 적힌 값이 있으면 그 값이 우선이다. 열리는
서버가 없으면 실행 조건 미비(ERROR)다.

BAT가 만드는 접근제어는 우선순위 0으로 올려 콘솔에서 만든 항목보다 먼저 매칭되게 한다.
같은 서버를 콘솔 항목이 이미 열어 두었을 수 있어서, 접속이 된다는 것만으로는 BAT 규칙이
동작했다고 보지 않는다. ZTNA 로그에 BAT 접근제어 이름으로 그 접속이 남아야 한다.

BLOCK은 BAT 접근제어 하나에 연결한 접근정책으로만 건다. 그 접근제어에 매칭된 내부
트래픽에만 걸리고 인터넷과 관리 API에는 영향이 없다.
"""
from __future__ import annotations

import base64
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from bat.events.poller import PollTimeout, poll_until
from bat.events.ztna_log import ZtnaLogReader, matches_access
from bat.fixtures.graphql_policies import AccessControlFactory, AccessPolicyFactory, TunnelFactory
from bat.fixtures.naming import is_bat_resource, resource_name
from bat.fixtures.policies import CleanupWarning
from bat.models import Kind, SecurityEvent, Step, TrafficResult
from bat.settings import ZtnaTarget, ZtnaTunnelTarget
from bat.clients.errors import EndpointError
from bat.traffic.http import BLOCK_STATUS_CODES, is_delivered_status, resolve_ip
from tests.support import (
    cleanup_failed,
    describe,
    endpoint_device_id,
    environment_error,
    expect_delivered,
    pass_case,
    unverified,
)

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.product("ztna"),
    pytest.mark.lane("e"),
    pytest.mark.xdist_group("lane-e"),
]

EVERYONE = [AccessPolicyFactory.rule(user_ids=[0])]

# 설정에 포트가 없을 때 게이트웨이 서버·터널 뒤 서버에서 웹 페이지를 찾아볼 (scheme, port).
WEB_PORTS = (
    ("http", 80), ("http", 8080), ("http", 8000), ("https", 443), ("https", 8443),
    ("http", 3000), ("http", 5000),
)
_TITLE_RE = re.compile(r"<title[^>]*>\s*([^<]+?)\s*</title>", re.IGNORECASE)

# 가짜 터널의 interface 주소. 문서용 대역(TEST-NET-1)이라 어떤 서버와도 겹치지 않는다.
FAKE_TUNNEL_IP = "192.0.2.10"


# 실행 안에서 워크스페이스마다 한 번만 찾는다. 찾은 대상 또는 못 찾은 이유(문자열).
_GATEWAY_TARGETS: dict[tuple[str, str], ZtnaTarget | str] = {}


@pytest.fixture
def ztna_target(case, run_context, lane, executor, access_controls) -> ZtnaTarget:
    key = (run_context.profile.name, str(getattr(lane.workspace, "name", lane.workspace)))
    found = _GATEWAY_TARGETS.get(key)
    if found is None:
        found = _gateway_target(executor, access_controls, run_context.profile.ztna or ZtnaTarget())
        _GATEWAY_TARGETS[key] = found
    if isinstance(found, str):
        environment_error(found)
    case.record(Step.SETUP, ok=True, kind=Kind.EVIDENCE, detail=found.how)
    return found


@pytest.fixture
def access_controls(console) -> AccessControlFactory:
    return AccessControlFactory(console)


@pytest.fixture
def access_policies(console) -> AccessPolicyFactory:
    return AccessPolicyFactory(console)


@pytest.fixture
def ztna_log(console) -> ZtnaLogReader:
    return ZtnaLogReader(console)


@pytest.fixture
def tunnels(console) -> TunnelFactory:
    return TunnelFactory(console)


@pytest.fixture
def ztna_tunnel(run_context) -> ZtnaTunnelTarget:
    """설정의 ztna_tunnel. 없으면 빈 값이고, 터널·포트·페이지 문구를 전부 찾아서 쓴다."""
    return run_context.profile.ztna_tunnel or ZtnaTunnelTarget()


def _server_id(access_controls: AccessControlFactory, ip: str) -> int:
    server_id = access_controls.gateway_server_id(ip)
    if server_id is None:
        environment_error(f"No ZTNA gateway in this tenant lists {ip} as a server")
    return server_id


def _url(host: str, port: int, scheme: str = "http") -> str:
    default = 443 if scheme == "https" else 80
    return f"{scheme}://{host}/" if port == default else f"{scheme}://{host}:{port}/"


def _fetch(executor, url: str, timeout_sec: int = 15) -> tuple[TrafficResult, str]:
    """단말에서 URL을 요청해 (결과, 본문)을 돌려준다. 본문으로 페이지와 차단 페이지를 가린다."""
    result = executor.run(
        f'curl -k -s --max-time {timeout_sec} -w "\\n%{{http_code}}" "{url}"',
        timeout_sec=timeout_sec + 10,
    )
    body, _, code = result.stdout.rstrip().rpartition("\n")
    status = int(code) if code.strip().isdigit() else None
    traffic = TrafficResult(
        url=url,
        status_code=status,
        blocked=bool(status) and status in BLOCK_STATUS_CODES,
        via="curl",
        detail=f"HTTP {status}" if status else (result.stderr.strip()[:200] or "no response"),
        delivered=is_delivered_status(status),
    )
    return traffic, body


def _fetch_until(executor, url: str, want, timeout_sec: int) -> tuple[TrafficResult, str]:
    last: dict = {}

    def probe():
        traffic, body = _fetch(executor, url)
        last["value"] = (traffic, body)
        return last["value"] if want(traffic, body) else None

    try:
        return poll_until(probe, timeout_sec=timeout_sec, description=f"{url}", initial_interval=2.0)
    except PollTimeout:
        return last["value"]


def _page_marker(body: str) -> str:
    """페이지를 알아볼 문구: <title>. 없으면 빈 문자열(그때는 응답 코드로만 판정)."""
    match = _TITLE_RE.search(body or "")
    return match.group(1).strip() if match else ""


def _scheme_of(port: int) -> str:
    return "https" if port in (443, 8443) else "http"


def _gateway_target(executor, access_controls: AccessControlFactory, configured: ZtnaTarget) -> ZtnaTarget | str:
    """게이트웨이 뒤에서 규칙 없이 열리는 웹 페이지를 찾는다. 못 찾으면 그 이유(문자열).

    설정에 적힌 값(server_ip, port, page_text, domain, other_ip)이 우선이다. 서버는 게이트웨이
    서버 목록에서 id 순으로, 포트는 WEB_PORTS를 차례로 서버 IP로 열어 처음 응답한 곳을 쓴다.
    페이지 문구가 없으면 그 페이지의 <title>, 도메인이 없으면 콘솔이 그 서버에 붙인 도메인을
    쓴다. other_ip가 없으면 같은 scheme·포트로 열리는 다른 서버를 찾는다(없으면 빈 값).
    규칙을 만들기 전에 하므로 이 확인이 곧 기준선이다.
    """
    servers = access_controls.gateway_servers()
    if configured.server_ip:
        servers = [s for s in servers if str(s.get("ip")) == configured.server_ip]
        if not servers:
            return f"No ZTNA gateway in this tenant lists {configured.server_ip} (ztna.server_ip) as a server"
    if not servers:
        return "No ZTNA gateway server in this workspace, so there is no internal server to open"
    ports = [(_scheme_of(configured.port), configured.port)] if configured.port else list(WEB_PORTS)

    tried: list[str] = []
    for server in servers:
        ip = str(server["ip"])
        for scheme, port in ports:
            url = _url(ip, port, scheme)
            traffic, body = _fetch(executor, url, timeout_sec=6)
            if not traffic.delivered:
                tried.append(f"{url} {describe(traffic)}")
                continue
            if configured.page_text and configured.page_text not in body:
                tried.append(f"{url} HTTP {traffic.status_code} without {configured.page_text!r}")
                continue
            page_text = configured.page_text or _page_marker(body)
            domain = configured.domain or str(server.get("domain") or "").strip()
            other_ip, other_how = configured.other_ip, "from config"
            if not other_ip:
                other_ip, other_how = "", "none answers on that port"
                for candidate in access_controls.gateway_servers():
                    candidate_ip = str(candidate["ip"])
                    if candidate_ip == ip:
                        continue
                    other, _ = _fetch(executor, _url(candidate_ip, port, scheme), timeout_sec=6)
                    if other.delivered:
                        other_ip, other_how = candidate_ip, "discovered"
                        break

            def origin(value: str) -> str:
                return "from config" if value else "discovered"

            how = (
                f"gateway server id={server['id']} {ip} ({origin(configured.server_ip)}), "
                f"page {url} (HTTP {traffic.status_code}, port {origin(str(configured.port or ''))}), "
                f"page text {page_text!r}"
                f"{' from config' if configured.page_text else ' from <title>' if page_text else ' (none)'}, "
                f"domain {domain or '(none)'}"
                f"{' from config' if configured.domain else ' from the gateway server' if domain else ''}, "
                f"other server {other_ip or '(none)'} ({other_how})"
            )
            return ZtnaTarget(
                server_ip=ip, domain=domain, port=port, page_text=page_text,
                other_ip=other_ip, scheme=scheme, how=how,
            )
    return f"No web page opens on any ZTNA gateway server without a BAT rule: {tried[:8]}"


def _need_domain(target: ZtnaTarget) -> str:
    if not target.domain:
        environment_error(
            f"Gateway server {target.server_ip} has no domain registered in the console "
            f"(and ztna.domain is not set), so there is no name to build a domain access control on"
        )
    return target.domain


def _blocked_by(control_name: str):
    """그 접근제어의 차단 페이지("blocked by <접근제어 이름>")가 돌아왔다."""
    return lambda traffic, body: traffic.blocked and f"blocked by {control_name}" in body


def _expect_page(case, traffic: TrafficResult, body: str, page_text: str, url: str) -> None:
    """서버 페이지가 열렸다. page_text가 설정돼 있으면 본문에 있어야 한다."""
    if not expect_delivered(
        case, traffic, expected="internal server page", failure=f"{url} should have opened",
    ):
        unverified(case, Step.USER_RESULT, f"{url} gave no usable answer ({describe(traffic)})")
    if page_text:
        found = page_text in body
        case.record(
            Step.USER_RESULT,
            ok=found,
            detail=f"page text {page_text!r} {'found' if found else 'missing'}",
            expected=f"body contains {page_text!r}",
            actual=body[:200],
        )
        assert found, (
            f"{url} answered HTTP {traffic.status_code} but the body is not the internal "
            f"server's page ({page_text!r} missing)"
        )


def _expect_block_page(case, traffic: TrafficResult, body: str, control_name: str, url: str) -> None:
    blocked = _blocked_by(control_name)(traffic, body)
    case.record(
        Step.USER_RESULT,
        ok=blocked,
        detail=describe(traffic),
        expected=f"block page naming {control_name}",
        actual=describe(traffic) if blocked else f"{describe(traffic)}: {body[:150]}",
        kind=Kind.ASSERTION,
    )
    assert blocked, f"{url} was not blocked by {control_name}: {describe(traffic)}"


def _expect_row(
    case, ztna_log: ZtnaLogReader, run_context, *, since: datetime, control: str, policy: str,
    action: str, destination: str, device_id: str,
) -> SecurityEvent:
    expected = {
        "access_control_name": control, "access_policy_name": policy, "action": action,
        "dst_ip": destination or "(any)", "device_id": device_id or "(any)",
    }
    try:
        event = ztna_log.wait_for(
            matches_access(
                access_control=control, access_policy=policy, action=action,
                destination=destination, device_id=device_id,
            ),
            since=since,
            timeout_sec=run_context.event_poll_timeout_sec,
            description=f"{action} row for {control} to {destination}",
        )
    except PollTimeout:
        seen = sorted({
            (e.raw.get("action"), e.raw.get("dst_ip"), e.raw.get("access_control_name"))
            for e in ztna_log.events(since=since)
        })
        case.record(
            Step.EVENT, ok=False, detail=f"no matching row; rows since then: {seen[:10]}",
            expected=expected, actual=seen[:10],
        )
        raise AssertionError(
            f"No ZTNA log row for {control} ({action} to {destination}) within "
            f"{run_context.event_poll_timeout_sec}s"
        )
    case.event_ids.append(event.event_id)
    case.record(
        Step.EVENT,
        ok=True,
        detail=f"service_security_log id={event.event_id} at {event.raw.get('time')}",
        expected=expected,
        actual={key: event.raw.get(key) for key in expected},
        kind=Kind.ASSERTION,
    )
    return event


def _device(lane, executor) -> str:
    device, _ = endpoint_device_id(lane, executor)
    return device


@pytest.mark.case("BAT-ZTNA-009")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
@pytest.mark.smoke
def test_domain_access_control_opens_the_internal_server(
    case, run_context, lane, executor, ztna_target, access_controls, access_policies, ztna_log
):
    """도메인으로 등록한 접근제어로 커넥터에서 내부 서버 페이지가 열리고, 그 접속이 BAT 규칙 이름으로 ZTNA 로그에 남는다."""
    target = ztna_target
    _need_domain(target)
    server_id = _server_id(access_controls, target.server_ip)
    device = _device(lane, executor)
    url = _url(target.domain, target.port, target.scheme)
    policy_name = resource_name(case.case_id, run_context.run_id, "ap")
    control_name = resource_name(case.case_id, run_context.run_id)
    entry = AccessControlFactory.via_gateway(server_id, target.port, domain=target.domain)

    try:
        with access_policies.temporary(policy_name, EVERYONE, action_type="LOGGING") as policy:
            case.policy_ids.append(policy.policy_id)
            with access_controls.temporary(control_name, [entry], policy_id=policy.policy_id) as control:
                case.policy_ids.append(control.policy_id)
                since = datetime.now(timezone.utc)
                case.record(
                    Step.SETUP, ok=True, kind=Kind.EVIDENCE,
                    detail=f"access control {control_name} (id={control.policy_id}, priority 0): "
                    f"{target.domain}:{target.port} via gateway server {server_id}, "
                    f"LOGGING policy {policy_name} (id={policy.policy_id})",
                )

                traffic, body = _fetch(executor, url)
                _expect_page(case, traffic, body, target.page_text, url)
                _expect_row(
                    case, ztna_log, run_context, since=since, control=control_name,
                    policy=policy_name, action="AP_LOGGING",
                    destination=f"{target.server_ip}:{target.port}", device_id=device,
                )
                pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-ZTNA-010")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
@pytest.mark.critical
def test_blocked_domain_access_control_stops_only_that_server(
    case, run_context, lane, executor, ztna_target, access_controls, access_policies, ztna_log
):
    """도메인 접근제어에 BLOCK 접근정책을 연결하면 그 서버만 도메인·IP 모두 차단되고, 지우면 다시 열린다."""
    target = ztna_target
    _need_domain(target)
    server_id = _server_id(access_controls, target.server_ip)
    device = _device(lane, executor)
    by_name = _url(target.domain, target.port, target.scheme)
    by_ip = _url(target.server_ip, target.port, target.scheme)
    policy_name = resource_name(case.case_id, run_context.run_id, "ap")
    control_name = resource_name(case.case_id, run_context.run_id)
    entry = AccessControlFactory.via_gateway(server_id, target.port, domain=target.domain)
    budget = run_context.policy_propagation_timeout_sec

    before, body = _fetch(executor, by_name)
    if not before.delivered or (target.page_text and target.page_text not in body):
        environment_error(f"{by_name} does not open even without a BAT rule ({describe(before)})")

    try:
        with access_policies.temporary(policy_name, EVERYONE, action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)
            with access_controls.temporary(control_name, [entry], policy_id=policy.policy_id) as control:
                case.policy_ids.append(control.policy_id)
                since = datetime.now(timezone.utc)
                case.record(
                    Step.SETUP, ok=True, kind=Kind.EVIDENCE,
                    detail=f"access control {control_name} (id={control.policy_id}, priority 0): "
                    f"{target.domain}:{target.port}, BLOCK policy {policy_name} (id={policy.policy_id})",
                )

                for url in (by_name, by_ip):
                    traffic, body = _fetch_until(executor, url, _blocked_by(control_name), budget)
                    _expect_block_page(case, traffic, body, control_name, url)

                if target.other_ip:
                    other = _url(target.other_ip, target.port, target.scheme)
                    traffic, _ = _fetch(executor, other)
                    expect_delivered(
                        case, traffic, expected="another internal server still opens",
                        failure=f"{control_name} names only {target.domain} but {other} was blocked too",
                    )

                _expect_row(
                    case, ztna_log, run_context, since=since, control=control_name,
                    policy=policy_name, action="AP_BLOCK",
                    destination=f"{target.server_ip}:{target.port}", device_id=device,
                )
    except CleanupWarning as warning:
        cleanup_failed(case, warning)
        return

    # 차단이 풀리는 것도 이 시나리오의 일부라 두 리소스를 지운 뒤에 본다.
    traffic, body = _fetch_until(
        executor, by_name, lambda t, b: t.delivered and (not target.page_text or target.page_text in b),
        budget,
    )
    _expect_page(case, traffic, body, target.page_text, by_name)
    pass_case(case)


@pytest.mark.case("BAT-ZTNA-011")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P2")
def test_ip_access_control_opens_the_internal_server(
    case, run_context, lane, executor, ztna_target, access_controls, access_policies, ztna_log
):
    """IP로 등록한 접근제어로 커넥터에서 내부 서버 IP에 접속되고, 그 접속이 BAT 규칙 이름으로 ZTNA 로그에 남는다."""
    target = ztna_target
    server_id = _server_id(access_controls, target.server_ip)
    device = _device(lane, executor)
    url = _url(target.server_ip, target.port, target.scheme)
    policy_name = resource_name(case.case_id, run_context.run_id, "ap")
    control_name = resource_name(case.case_id, run_context.run_id)
    entry = AccessControlFactory.via_gateway(server_id, target.port, ip=target.server_ip)

    try:
        with access_policies.temporary(policy_name, EVERYONE, action_type="LOGGING") as policy:
            case.policy_ids.append(policy.policy_id)
            with access_controls.temporary(control_name, [entry], policy_id=policy.policy_id) as control:
                case.policy_ids.append(control.policy_id)
                since = datetime.now(timezone.utc)
                case.record(
                    Step.SETUP, ok=True, kind=Kind.EVIDENCE,
                    detail=f"access control {control_name} (id={control.policy_id}, priority 0): "
                    f"{target.server_ip}:{target.port}, LOGGING policy {policy_name}",
                )

                traffic, body = _fetch(executor, url)
                _expect_page(case, traffic, body, target.page_text, url)
                _expect_row(
                    case, ztna_log, run_context, since=since, control=control_name,
                    policy=policy_name, action="AP_LOGGING",
                    destination=f"{target.server_ip}:{target.port}", device_id=device,
                )
                pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-ZTNA-012")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P2")
def test_ip_access_control_block_stays_on_its_ip(
    case, run_context, executor, ztna_target, access_controls, access_policies, ztna_log
):
    """IP로만 등록한 접근제어에 BLOCK을 연결하면 그 IP만 막히고, 같은 포트의 다른 내부 서버는 열린다."""
    target = ztna_target
    if not target.other_ip:
        environment_error(
            f"No other gateway server answers on port {target.port} without a BAT rule (and ztna.other_ip "
            f"is not set), so there is no second server to check the scope on"
        )
    server_id = _server_id(access_controls, target.server_ip)
    mine = _url(target.server_ip, target.port, target.scheme)
    other = _url(target.other_ip, target.port, target.scheme)
    policy_name = resource_name(case.case_id, run_context.run_id, "ap")
    control_name = resource_name(case.case_id, run_context.run_id)
    entry = AccessControlFactory.via_gateway(server_id, target.port, ip=target.server_ip)

    before, _ = _fetch(executor, other)
    if not before.delivered:
        environment_error(f"{other} does not open even without a BAT rule ({describe(before)})")

    try:
        with access_policies.temporary(policy_name, EVERYONE, action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)
            with access_controls.temporary(control_name, [entry], policy_id=policy.policy_id) as control:
                case.policy_ids.append(control.policy_id)
                since = datetime.now(timezone.utc)
                case.record(
                    Step.SETUP, ok=True, kind=Kind.EVIDENCE,
                    detail=f"access control {control_name} (id={control.policy_id}, priority 0): "
                    f"{target.server_ip}:{target.port} (no domain), BLOCK policy {policy_name}",
                )

                traffic, body = _fetch_until(
                    executor, mine, _blocked_by(control_name), run_context.policy_propagation_timeout_sec
                )
                _expect_block_page(case, traffic, body, control_name, mine)

                traffic, body = _fetch(executor, other)
                if not traffic.delivered:
                    rows = [
                        e for e in ztna_log.events(since=since)
                        if e.raw.get("access_control_name") == control_name
                        and str(e.raw.get("dst_ip") or "").startswith(f"{target.other_ip}:")
                    ]
                    case.record(
                        Step.EVENT, ok=bool(rows), kind=Kind.EVIDENCE,
                        detail=f"{len(rows)} row(s) of {control_name} for {target.other_ip}",
                    )
                expect_delivered(
                    case, traffic, expected=f"{other} still opens",
                    failure=f"{control_name} names only {target.server_ip} but also blocked {other}",
                )
                pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-ZTNA-013")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_gateway_server_domain_opens_through_the_connector(
    case, run_context, lane, executor, browser_session, ztna_target, access_controls,
    access_policies, ztna_log,
):
    """게이트웨이 서버에 등록한 도메인이 커넥터에서 그 서버 IP로 풀려 브라우저와 curl로 페이지가 열리고, 그 도메인으로 만든 접근제어가 접속을 기록한다."""
    target = ztna_target
    server = access_controls.gateway_server(target.server_ip)
    if server is None:
        environment_error(f"No ZTNA gateway in this tenant lists {target.server_ip} as a server")
    domain = str(server.get("domain") or "").strip()
    if not domain:
        environment_error(
            f"Gateway server {target.server_ip} (id={server['id']}) has no domain registered in the console"
        )
    server_id = int(server["id"])
    device = _device(lane, executor)
    url = _url(domain, target.port, target.scheme)
    case.record(
        Step.SETUP, ok=True, kind=Kind.EVIDENCE,
        detail=f"gateway server id={server_id} {target.server_ip} has domain {domain}",
    )

    # 커넥터가 그 이름을 서버 IP로 답해야 한다(공용 DNS에는 다른 주소가 있을 수 있다).
    try:
        address = resolve_ip(executor, domain)
    except EndpointError as exc:
        address = ""
        detail = str(exc)[:200]
    else:
        detail = f"{domain} -> {address}"
    case.record(
        Step.USER_RESULT, ok=address == target.server_ip, detail=detail,
        expected=f"{domain} resolves to {target.server_ip}", actual=address or detail,
    )
    assert address == target.server_ip, (
        f"{domain} is the domain of gateway server {target.server_ip} but resolved to "
        f"{address or 'nothing'} on the endpoint"
    )

    policy_name = resource_name(case.case_id, run_context.run_id, "ap")
    control_name = resource_name(case.case_id, run_context.run_id)
    entry = AccessControlFactory.via_gateway(server_id, target.port, domain=domain)
    try:
        with access_policies.temporary(policy_name, EVERYONE, action_type="LOGGING") as policy:
            case.policy_ids.append(policy.policy_id)
            with access_controls.temporary(control_name, [entry], policy_id=policy.policy_id) as control:
                case.policy_ids.append(control.policy_id)
                since = datetime.now(timezone.utc)
                case.record(
                    Step.SETUP, ok=True, kind=Kind.EVIDENCE,
                    detail=f"access control {control_name} (id={control.policy_id}, priority 0): "
                    f"{domain}:{target.port} via gateway server {server_id}, "
                    f"LOGGING policy {policy_name} (id={policy.policy_id})",
                )

                traffic, body = _fetch(executor, url)
                _expect_page(case, traffic, body, target.page_text, url)
                visit = browser_session.visit(url, case_id=case.case_id)
                if not expect_delivered(
                    case, visit, expected="internal server page in the browser",
                    failure=f"{url} should have opened in the browser",
                ):
                    unverified(case, Step.USER_RESULT, f"browser got no usable answer ({describe(visit)})")
                _expect_row(
                    case, ztna_log, run_context, since=since, control=control_name,
                    policy=policy_name, action="AP_LOGGING",
                    destination=f"{target.server_ip}:{target.port}", device_id=device,
                )
                pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


def _resolves_to(executor, domain: str) -> str:
    """단말에서 domain이 풀린 IPv4 주소. 안 풀리면 빈 문자열."""
    try:
        return resolve_ip(executor, domain)
    except EndpointError:
        return ""


def _wait_resolution(executor, domain: str, want, timeout_sec: int) -> str:
    """want(주소)가 참이 될 때까지 조회를 되풀이하고 마지막 주소를 돌려준다."""
    last = {"address": ""}

    def probe():
        last["address"] = _resolves_to(executor, domain)
        return True if want(last["address"]) else None

    try:
        poll_until(probe, timeout_sec=timeout_sec, description=f"resolution of {domain}", initial_interval=2.0)
    except PollTimeout:
        pass
    return last["address"]


@pytest.mark.case("BAT-ZTNA-014")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P2")
def test_registered_tunnel_reaches_the_connector_and_leaves_on_delete(case, run_context, executor, tunnels):
    """커넥터를 설치하지 않은 터널을 등록하면 그 도메인이 단말에서 터널 주소로 풀리지만 접속은 되지 않고, 지우면 이름이 사라진다."""
    domain = f"bat-{run_context.run_id}.tunnel.internal".lower()
    name = resource_name(case.case_id, run_context.run_id)
    workspace = run_context.workspaces[0].name
    budget = max(run_context.policy_propagation_timeout_sec, 60)

    if _resolves_to(executor, domain):
        environment_error(f"{domain} already resolves before the tunnel exists")

    try:
        with tunnels.temporary(name, [{"ip": FAKE_TUNNEL_IP, "domain": domain}]) as tunnel:
            case.policy_ids.append(tunnel.policy_id)
            row = tunnels.find(name) or {}
            case.record(
                Step.SETUP, ok=True, kind=Kind.EVIDENCE,
                detail=f"tunnel {name} (id={tunnel.policy_id}): interface {row.get('interface')}, "
                f"connect_status={row.get('connect_status')}, server_ip={row.get('server_ip')}",
            )
            connected = bool(row.get("connect_status"))
            case.record(
                Step.SETUP, ok=not connected, kind=Kind.ASSERTION,
                detail=f"connect_status={row.get('connect_status')}",
                expected="a tunnel without an installed connector is not connected",
            )
            assert not connected, f"tunnel {name} has no connector installed but shows as connected"

            # 인증 파일은 값(자격증명)을 남기지 않고 형태만 확인한다.
            auth = tunnels.auth_file(tunnel.policy_id)
            try:
                auth_workspace = base64.b64decode(str(auth.get("workspace") or "")).decode("utf-8")
            except ValueError:
                auth_workspace = ""
            usable = auth_workspace == workspace and bool(auth.get("access_id"))
            case.record(
                Step.SETUP, ok=usable, kind=Kind.ASSERTION,
                detail=f"auth file keys {sorted(auth)}, workspace={auth_workspace}",
                expected=f"auth file for workspace {workspace} with an access_id",
            )
            assert usable, f"auth file of tunnel {name} is not usable (keys {sorted(auth)}, workspace {auth_workspace!r})"

            address = _wait_resolution(executor, domain, lambda a: a == FAKE_TUNNEL_IP, budget)
            case.record(
                Step.USER_RESULT, ok=address == FAKE_TUNNEL_IP, kind=Kind.ASSERTION,
                detail=f"{domain} -> {address or 'not resolved'}",
                expected=f"{domain} resolves to {FAKE_TUNNEL_IP} within {budget}s",
            )
            assert address == FAKE_TUNNEL_IP, (
                f"{domain} of the new tunnel did not resolve to {FAKE_TUNNEL_IP} within {budget}s "
                f"(got {address or 'nothing'})"
            )

            traffic, _ = _fetch(executor, _url(FAKE_TUNNEL_IP, 80), timeout_sec=10)
            case.record(
                Step.USER_RESULT, ok=not traffic.delivered, kind=Kind.ASSERTION,
                detail=describe(traffic), expected="a tunnel that is not connected does not open",
            )
            assert not traffic.delivered, f"{FAKE_TUNNEL_IP} answered although its tunnel is not connected"
    except CleanupWarning as warning:
        cleanup_failed(case, warning)
        return

    # 이름이 사라지는 것도 이 시나리오의 일부라 터널을 지운 뒤에 본다.
    address = _wait_resolution(executor, domain, lambda a: not a, budget)
    case.record(
        Step.USER_RESULT, ok=not address, kind=Kind.ASSERTION,
        detail=f"{domain} -> {address or 'not resolved'} after delete",
        expected=f"{domain} no longer resolves within {budget}s of deleting the tunnel",
    )
    assert not address, f"{domain} still resolves to {address} {budget}s after the tunnel was deleted"
    pass_case(case)


@dataclass(frozen=True)
class TunnelService:
    """BAT 규칙 없이 터널 너머로 열리는 웹 페이지."""

    tunnel: dict
    interface: dict
    host: str
    port: int
    url: str
    page_text: str
    how: str


def _tunnel_service(case, executor, tunnels: TunnelFactory, target: ZtnaTunnelTarget) -> TunnelService:
    """연결된 터널과 그 너머의 웹 페이지를 찾는다. 설정에 적힌 값(이름, 포트, 문구)이 우선이다.

    이름이 없으면 연결된(콘솔의 초록불) 터널 중 BAT가 만든 것을 빼고 id 순으로 고른다.
    포트가 없으면 WEB_PORTS를 차례로 열어 처음 응답한 곳을 쓴다. 문구가 없으면
    그 페이지의 <title>을 쓴다. 규칙을 만들기 전에 하므로 이 확인이 곧 기준선이다.
    못 찾으면 실행 조건 미비다.
    """
    rows = tunnels.list()
    if target.name:
        candidates = [r for r in rows if r.get("name") == target.name]
        if not candidates:
            environment_error(f"No ZTNA tunnel named {target.name!r} in this workspace")
    else:
        candidates = sorted(
            (r for r in rows if not is_bat_resource(str(r.get("name") or ""))),
            key=lambda r: int(r.get("id") or 0),
        )
    connected = [r for r in candidates if r.get("connect_status")]
    if not connected:
        names = [f"{r.get('name')} (connected={r.get('connect_status')})" for r in candidates]
        environment_error(f"No connected ZTNA tunnel in this workspace (tunnels: {names or 'none'})")

    if target.port:
        ports = [("https" if target.port in (443, 8443) else "http", target.port)]
    else:
        ports = list(WEB_PORTS)
    tried: list[str] = []
    for tunnel in connected:
        for interface in tunnel.get("interface") or []:
            if not interface.get("ip") or interface.get("id") is None:
                continue
            host = str(interface.get("domain") or "") or str(interface["ip"])
            for scheme, port in ports:
                url = _url(host, port, scheme)
                traffic, body = _fetch(executor, url, timeout_sec=6)
                if not traffic.delivered:
                    tried.append(f"{url} {describe(traffic)}")
                    continue
                page_text = target.page_text or _page_marker(body)
                if target.page_text and target.page_text not in body:
                    tried.append(f"{url} HTTP {traffic.status_code} without {target.page_text!r}")
                    continue
                how = (
                    f"tunnel {tunnel.get('name')} (id={tunnel.get('id')}, connected"
                    f"{', from config' if target.name else ', discovered'}), interface "
                    f"{interface.get('id')} {interface.get('ip')} {interface.get('domain') or ''}, "
                    f"page {url} (HTTP {traffic.status_code}), page text {page_text!r}"
                    f"{' from config' if target.page_text else ' from <title>' if page_text else ' (none)'}"
                )
                case.record(Step.SETUP, ok=True, kind=Kind.EVIDENCE, detail=how)
                return TunnelService(tunnel, interface, host, port, url, page_text, how)
    environment_error(f"No web page opens behind the connected tunnel(s) without a BAT rule: {tried[:8]}")


def _tunnel_entry(service: TunnelService) -> dict:
    """도메인이 있으면 도메인으로 만든다(도메인 없는 항목은 포트만으로 매칭된다)."""
    domain = str(service.interface.get("domain") or "")
    return AccessControlFactory.via_tunnel(
        int(service.interface["id"]), service.port,
        domain=domain, ip="" if domain else str(service.interface["ip"]),
    )


def _record_destination(case, event: SecurityEvent) -> None:
    case.record(
        Step.EVENT, ok=True, kind=Kind.EVIDENCE,
        detail=f"tunnel row dst_ip={event.raw.get('dst_ip')} app_protocol={event.raw.get('app_protocol')}",
    )


@pytest.mark.case("BAT-ZTNA-015")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_tunnel_access_control_opens_the_server_behind_the_tunnel(
    case, run_context, lane, executor, ztna_tunnel, tunnels, access_controls, access_policies, ztna_log
):
    """실제로 연결된 터널을 대상으로 만든 접근제어로 커넥터에서 터널 뒤 서버 페이지가 열리고, 그 접속이 BAT 규칙 이름으로 ZTNA 로그에 남는다."""
    service = _tunnel_service(case, executor, tunnels, ztna_tunnel)
    entry = _tunnel_entry(service)
    device = _device(lane, executor)
    policy_name = resource_name(case.case_id, run_context.run_id, "ap")
    control_name = resource_name(case.case_id, run_context.run_id)

    try:
        with access_policies.temporary(policy_name, EVERYONE, action_type="LOGGING") as policy:
            case.policy_ids.append(policy.policy_id)
            with access_controls.temporary(control_name, [entry], policy_id=policy.policy_id) as control:
                case.policy_ids.append(control.policy_id)
                since = datetime.now(timezone.utc)
                case.record(
                    Step.SETUP, ok=True, kind=Kind.EVIDENCE,
                    detail=f"access control {control_name} (id={control.policy_id}, priority 0): "
                    f"{service.host}:{service.port} via tunnel interface {service.interface.get('id')}, "
                    f"LOGGING policy {policy_name} (id={policy.policy_id})",
                )

                traffic, body = _fetch(executor, service.url)
                _expect_page(case, traffic, body, service.page_text, service.url)
                event = _expect_row(
                    case, ztna_log, run_context, since=since, control=control_name,
                    policy=policy_name, action="AP_LOGGING", destination="", device_id=device,
                )
                _record_destination(case, event)
                pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-ZTNA-016")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_blocked_tunnel_access_control_stops_the_server_behind_the_tunnel(
    case, run_context, lane, executor, ztna_tunnel, tunnels, access_controls, access_policies, ztna_log
):
    """실제로 연결된 터널을 대상으로 만든 접근제어에 BLOCK 접근정책을 연결하면 터널 뒤 서버가 차단되고, 지우면 다시 열린다."""
    service = _tunnel_service(case, executor, tunnels, ztna_tunnel)  # 규칙 없이 열리는지가 기준선
    entry = _tunnel_entry(service)
    device = _device(lane, executor)
    policy_name = resource_name(case.case_id, run_context.run_id, "ap")
    control_name = resource_name(case.case_id, run_context.run_id)
    budget = run_context.policy_propagation_timeout_sec

    def opened(traffic: TrafficResult, body: str) -> bool:
        return traffic.delivered and (not service.page_text or service.page_text in body)

    try:
        with access_policies.temporary(policy_name, EVERYONE, action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)
            with access_controls.temporary(control_name, [entry], policy_id=policy.policy_id) as control:
                case.policy_ids.append(control.policy_id)
                since = datetime.now(timezone.utc)
                case.record(
                    Step.SETUP, ok=True, kind=Kind.EVIDENCE,
                    detail=f"access control {control_name} (id={control.policy_id}, priority 0): "
                    f"{service.host}:{service.port} via tunnel interface {service.interface.get('id')}, "
                    f"BLOCK policy {policy_name} (id={policy.policy_id})",
                )
                traffic, body = _fetch_until(executor, service.url, _blocked_by(control_name), budget)
                _expect_block_page(case, traffic, body, control_name, service.url)
                event = _expect_row(
                    case, ztna_log, run_context, since=since, control=control_name,
                    policy=policy_name, action="AP_BLOCK", destination="", device_id=device,
                )
                _record_destination(case, event)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)
        return

    # 차단이 풀리는 것도 이 시나리오의 일부라 두 리소스를 지운 뒤에 본다.
    traffic, body = _fetch_until(executor, service.url, opened, budget)
    _expect_page(case, traffic, body, service.page_text, service.url)
    pass_case(case)
