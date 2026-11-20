"""ZTNA 트래픽 케이스: 접근제어로 내부 서버가 실제로 열리고 막히는지 본다.

게이트웨이와 터널은 단말에서 보면 같게 동작한다(접근제어의 target_type만 다르다). 그래서
대상은 둘 중 있는 쪽에서 설정 없이 찾는다(`_ztna_target`): 먼저 게이트웨이 서버 목록(콘솔
도메인이 있는 서버 먼저, id 순)에서 흔한 웹 포트 중 규칙 없이 처음 열리는 서버와 포트,
없으면 연결된 터널의 interface에서 같은 방법으로. 그 페이지의 <title>, 콘솔이 붙인 도메인
(커넥터가 직접 답하는 이름), 같은 포트로 열리는 다른 서버도 찾는다. 스테이지 블록의 `ztna:`
(server_ip, domain, port, page_text, other_ip)와 `ztna_tunnel:`(name, port, page_text)에 적힌
값이 있으면 그 값이 우선이다. 둘 다 열리는 서버가 없으면 실행 조건 미비(BAT_ERROR)다.

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
import time
from dataclasses import replace
from datetime import datetime, timezone

import httpx
import pytest

from bat.clients.auth_server import AppLauncherSession, launcher_env, launcher_url
from bat.clients.tokens import load_console_token, save_console_token
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
    block_page_rule,
    cleanup_failed,
    describe,
    endpoint_device_id,
    environment_error,
    expect_delivered,
    expect_hold,
    hold_after_change,
    pass_case,
    policy_changed,
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
def ztna_target(case, run_context, lane, executor, access_controls, tunnels, ztna_tunnel, ztna_log) -> ZtnaTarget:
    key = (run_context.profile.name, str(getattr(lane.workspace, "name", lane.workspace)))
    found = _GATEWAY_TARGETS.get(key)
    if found is None:
        started = datetime.now(timezone.utc)
        found = _ztna_target(
            executor, access_controls, tunnels, run_context.profile.ztna or ZtnaTarget(), ztna_tunnel
        )
        if isinstance(found, str):
            found += _recent_ztna_rows(ztna_log, started)
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


def summarize_ztna_rows(rows: list[dict]) -> str:
    """ZTNA 로그 행을 (동작, 접근제어, 목적지)별 개수로. 열리지 않은 이유(예: 사용자 규칙의
    DPC_FAIL, AP_BLOCK)를 오류 메시지에 남기는 데 쓴다."""
    counts: dict[tuple[str, str, str], int] = {}
    for row in rows:
        key = (str(row.get("action") or ""), str(row.get("access_control_name") or ""), str(row.get("dst_ip") or ""))
        counts[key] = counts.get(key, 0) + 1
    if not counts:
        return "; the ZTNA log has no rows for those requests"
    parts = [f"{action} by {control or '-'} to {dst} x{n}" for (action, control, dst), n in sorted(counts.items())]
    return "; ZTNA log for those requests: " + ", ".join(parts)


def _recent_ztna_rows(ztna_log: ZtnaLogReader, since: datetime) -> str:
    """since 뒤의 ZTNA 로그 요약. 행은 10초쯤 늦게 찍혀 20초까지 기다린다. 로그를 못 읽으면 그
    사실을 적는다(대상 탐색 실패를 가리지 않는다)."""
    try:
        try:
            rows = poll_until(
                lambda: [event.raw for event in ztna_log.events(since=since)] or None,
                timeout_sec=20, description="ZTNA log rows for the target search", initial_interval=3.0,
            )
        except PollTimeout:
            rows = []
        return summarize_ztna_rows(rows)
    except Exception as exc:  # noqa: BLE001 - 이미 실패한 탐색에 덧붙이는 정보다
        return f"; the ZTNA log could not be read ({type(exc).__name__})"


def _entry(target: ZtnaTarget, *, by_domain: bool) -> dict:
    """대상의 접근제어 항목. by_domain이면 target.domain으로, 아니면 IP만으로 만든다."""
    make = AccessControlFactory.via_tunnel if target.via == "tunnel" else AccessControlFactory.via_gateway
    if by_domain:
        return make(target.target_id, target.port, domain=target.domain)
    return make(target.target_id, target.port, ip=target.server_ip)


def _where(target: ZtnaTarget) -> str:
    kind = "tunnel interface" if target.via == "tunnel" else "gateway server"
    return f"{kind} {target.target_id}"


def _log_destination(target: ZtnaTarget) -> str:
    """ZTNA 로그 행에서 기대하는 dst_ip. 게이트웨이는 "<서버 IP>:<포트>"로 확인돼 있다.
    터널 행의 dst_ip 형태는 아직 실측하지 못해 비워 두고(아무 값), 행에 찍힌 값을 근거로 남긴다."""
    return "" if target.via == "tunnel" else f"{target.server_ip}:{target.port}"


def _url(host: str, port: int, scheme: str = "http") -> str:
    default = 443 if scheme == "https" else 80
    return f"{scheme}://{host}/" if port == default else f"{scheme}://{host}:{port}/"


def _fetch(executor, url: str, timeout_sec: int = 15, user_agent: str = "") -> tuple[TrafficResult, str]:
    """단말에서 URL을 요청해 (결과, 본문)을 돌려준다. 본문으로 페이지와 차단 페이지를 가린다.
    user_agent를 주면 그 User-Agent로 보낸다(접근정책 OS 조건이 이 값을 본다)."""
    agent = f'-A "{user_agent}" ' if user_agent else ""
    result = executor.run(
        f'curl -k -s --max-time {timeout_sec} {agent}-w "\\n%{{http_code}}" "{url}"',
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


def _open_page(
    executor, candidates: list[dict], configured: ZtnaTarget, *, via: str, configured_where: object,
    others: list[dict] | None = None,
) -> ZtnaTarget | list[str]:
    """candidates({id, ip, domain, label}) 중 규칙 없이 웹 페이지가 열리는 첫 서버. 못 찾으면 시도한 URL들.

    포트는 설정에 있으면 그 하나, 없으면 WEB_PORTS를 차례로 서버 IP로 연다. 페이지 문구가 없으면
    그 페이지의 <title>, 도메인이 없으면 콘솔이 그 서버에 붙인 도메인을 쓴다. other_ip가 없으면
    같은 scheme·포트로 열리는 다른 서버를 others(없으면 candidates)에서 찾는다(없으면 빈 값). 규칙을 만들기 전에 하므로 이
    확인이 곧 기준선이다.
    """
    ports = [(_scheme_of(configured.port), configured.port)] if configured.port else list(WEB_PORTS)
    tried: list[str] = []
    for server in candidates:
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
            registered = str(server.get("domain") or "").strip()
            domain = configured.domain or registered
            other_ip, other_how = configured.other_ip, "from config"
            if not other_ip:
                other_ip, other_how = "", "none answers on that port"
                for candidate in others if others is not None else candidates:
                    candidate_ip = str(candidate["ip"])
                    if candidate_ip == ip:
                        continue
                    other, _ = _fetch(executor, _url(candidate_ip, port, scheme), timeout_sec=6)
                    if other.delivered:
                        other_ip, other_how = candidate_ip, "discovered"
                        break

            def origin(value: object) -> str:
                return "from config" if value else "discovered"

            how = (
                f"{server['label']} {ip} ({origin(configured_where)}), "
                f"page {url} (HTTP {traffic.status_code}, port {origin(configured.port)}), "
                f"page text {page_text!r}"
                f"{' from config' if configured.page_text else ' from <title>' if page_text else ' (none)'}, "
                f"domain {domain or '(none)'}"
                f"{' from config' if configured.domain else ' registered in the console' if domain else ''}, "
                f"other server {other_ip or '(none)'} ({other_how})"
            )
            return ZtnaTarget(
                server_ip=ip, domain=domain, port=port, page_text=page_text, other_ip=other_ip,
                scheme=scheme, how=how, via=via, target_id=int(server["id"]), registered_domain=registered,
            )
    return tried


def _by_domain_first(candidates: list[dict], configured: ZtnaTarget) -> list[dict]:
    """도메인 케이스(009/010/013)는 콘솔 도메인이 필요하다. 도메인이 있는 후보를 먼저 연다(안정 정렬)."""
    if configured.domain:
        return candidates
    return sorted(candidates, key=lambda c: not str(c.get("domain") or "").strip())


def _gateway_target(executor, access_controls: AccessControlFactory, configured: ZtnaTarget) -> ZtnaTarget | str:
    """게이트웨이 서버 뒤에서 규칙 없이 열리는 웹 페이지(_open_page). 못 찾으면 그 이유(문자열).

    설정의 server_ip가 있으면 그 서버만 본다. 서버는 콘솔 도메인이 있는 것을 먼저, 그 안에서
    id 순으로 연다.
    """
    every = access_controls.gateway_servers()
    servers = every
    if configured.server_ip:
        servers = [s for s in servers if str(s.get("ip")) == configured.server_ip]
        if not servers:
            return f"No ZTNA gateway in this tenant lists {configured.server_ip} (ztna.server_ip) as a server"
    if not servers:
        return "No ZTNA gateway server in this workspace"
    candidates = [{**s, "label": f"gateway server id={s['id']}"} for s in servers]
    found = _open_page(
        executor, _by_domain_first(candidates, configured), configured,
        via="gateway", configured_where=configured.server_ip, others=every,
    )
    if isinstance(found, ZtnaTarget):
        return found
    return f"No web page opens on any ZTNA gateway server without a BAT rule: {found[:8]}"


def _tunnel_target(
    executor, tunnels: TunnelFactory, configured: ZtnaTarget, tunnel: ZtnaTunnelTarget,
) -> ZtnaTarget | str:
    """연결된(콘솔의 초록불) 터널의 interface 뒤에서 규칙 없이 열리는 웹 페이지(_open_page).

    터널 이름이 설정에 없으면 BAT가 만든 것을 빼고 id 순으로 본다. 포트·문구는 ztna_tunnel에
    적힌 값이 ztna보다 우선이다. 터널 접근제어의 target_id는 interface id다.
    """
    rows = tunnels.list()
    if tunnel.name:
        rows = [r for r in rows if r.get("name") == tunnel.name]
        if not rows:
            return f"No ZTNA tunnel named {tunnel.name!r} (ztna_tunnel.name) in this workspace"
    else:
        rows = sorted(
            (r for r in rows if not is_bat_resource(str(r.get("name") or ""))),
            key=lambda r: int(r.get("id") or 0),
        )
    connected = [r for r in rows if r.get("connect_status")]
    if not connected:
        names = [f"{r.get('name')} (connected={r.get('connect_status')})" for r in rows]
        return f"No connected ZTNA tunnel in this workspace (tunnels: {names or 'none'})"
    candidates = [
        {
            "id": interface["id"], "ip": interface["ip"], "domain": interface.get("domain"),
            "label": f"tunnel {row.get('name')} (id={row.get('id')}) interface id={interface['id']}",
        }
        for row in connected
        for interface in row.get("interface") or []
        if interface.get("ip") and interface.get("id") is not None
    ]
    settings = ZtnaTarget(
        domain=configured.domain, other_ip=configured.other_ip,
        port=tunnel.port or configured.port, page_text=tunnel.page_text or configured.page_text,
    )
    found = _open_page(
        executor, _by_domain_first(candidates, settings), settings, via="tunnel", configured_where=tunnel.name,
    )
    if isinstance(found, ZtnaTarget):
        return found
    return f"No web page opens behind the connected ZTNA tunnel(s) without a BAT rule: {found[:8]}"


def _ztna_target(
    executor, access_controls: AccessControlFactory, tunnels: TunnelFactory,
    configured: ZtnaTarget, tunnel: ZtnaTunnelTarget,
) -> ZtnaTarget | str:
    """게이트웨이와 터널 중 있는 쪽의 대상. 게이트웨이를 먼저 보고, 거기서 못 찾으면 터널을 본다.

    설정에 게이트웨이 서버(ztna.server_ip)가 적혀 있으면 터널로 넘어가지 않는다. 둘 다 못 찾으면
    두 이유를 합친 문자열이다.
    """
    gateway = _gateway_target(executor, access_controls, configured)
    if isinstance(gateway, ZtnaTarget) or configured.server_ip:
        return gateway
    found = _tunnel_target(executor, tunnels, configured, tunnel)
    if isinstance(found, ZtnaTarget):
        return replace(found, how=f"{found.how}; gateway: {gateway}")
    return f"Neither a ZTNA gateway server nor a connected tunnel opens a web page. Gateway: {gateway} Tunnel: {found}"


def _need_domain(target: ZtnaTarget) -> str:
    if not target.domain:
        environment_error(
            f"{_where(target)} ({target.server_ip}) has no domain registered in the console "
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
@pytest.mark.priority("P0")
@pytest.mark.gate
@pytest.mark.smoke
def test_domain_access_control_opens_the_internal_server(
    case, run_context, lane, executor, ztna_target, access_controls, access_policies, ztna_log
):
    """도메인으로 등록한 접근제어로 커넥터에서 내부 서버(게이트웨이 또는 터널 뒤) 페이지가 열리고, 그 접속이 BAT 규칙 이름으로 ZTNA 로그에 남는다."""
    target = ztna_target
    _need_domain(target)
    device = _device(lane, executor)
    url = _url(target.domain, target.port, target.scheme)
    policy_name = resource_name(case.case_id, run_context.run_id, "ap")
    control_name = resource_name(case.case_id, run_context.run_id)
    entry = _entry(target, by_domain=True)

    try:
        with access_policies.temporary(policy_name, EVERYONE, action_type="LOGGING") as policy:
            case.policy_ids.append(policy.policy_id)
            with access_controls.temporary(control_name, [entry], policy_id=policy.policy_id) as control:
                case.policy_ids.append(control.policy_id)
                since = datetime.now(timezone.utc)
                case.record(
                    Step.SETUP, ok=True, kind=Kind.EVIDENCE,
                    detail=f"access control {control_name} (id={control.policy_id}, priority 0): "
                    f"{target.domain}:{target.port} via {_where(target)}, "
                    f"LOGGING policy {policy_name} (id={policy.policy_id})",
                )

                traffic, body = _fetch(executor, url)
                _expect_page(case, traffic, body, target.page_text, url)
                _expect_row(
                    case, ztna_log, run_context, since=since, control=control_name,
                    policy=policy_name, action="AP_LOGGING",
                    destination=_log_destination(target), device_id=device,
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
    """도메인 접근제어에 BLOCK 접근정책을 연결하면 그 서버(게이트웨이 또는 터널 뒤)만 도메인·IP 모두 차단되고, 지우면 다시 열린다."""
    target = ztna_target
    _need_domain(target)
    device = _device(lane, executor)
    by_name = _url(target.domain, target.port, target.scheme)
    by_ip = _url(target.server_ip, target.port, target.scheme)
    policy_name = resource_name(case.case_id, run_context.run_id, "ap")
    control_name = resource_name(case.case_id, run_context.run_id)
    entry = _entry(target, by_domain=True)
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
                    f"{target.domain}:{target.port} via {_where(target)}, "
                    f"BLOCK policy {policy_name} (id={policy.policy_id})",
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
                    destination=_log_destination(target), device_id=device,
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
    """IP로 등록한 접근제어로 커넥터에서 내부 서버(게이트웨이 또는 터널 뒤) IP에 접속되고, 그 접속이 BAT 규칙 이름으로 ZTNA 로그에 남는다."""
    target = ztna_target
    device = _device(lane, executor)
    url = _url(target.server_ip, target.port, target.scheme)
    policy_name = resource_name(case.case_id, run_context.run_id, "ap")
    control_name = resource_name(case.case_id, run_context.run_id)
    entry = _entry(target, by_domain=False)

    try:
        with access_policies.temporary(policy_name, EVERYONE, action_type="LOGGING") as policy:
            case.policy_ids.append(policy.policy_id)
            with access_controls.temporary(control_name, [entry], policy_id=policy.policy_id) as control:
                case.policy_ids.append(control.policy_id)
                since = datetime.now(timezone.utc)
                case.record(
                    Step.SETUP, ok=True, kind=Kind.EVIDENCE,
                    detail=f"access control {control_name} (id={control.policy_id}, priority 0): "
                    f"{target.server_ip}:{target.port} via {_where(target)}, LOGGING policy {policy_name}",
                )

                traffic, body = _fetch(executor, url)
                _expect_page(case, traffic, body, target.page_text, url)
                _expect_row(
                    case, ztna_log, run_context, since=since, control=control_name,
                    policy=policy_name, action="AP_LOGGING",
                    destination=_log_destination(target), device_id=device,
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
            f"No other server ({target.via}) answers on port {target.port} without a BAT rule "
            f"(and ztna.other_ip is not set), so there is no second server to check the scope on"
        )
    mine = _url(target.server_ip, target.port, target.scheme)
    other = _url(target.other_ip, target.port, target.scheme)
    policy_name = resource_name(case.case_id, run_context.run_id, "ap")
    control_name = resource_name(case.case_id, run_context.run_id)
    entry = _entry(target, by_domain=False)

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
                    f"{target.server_ip}:{target.port} (no domain) via {_where(target)}, "
                    f"BLOCK policy {policy_name}",
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
                    named = block_page_rule(body) if traffic.blocked else ""
                    case.record(
                        Step.EVENT, ok=bool(rows), kind=Kind.EVIDENCE,
                        detail=f"{len(rows)} row(s) of {control_name} for {target.other_ip}; "
                        f"block page names {named or '(no rule name)'}",
                    )
                    # 다른 서버가 막혔어도 BAT 규칙이 막았다는 근거(차단 페이지의 규칙 이름이나 그
                    # 규칙의 로그)가 없으면 제품이 범위를 넘었다고 단정할 수 없다.
                    if traffic.blocked and not _blocked_by(control_name)(traffic, body) and not rows:
                        unverified(
                            case, Step.USER_RESULT,
                            f"{other} answered {describe(traffic)}, but neither the block page "
                            f"(names {named or 'no rule'}) nor the ZTNA log ties it to {control_name}",
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
    """게이트웨이 서버(또는 터널 interface)에 등록한 도메인이 커넥터에서 그 IP로 풀려 브라우저와 curl로 페이지가 열리고, 그 도메인으로 만든 접근제어가 접속을 기록한다."""
    target = ztna_target
    domain = target.registered_domain
    if not domain:
        environment_error(f"{_where(target)} ({target.server_ip}) has no domain registered in the console")
    device = _device(lane, executor)
    url = _url(domain, target.port, target.scheme)
    case.record(
        Step.SETUP, ok=True, kind=Kind.EVIDENCE,
        detail=f"{_where(target)} {target.server_ip} has domain {domain}",
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
        f"{domain} is the domain of {_where(target)} {target.server_ip} but resolved to "
        f"{address or 'nothing'} on the endpoint"
    )

    policy_name = resource_name(case.case_id, run_context.run_id, "ap")
    control_name = resource_name(case.case_id, run_context.run_id)
    entry = _entry(replace(target, domain=domain), by_domain=True)
    try:
        with access_policies.temporary(policy_name, EVERYONE, action_type="LOGGING") as policy:
            case.policy_ids.append(policy.policy_id)
            with access_controls.temporary(control_name, [entry], policy_id=policy.policy_id) as control:
                case.policy_ids.append(control.policy_id)
                since = datetime.now(timezone.utc)
                case.record(
                    Step.SETUP, ok=True, kind=Kind.EVIDENCE,
                    detail=f"access control {control_name} (id={control.policy_id}, priority 0): "
                    f"{domain}:{target.port} via {_where(target)}, "
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
                    destination=_log_destination(target), device_id=device,
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


# --- 규칙을 바꾼 뒤의 상태 ------------------------------------------------------
#
# 아래 케이스는 BAT 접근제어 하나(도메인 항목)에 BAT 접근정책 하나를 연결해 두고, 접근제어의
# 활성화나 접근정책의 동작·조건을 바꾼 뒤 그 서버가 막히는지 열리는지 본다. 바꿀 때마다
# 전파 예산 안에 한 번 기대한 상태가 되고, 예산이 지난 뒤 HOLD_REPEATS번 연속 그 상태여야
# 한다(hold_after_change). 막혔다는 것은 그 접근제어 이름의 차단 페이지, 열렸다는 것은 그
# 서버 페이지(페이지 문구 포함)다. 둘 다 아니면 판정할 수 없는 응답이다.


# 접근정책의 OS 조건은 HTTP User-Agent로 판정된다(2026-11-19 lguplus: os_id=Windows BLOCK이 이 UA
# 요청만 막고, curl 기본 UA와 macOS UA 요청은 그 규칙에 매칭되지 않았다). 그래서 OS 조건 케이스는
# 이 단말(Windows) 브라우저와 같은 UA로 보낸다.
WINDOWS_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)


def _state(executor, url: str, control_name: str, page_text: str, user_agent: str = ""):
    """요청 한 번을 상태로: blocked는 그 접근제어의 차단 페이지, delivered는 그 서버 페이지."""

    def check() -> TrafficResult:
        traffic, body = _fetch(executor, url, user_agent=user_agent)
        return replace(
            traffic,
            blocked=_blocked_by(control_name)(traffic, body),
            delivered=traffic.delivered and (not page_text or page_text in body),
        )

    return check


def _expect_state(
    case, check, *, blocked: bool, changed, budget: float, expected: str, failure: str,
    steady: bool = False,
) -> None:
    hold = hold_after_change(
        check,
        want=(lambda t: t.blocked) if blocked else (lambda t: t.delivered),
        against=(lambda t: t.delivered) if blocked else (lambda t: t.blocked),
        changed_at=changed.at,
        budget_sec=budget,
        steady=steady,
    )
    expect_hold(case, hold, expected=expected, failure=failure)


def _os_ids(access_policies: AccessPolicyFactory) -> tuple[int, int, str]:
    """(이 단말 OS id, 다른 OS id, 설명). 단말은 Windows다(실행기가 PowerShell로 돈다)."""
    catalog = {str(row.get("name") or ""): int(row["id"]) for row in access_policies.os_catalog()}
    if "Windows" not in catalog or "Linux" not in catalog:
        environment_error(f"OS catalog has no Windows/Linux entry: {sorted(catalog)}")
    return catalog["Windows"], catalog["Linux"], f"Windows={catalog['Windows']}, Linux={catalog['Linux']}"


def _open_without_rule(executor, target: ZtnaTarget, url: str) -> None:
    before, body = _fetch(executor, url)
    if not before.delivered or (target.page_text and target.page_text not in body):
        environment_error(f"{url} does not open even without a BAT rule ({describe(before)})")


@pytest.mark.case("BAT-ZTNA-017")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_disabled_access_control_stops_applying(
    case, run_context, lane, executor, ztna_target, access_controls, access_policies, ztna_log
):
    """BLOCK을 연결한 접근제어를 비활성화하면 그 서버가 다시 열리고, 다시 활성화하면 다시 차단된다."""
    target = ztna_target
    _need_domain(target)
    device = _device(lane, executor)
    url = _url(target.domain, target.port, target.scheme)
    policy_name = resource_name(case.case_id, run_context.run_id, "ap")
    control_name = resource_name(case.case_id, run_context.run_id)
    budget = run_context.policy_propagation_timeout_sec
    check = _state(executor, url, control_name, target.page_text)
    _open_without_rule(executor, target, url)

    try:
        with access_policies.temporary(policy_name, EVERYONE, action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)
            with access_controls.temporary(
                control_name, [_entry(target, by_domain=True)], policy_id=policy.policy_id
            ) as control:
                case.policy_ids.append(control.policy_id)
                changed = policy_changed(case, f"access control {control_name} created (enabled, BLOCK)")
                _expect_state(
                    case, check, blocked=True, changed=changed, budget=budget,
                    expected=f"{url} blocked by {control_name}",
                    failure=f"{url} was not blocked by the new BLOCK access control",
                )
                _expect_row(
                    case, ztna_log, run_context, since=changed.utc, control=control_name,
                    policy=policy_name, action="AP_BLOCK",
                    destination=_log_destination(target), device_id=device,
                )

                access_controls.set_enabled(control, False)
                changed = policy_changed(case, f"access control {control_name} disabled")
                _expect_state(
                    case, check, blocked=False, changed=changed, budget=budget,
                    expected=f"{url} opens while {control_name} is disabled",
                    failure=f"{url} stayed blocked after {control_name} was disabled",
                )

                access_controls.set_enabled(control, True)
                changed = policy_changed(case, f"access control {control_name} enabled again")
                _expect_state(
                    case, check, blocked=True, changed=changed, budget=budget,
                    expected=f"{url} blocked by {control_name} again",
                    failure=f"{url} was not blocked again after {control_name} was re-enabled",
                )
                pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-ZTNA-018")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_access_policy_edit_reaches_its_access_control(
    case, run_context, lane, executor, ztna_target, access_controls, access_policies, ztna_log
):
    """접근제어에 연결된 접근정책의 동작을 BLOCK에서 LOGGING으로 바꾸면 그 서버가 열리며 LOGGING으로 기록되고, 다시 BLOCK으로 바꾸면 차단된다."""
    target = ztna_target
    _need_domain(target)
    device = _device(lane, executor)
    url = _url(target.domain, target.port, target.scheme)
    policy_name = resource_name(case.case_id, run_context.run_id, "ap")
    control_name = resource_name(case.case_id, run_context.run_id)
    budget = run_context.policy_propagation_timeout_sec
    check = _state(executor, url, control_name, target.page_text)
    _open_without_rule(executor, target, url)

    try:
        with access_policies.temporary(policy_name, EVERYONE, action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)
            with access_controls.temporary(
                control_name, [_entry(target, by_domain=True)], policy_id=policy.policy_id
            ) as control:
                case.policy_ids.append(control.policy_id)
                changed = policy_changed(case, f"{control_name} created with BLOCK policy {policy_name}")
                _expect_state(
                    case, check, blocked=True, changed=changed, budget=budget,
                    expected=f"{url} blocked by {control_name}",
                    failure=f"{url} was not blocked by the BLOCK access policy",
                )

                access_policies.update(policy, EVERYONE, action_type="LOGGING")
                changed = policy_changed(case, f"access policy {policy_name} changed to LOGGING")
                _expect_state(
                    case, check, blocked=False, changed=changed, budget=budget,
                    expected=f"{url} opens once {policy_name} is LOGGING",
                    failure=f"{url} stayed blocked after its access policy was changed to LOGGING",
                )
                _expect_row(
                    case, ztna_log, run_context, since=changed.utc, control=control_name,
                    policy=policy_name, action="AP_LOGGING",
                    destination=_log_destination(target), device_id=device,
                )

                access_policies.update(policy, EVERYONE, action_type="BLOCK")
                changed = policy_changed(case, f"access policy {policy_name} changed back to BLOCK")
                _expect_state(
                    case, check, blocked=True, changed=changed, budget=budget,
                    expected=f"{url} blocked by {control_name} again",
                    failure=f"{url} was not blocked after its access policy was changed back to BLOCK",
                )
                pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-ZTNA-019")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_access_policy_conditions_match_only_this_endpoint(
    case, run_context, lane, executor, ztna_target, access_controls, access_policies, ztna_log
):
    """접근정책 BLOCK은 조건(OS)이 이 단말과 맞을 때만 접근제어에 걸리고, 다른 OS나 다른 국가(AQ) 조건이면 서버가 열린다."""
    target = ztna_target
    _need_domain(target)
    device = _device(lane, executor)
    url = _url(target.domain, target.port, target.scheme)
    policy_name = resource_name(case.case_id, run_context.run_id, "ap")
    control_name = resource_name(case.case_id, run_context.run_id)
    budget = run_context.policy_propagation_timeout_sec
    check = _state(executor, url, control_name, target.page_text, user_agent=WINDOWS_BROWSER_UA)
    this_os, other_os, catalog = _os_ids(access_policies)
    case.record(Step.SETUP, ok=True, kind=Kind.EVIDENCE, detail=f"OS catalog {catalog}")
    _open_without_rule(executor, target, url)

    matching = [AccessPolicyFactory.rule(os_ids=[this_os])]
    try:
        with access_policies.temporary(policy_name, matching, action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)
            with access_controls.temporary(
                control_name, [_entry(target, by_domain=True)], policy_id=policy.policy_id
            ) as control:
                case.policy_ids.append(control.policy_id)
                changed = policy_changed(case, f"{control_name} with BLOCK {policy_name} (os_id={this_os})")
                _expect_state(
                    case, check, blocked=True, changed=changed, budget=budget,
                    expected=f"{url} blocked: the policy names this endpoint's OS",
                    failure=f"a BLOCK policy for this endpoint's OS (os_id={this_os}) did not block {url}",
                )
                _expect_row(
                    case, ztna_log, run_context, since=changed.utc, control=control_name,
                    policy=policy_name, action="AP_BLOCK",
                    destination=_log_destination(target), device_id=device,
                )
                # OS 조건은 User-Agent로 판정되므로 OS가 없는 UA(curl 기본값)는 이 규칙에 안 걸린다.
                # 판정하지 않고 근거로만 남긴다.
                plain = _state(executor, url, control_name, target.page_text)()
                case.record(
                    Step.USER_RESULT, ok=True, kind=Kind.EVIDENCE,
                    detail=f"same URL with curl's default User-Agent (no OS): {describe(plain)}, "
                    f"blocked by {control_name}={plain.blocked}",
                )

                access_policies.update(policy, [AccessPolicyFactory.rule(os_ids=[other_os])], action_type="BLOCK")
                changed = policy_changed(case, f"{policy_name} condition changed to os_id={other_os}")
                _expect_state(
                    case, check, blocked=False, changed=changed, budget=budget,
                    expected=f"{url} opens: the policy names another OS",
                    failure=f"a BLOCK policy for another OS (os_id={other_os}) still blocked {url}",
                )

                access_policies.update(policy, [AccessPolicyFactory.rule(countries=["AQ"])], action_type="BLOCK")
                changed = policy_changed(case, f"{policy_name} condition changed to country AQ")
                _expect_state(
                    case, check, blocked=False, changed=changed, budget=budget, steady=True,
                    expected=f"{url} keeps opening: the policy names another country (AQ)",
                    failure=f"a BLOCK policy for country AQ blocked {url}",
                )
                pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-ZTNA-020")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P2")
def test_access_policy_and_or_conditions(
    case, run_context, lane, executor, ztna_target, access_controls, access_policies, ztna_log
):
    """접근정책 조건은 그룹 안이 AND, 그룹끼리 OR로 평가된다: 하나만 맞는 OR은 차단, 하나만 맞는 AND는 통과, 둘 다 맞는 AND는 차단."""
    target = ztna_target
    _need_domain(target)
    device = _device(lane, executor)
    url = _url(target.domain, target.port, target.scheme)
    policy_name = resource_name(case.case_id, run_context.run_id, "ap")
    control_name = resource_name(case.case_id, run_context.run_id)
    budget = run_context.policy_propagation_timeout_sec
    check = _state(executor, url, control_name, target.page_text, user_agent=WINDOWS_BROWSER_UA)
    this_os, _, catalog = _os_ids(access_policies)
    case.record(Step.SETUP, ok=True, kind=Kind.EVIDENCE, detail=f"OS catalog {catalog}")
    _open_without_rule(executor, target, url)

    one_true_or = [AccessPolicyFactory.rule(os_ids=[this_os]), AccessPolicyFactory.rule(countries=["AQ"])]
    one_true_and = [AccessPolicyFactory.rule(os_ids=[this_os], countries=["AQ"])]
    both_true_and = [AccessPolicyFactory.rule(os_ids=[this_os], user_ids=[0])]
    try:
        with access_policies.temporary(policy_name, one_true_or, action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)
            with access_controls.temporary(
                control_name, [_entry(target, by_domain=True)], policy_id=policy.policy_id
            ) as control:
                case.policy_ids.append(control.policy_id)
                changed = policy_changed(case, f"{policy_name}: os_id={this_os} OR country AQ")
                _expect_state(
                    case, check, blocked=True, changed=changed, budget=budget,
                    expected=f"{url} blocked: one of two OR groups matches",
                    failure=f"OR with one matching group (os_id={this_os}) did not block {url}",
                )
                _expect_row(
                    case, ztna_log, run_context, since=changed.utc, control=control_name,
                    policy=policy_name, action="AP_BLOCK",
                    destination=_log_destination(target), device_id=device,
                )

                access_policies.update(policy, one_true_and, action_type="BLOCK")
                changed = policy_changed(case, f"{policy_name}: os_id={this_os} AND country AQ")
                _expect_state(
                    case, check, blocked=False, changed=changed, budget=budget,
                    expected=f"{url} opens: one of two AND conditions is false",
                    failure=f"AND with one false condition (country AQ) still blocked {url}",
                )

                access_policies.update(policy, both_true_and, action_type="BLOCK")
                changed = policy_changed(case, f"{policy_name}: os_id={this_os} AND all users")
                _expect_state(
                    case, check, blocked=True, changed=changed, budget=budget,
                    expected=f"{url} blocked: both AND conditions match",
                    failure=f"AND with both conditions true (os_id={this_os}, all users) did not block {url}",
                )
                pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


# -- 앱 런처 -------------------------------------------------------------------


def _launcher_state(response) -> str:
    """서비스 주소 응답을 'page'(2xx), 'redirect'(3xx, 로그인 화면 등), 'blocked'(403), 'other'로."""
    if response is None:
        return "other"
    if response.status_code in BLOCK_STATUS_CODES:
        return "blocked"
    if 300 <= response.status_code < 400:
        return "redirect"
    return "page" if is_delivered_status(response.status_code) else "other"


def _describe_launch(response) -> str:
    if response is None:
        return "no response"
    if 300 <= response.status_code < 400:
        location = httpx.URL(response.headers.get("location", ""))
        return f"HTTP {response.status_code} to {location.scheme}://{location.host}{location.path}"
    title = _TITLE_RE.search(response.text or "")
    return f"HTTP {response.status_code}, title {title.group(1)!r}" if title else (
        f"HTTP {response.status_code}, body {(response.text or '')[:80]!r}"
    )


def _launch_until(session, url: str, app_server: str, want, budget: int):
    """타일을 누르는 것(새 티켓)을 want(응답)가 참이 될 때까지 budget초 동안 반복한다. 마지막 응답."""
    deadline = time.monotonic() + budget
    response = None
    while True:
        try:
            response = session.open(url, app_server)
        except httpx.HTTPError as exc:
            log.info("App launcher request to %s failed: %s", url, exc)
            response = None
        if (response is not None and want(response)) or time.monotonic() >= deadline:
            return response
        time.sleep(3)


@pytest.mark.case("BAT-ZTNA-021")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_app_launcher_tile_opens_and_follows_its_access_policy(
    case, run_context, lane, console, ztna_target, access_controls, access_policies, ztna_log
):
    """앱 런처를 켠 접근제어는 포털 타일로 나오고 그 타일로 커넥터 없이 내부 서버가 열리며, 접근정책을 BLOCK으로 바꾸면 막히고, 지우면 받은 런처 쿠키로도 열리지 않는다."""
    target = ztna_target
    workspace = lane.workspace
    if not workspace.has_console_credentials:
        environment_error("The app launcher needs a console login (BAT_CONSOLE_USER / BAT_CONSOLE_PASSWORD)")
    try:
        app_domain, app_server = launcher_env(run_context.profile)
    except LookupError as exc:
        environment_error(str(exc))
    org_id = access_controls.org_id()
    policy_name = resource_name(case.case_id, run_context.run_id, "ap")
    control_name = resource_name(case.case_id, run_context.run_id)
    entry = dict(_entry(target, by_domain=bool(target.domain)), app_launcher_name=control_name[:50])
    budget = run_context.policy_propagation_timeout_sec
    page_text = target.page_text
    is_page = lambda r: _launcher_state(r) == "page" and (not page_text or page_text in r.text)  # noqa: E731
    is_blocked = lambda r: _launcher_state(r) == "blocked" and f"blocked by {control_name}" in r.text  # noqa: E731

    try:
        # 이 로그인은 같은 계정의 GraphQL 세션을 끊는다. 새 세션을 콘솔 클라이언트(정리에도 쓰는)와
        # 캐시에 넣는다. 그래서 리소스를 만들기 전에 로그인한다.
        with AppLauncherSession(
            run_context.profile, workspace.name, workspace.login_id, workspace.password
        ) as session:
            console.use_token(session.console_token)
            if load_console_token(workspace.name):
                save_console_token(workspace.name, session.console_token)

            with access_policies.temporary(policy_name, EVERYONE, action_type="LOGGING") as policy:
                case.policy_ids.append(policy.policy_id)
                with access_controls.temporary(
                    control_name, [entry], policy_id=policy.policy_id, app_launcher=True
                ) as control:
                    case.policy_ids.append(control.policy_id)
                    tiles = access_controls.launcher_tiles(control_name)
                    case.record(
                        Step.USER_RESULT, ok=bool(tiles), kind=Kind.ASSERTION,
                        expected=f"app launcher portal lists {control_name}",
                        actual=tiles or "not listed",
                        detail=f"{len(tiles)} tile(s)",
                    )
                    assert tiles, f"{control_name} has app_launcher on but the portal list does not show it"
                    tile = tiles[0]
                    host = str(tile.get("domain") or tile.get("ip") or "")
                    url = launcher_url(host, tile.get("port") or target.port, org_id, app_domain)
                    case.record(
                        Step.SETUP, ok=True, kind=Kind.EVIDENCE,
                        detail=f"tile {tile.get('app_launcher_name')!r} -> {url} (OrgID {org_id}, "
                        f"launcher {app_server}), LOGGING policy {policy_name}",
                    )

                    bare = session.without_ticket(url)
                    refused = _launcher_state(bare) != "page" or bool(page_text and page_text not in bare.text)
                    case.record(
                        Step.USER_RESULT, ok=refused, kind=Kind.ASSERTION,
                        expected="service address refuses a request without the launcher cookie",
                        actual=_describe_launch(bare),
                    )
                    assert refused, f"{url} served the internal page without an app launcher ticket"

                    since = datetime.now(timezone.utc)
                    opened = _launch_until(session, url, app_server, is_page, budget)
                    case.record(
                        Step.USER_RESULT, ok=opened is not None and is_page(opened), kind=Kind.ASSERTION,
                        expected=f"tile opens {target.server_ip}:{target.port}"
                        + (f" ({page_text})" if page_text else ""),
                        actual=_describe_launch(opened),
                    )
                    assert opened is not None and is_page(opened), (
                        f"The app launcher tile did not open the internal page: {_describe_launch(opened)}"
                    )
                    _expect_row(
                        case, ztna_log, run_context, since=since, control=control_name,
                        policy=policy_name, action="AP_LOGGING",
                        destination=_log_destination(target), device_id="",
                    )

                    access_policies.update(policy, EVERYONE, action_type="BLOCK")
                    changed = policy_changed(case, f"{policy_name} changed to BLOCK")
                    blocked = _launch_until(session, url, app_server, is_blocked, budget)
                    case.record(
                        Step.USER_RESULT, ok=blocked is not None and is_blocked(blocked), kind=Kind.ASSERTION,
                        expected=f"tile gets the block page naming {control_name}",
                        actual=_describe_launch(blocked),
                    )
                    assert blocked is not None and is_blocked(blocked), (
                        f"The app launcher tile still reached the server after BLOCK: {_describe_launch(blocked)}"
                    )
                    _expect_row(
                        case, ztna_log, run_context, since=changed.utc, control=control_name,
                        policy=policy_name, action="AP_BLOCK",
                        destination=_log_destination(target), device_id="",
                    )

                    # 다시 LOGGING으로 열어 둔 채 지운다. 삭제 뒤에 열리지 않는 것이 쿠키 때문이 아니라
                    # 접근제어가 사라졌기 때문이어야 하므로.
                    access_policies.update(policy, EVERYONE, action_type="LOGGING")
                    reopened = _launch_until(session, url, app_server, is_page, budget)
                    if reopened is None or not is_page(reopened):
                        unverified(
                            case, Step.USER_RESULT,
                            f"the tile did not open again after switching back to LOGGING ({_describe_launch(reopened)})",
                        )

                # 접근제어가 지워졌다(삭제 확인은 팩토리가 한다). 받아 둔 런처 쿠키로 다시 연다.
                deleted = policy_changed(case, f"access control {control_name} deleted")
                deadline = deleted.at + budget
                while True:
                    try:
                        after = session.again(url)
                    except httpx.HTTPError as exc:
                        log.info("App launcher request after delete failed: %s", exc)
                        after = None
                    if _launcher_state(after) != "page" or time.monotonic() >= deadline:
                        break
                    time.sleep(3)
                closed = _launcher_state(after) != "page"
                case.record(
                    Step.USER_RESULT, ok=closed, kind=Kind.ASSERTION,
                    expected="the old launcher cookie no longer opens the server",
                    actual=f"{_describe_launch(after)} {time.monotonic() - deleted.at:.0f}s after delete",
                )
                assert closed, f"{url} still opened with the old launcher cookie after {control_name} was deleted"
                pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)
