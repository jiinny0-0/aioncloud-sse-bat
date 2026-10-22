"""케이스들이 함께 쓰는 헬퍼.

모든 케이스는 같은 모양을 따른다: 정책을 걸고, 실제 트래픽을 만들고, 사용자가 보는
결과를 확인한 뒤, 플랫폼이 기록한 것을 확인한다.
"""
from __future__ import annotations

import itertools
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, NoReturn
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from bat.clients.errors import ApiError, AuthError, SelfBlockedError
from bat.events.casb_log import CasbLogReader
from bat.events.casb_log import in_app_service_name
from bat.events.casb_log import matches_rule as matches_casb_rule
from bat.events.network_log import NetworkLogReader
from bat.events.network_log import matches_policy as matches_network_policy
from bat.events.poller import PollTimeout, poll_until
from bat.events.web_log import (
    WebLogReader,
    all_of,
    identity_of,
    matches_action,
    matches_policy,
    matches_target,
)
from bat.models import CaseResult, Kind, SecurityEvent, Status, Step, TrafficResult

log = logging.getLogger(__name__)


class VerificationUnavailable(pytest.skip.Exception):
    """검사를 수행할 수 없었으므로 케이스는 SKIP이 아니라 UNVERIFIED다.

    pytest가 실패로 세지 않도록 pytest.skip의 하위 클래스로 둔다. conftest가 둘을 구분하고
    bat.verdict가 UNVERIFIED로 분류한다.
    """


def visit_until_blocked(browser_session, url: str, case_id: str, timeout_sec: int) -> TrafficResult:
    """정책이 전파되는 동안 방문을 재시도한다.

    어느 쪽이든 마지막 시도를 돌려주므로, 호출자는 그것으로 assert하면서도 사용자가 실제로
    본 화면의 스크린샷을 얻는다.
    """
    last: dict[str, TrafficResult] = {}

    def probe() -> TrafficResult | None:
        result = browser_session.visit(url, case_id=case_id)
        last["result"] = result
        return result if result.blocked else None

    try:
        return poll_until(
            probe,
            timeout_sec=timeout_sec,
            description=f"block page for {url}",
            initial_interval=2.0,
        )
    except PollTimeout:
        return last["result"]


def marker_of(uri: object) -> str:
    """요청 URL에 붙은 `bat=` 값(없으면 ""). expect_casb_block이 붙이는 값이다."""
    values = parse_qs(urlsplit(str(uri or "")).query).get("bat") or [""]
    return values[0].lower()


def visit_until_allowed(browser_session, url: str, case_id: str, timeout_sec: int) -> TrafficResult:
    """위의 반대 방향으로, 정책을 지우면 접근이 복구돼야 하는 케이스용이다.

    차단 페이지가 없다는 것만이 아니라 실제로 렌더링된 페이지(TrafficResult.delivered)에서
    멈춘다 — 탐색 오류에도 차단 페이지는 없다."""
    last: dict[str, TrafficResult] = {}

    def probe() -> TrafficResult | None:
        result = browser_session.visit(url, case_id=case_id)
        last["result"] = result
        return result if result.delivered else None

    try:
        return poll_until(
            probe,
            timeout_sec=timeout_sec,
            description=f"page to load normally: {url}",
            initial_interval=2.0,
        )
    except PollTimeout:
        return last["result"]


def visit_until_isolated(browser_session, url: str, case_id: str, timeout_sec: int) -> TrafficResult:
    """RBI 정책이 전파되는 동안 방문을 재시도한다."""
    last: dict[str, TrafficResult] = {}

    def probe() -> TrafficResult | None:
        result = browser_session.visit_for_isolation(url, case_id=case_id)
        last["result"] = result
        return result if result.isolated else None

    try:
        return poll_until(
            probe,
            timeout_sec=timeout_sec,
            description=f"isolation redirect for {url}",
            initial_interval=2.0,
        )
    except PollTimeout:
        return last["result"]


def visit_until_not_isolated(browser_session, url: str, case_id: str, timeout_sec: int) -> TrafficResult:
    """visit_until_isolated의 반대 방향으로, RBI rule을 지우면 직접 렌더링이 복구돼야
    하는 케이스용이다 — 실패한 탐색도 "격리 안 됨"이므로 실제 직접 렌더링(delivered)을
    기다린다."""
    last: dict[str, TrafficResult] = {}

    def probe() -> TrafficResult | None:
        result = browser_session.visit_for_isolation(url, case_id=case_id)
        last["result"] = result
        return result if result.delivered else None

    try:
        return poll_until(
            probe,
            timeout_sec=timeout_sec,
            description=f"direct render restored for {url}",
            initial_interval=2.0,
        )
    except PollTimeout:
        return last["result"]


def curl_until_blocked(executor, url: str, timeout_sec: int, **kwargs):
    """같은 방식을 브라우저 대신 curl로 보내는 요청에 쓴다."""
    from bat.traffic.http import curl_status

    last: dict = {}

    def probe():
        result = curl_status(executor, url, **kwargs)
        last["result"] = result
        return result if result.blocked else None

    try:
        return poll_until(
            probe, timeout_sec=timeout_sec, description=f"block for {url}", initial_interval=2.0
        )
    except PollTimeout:
        return last["result"]


def dns_lookup_until_blocked(executor, domain: str, timeout_sec: int):
    """DNS Firewall 차단 정책이 전파되는 동안 DNS 조회를 재시도한다."""
    from bat.traffic.http import dns_lookup

    last: dict = {}

    def probe():
        result = dns_lookup(executor, domain, timeout_sec=timeout_sec)
        last["result"] = result
        return result if result.blocked else None

    try:
        return poll_until(
            probe, timeout_sec=timeout_sec, description=f"DNS block for {domain}", initial_interval=2.0
        )
    except PollTimeout:
        return last["result"]


def curl_until_delivered(
    executor, url: str, timeout_sec: int, *, request_timeout_sec: int = 30, **kwargs
):
    """curl_until_blocked의 반대 방향으로, 요청이 다시 통과하기 시작해야 하는 케이스용이다.
    차단이 없다는 것이 아니라 긍정적인 근거(TrafficResult.delivered)에서 멈추고 — curl의
    "000"도 차단은 아니다 — 어느 쪽이든 마지막 시도를 돌려줘 호출자가 판정하게 한다."""
    from bat.traffic.http import curl_status

    last: dict = {}

    def probe():
        result = curl_status(executor, url, timeout_sec=request_timeout_sec, **kwargs)
        last["result"] = result
        return result if result.delivered else None

    try:
        return poll_until(
            probe, timeout_sec=timeout_sec, description=f"{url} to go through", initial_interval=2.0
        )
    except PollTimeout:
        return last["result"]


def curl_until_unreachable(executor, url: str, timeout_sec: int, **kwargs):
    """curl_until_blocked와 같지만, HTTP 차단 페이지를 돌려주지 않고 연결 자체를 끊는
    (status_code 0/curl의 "000") 정책용이다. Application Firewall이 이렇게 나타난다 —
    HTTP를 이해하는 프록시가 아니라 네트워크 계층에서 동작하므로 찾을 403이 없다."""
    from bat.traffic.http import curl_status

    last: dict = {}

    def probe():
        result = curl_status(executor, url, **kwargs)
        last["result"] = result
        return result if not result.status_code else None

    try:
        return poll_until(
            probe,
            timeout_sec=timeout_sec,
            description=f"connection refused for {url}",
            initial_interval=2.0,
        )
    except PollTimeout:
        return last["result"]


def curl_until_reachable(executor, url: str, timeout_sec: int, **kwargs):
    """위의 반대 방향으로, 정책을 지우면 연결이 복구돼야 하는 케이스용이다."""
    from bat.traffic.http import curl_status

    last: dict = {}

    def probe():
        result = curl_status(executor, url, **kwargs)
        last["result"] = result
        return result if result.status_code else None

    try:
        return poll_until(
            probe,
            timeout_sec=timeout_sec,
            description=f"connection restored for {url}",
            initial_interval=2.0,
        )
    except PollTimeout:
        return last["result"]


def dns_lookup_until_allowed(executor, domain: str, timeout_sec: int):
    """위의 반대 방향으로, 정책을 지우면 이름 해석이 복구돼야 하는 케이스용이다 —
    타임아웃도 거부는 아니므로 주소가 담긴 응답을 기다린다."""
    from bat.traffic.http import dns_lookup

    last: dict = {}

    def probe():
        result = dns_lookup(executor, domain, timeout_sec=timeout_sec)
        last["result"] = result
        return result if result.delivered else None

    try:
        return poll_until(
            probe,
            timeout_sec=timeout_sec,
            description=f"name resolution restored for {domain}",
            initial_interval=2.0,
        )
    except PollTimeout:
        return last["result"]


def describe(traffic: TrafficResult) -> str:
    """요청이 어떤 결과로 돌아왔는지를 리포트가 쓰는 말로 나타낸다."""
    if traffic.via == "dns":
        if traffic.blocked:
            return "resolution failed"
        return "resolution succeeded" if traffic.delivered else "no answer (timeout or error)"
    if traffic.isolated:
        return "isolated"
    if traffic.blocked:
        return "block page" if traffic.via == "browser" else f"HTTP {traffic.status_code}"
    if traffic.delivered:
        return "page rendered" if traffic.via == "browser" else f"HTTP {traffic.status_code}"
    if traffic.status_code == 0:
        return "connection failed"
    if traffic.status_code:
        return f"no usable response (HTTP {traffic.status_code})"
    return "no response"


def record_user_result(case: CaseResult, traffic: TrafficResult, *, expect_blocked: bool) -> None:
    if not expect_blocked:
        expect_delivered(
            case,
            traffic,
            expected="page rendered",
            failure=f"{traffic.url} should not have been blocked",
            fatal=False,
        )
        return
    case.record(
        Step.USER_RESULT,
        ok=traffic.blocked,
        detail=traffic.detail,
        expected="block page",
        actual=describe(traffic),
    )
    if traffic.artifact:
        case.artifacts.append(traffic.artifact)


def expect_block(case: CaseResult, traffic: TrafficResult, url: str) -> None:
    record_user_result(case, traffic, expect_blocked=True)
    assert traffic.blocked, f"Expected the SSE block page for {url}, got: {traffic.detail}"


def expect_delivered(
    case: CaseResult,
    traffic: TrafficResult,
    *,
    expected: str,
    failure: str,
    step: Step = Step.USER_RESULT,
    fatal: bool = True,
) -> bool:
    """요청이 통과했어야 한다. 차단이 없다는 것이 아니라 긍정적인 근거로 판정한다
    (세 가지 결과는 TrafficResult 설명 참조).

    blocked/isolated  실패한 assertion(FAIL). fatal=False가 아니면 예외를 던진다.
    delivered         통과한 assertion.
    둘 다 아님        UNAVAILABLE로 기록하고 케이스는 계속된다: 뒤에서 실패하면 여전히
                      FAIL이지만, 더는 PASS로 끝날 수 없다(bat.verdict). 탐색 오류,
                      curl의 "000", DNS 타임아웃은 정책에 대해 아무것도 말해주지 않으므로
                      허용의 증거도 아니고 그 FAIL도 아니다.
    요청이 전달됐는지를 돌려준다.
    """
    actual = describe(traffic)
    if traffic.artifact:
        case.artifacts.append(traffic.artifact)
    if traffic.blocked or traffic.isolated:
        case.record(
            step, ok=False, detail=traffic.detail, expected=expected, actual=actual,
            kind=Kind.ASSERTION,
        )
        if fatal:
            raise AssertionError(f"{failure}: {traffic.detail or actual}")
        return False
    if not traffic.delivered:
        case.record(
            step,
            ok=False,
            detail=f"inconclusive, not judged: {traffic.detail or actual}",
            expected=expected,
            actual=actual,
            kind=Kind.UNAVAILABLE,
        )
        return False
    case.record(
        step, ok=True, detail=traffic.detail, expected=expected, actual=actual,
        kind=Kind.ASSERTION,
    )
    return True


def expect_allowed(case: CaseResult, traffic: TrafficResult, url: str) -> None:
    expect_delivered(
        case, traffic, expected="page rendered", failure=f"{url} should not have been blocked"
    )


def await_security_event(
    case: CaseResult,
    web_log: WebLogReader,
    policy_name: str,
    *,
    timeout_sec: float,
    expected_action: str = "BLOCK",
    expected_target: str | None = None,
    target_in_search: bool = False,
    extra: Callable[[SecurityEvent], bool] | None = None,
    policy_id: str | int | None = None,
) -> SecurityEvent:
    """정책 이름(정확히 일치)과, 주어지면 케이스가 만든 정책의 id로 이벤트를 찾은 뒤
    그 내용을 검증한다.

    검색 조건에 action과 target까지 넣으면 틀린 값이 타임아웃으로 바뀌어 "이벤트가 안
    남았다"로 읽히고 실제 차이가 가려진다. 먼저 찾고 나중에 확인하면 둘이 구분된다.

    target_in_search는 예외다: 넓은 정책은 케이스 자신의 요청보다 많이 매칭한다 — 러너의
    API 트래픽도 같은 커넥터를 지난다 — 그래서 그 정책 이름이 붙은 첫 이벤트가 전혀 다른
    요청의 것일 수 있다. 이런 케이스는 target으로도 검색해야 한다.
    """
    search = matches_policy(policy_name, policy_id)
    if target_in_search and expected_target:
        search = all_of(search, matches_target(expected_target))

    try:
        event = web_log.wait_for_security_event(
            search,
            timeout_sec=timeout_sec,
            description=f"security event for {policy_name}",
        )
    except PollTimeout as timeout:
        case.record(
            Step.EVENT,
            ok=False,
            detail=str(timeout),
            expected=f"security event naming {policy_name}",
            actual="no matching event",
        )
        raise AssertionError(
            f"Enforcement happened but no security event appeared: {timeout}"
        ) from timeout

    case.event_ids.append(event.event_id)

    checks: dict[str, bool] = {"action": matches_action(expected_action)(event)}
    if expected_target:
        checks["target"] = matches_target(expected_target)(event)
    if extra:
        checks["extra"] = extra(event)

    case.record(
        Step.EVENT,
        ok=all(checks.values()),
        detail=f"security_log_id={event.event_id}",
        expected={
            "policy": policy_name,
            "policy_id": policy_id,
            "action": expected_action,
            "target": expected_target,
        },
        actual={
            "policy": event.get("policy_name"),
            "policy_id": event.get("policy_id"),
            "action": event.get("action"),
            "target": event.get("full_uri"),
        },
    )

    assert checks["action"], (
        f"Event {event.event_id} records action {event.get('action')!r}, "
        f"expected {expected_action}"
    )
    if expected_target:
        assert checks["target"], (
            f"Event {event.event_id} records target {event.get('full_uri')!r}, "
            f"expected something containing {expected_target}"
        )
    if extra:
        assert checks["extra"], f"Event {event.event_id} failed the case's extra check"

    return event


def await_network_event(
    case: CaseResult,
    network_log: NetworkLogReader,
    policy_name: str,
    *,
    kind: str,
    timeout_sec: float,
    expected_action: str = "BLOCK",
) -> SecurityEvent:
    """await_security_event와 같지만, 웹 보안로그와 별개인 DNS/Application Firewall 자신의
    로그(SIA.log.dns_security_log / firewall_security_log)용이다. `kind`는 "dns" 또는
    "firewall"이다.
    """
    wait_for = {
        "dns": network_log.wait_for_dns_event,
        "firewall": network_log.wait_for_firewall_event,
    }[kind]

    try:
        event = wait_for(
            matches_network_policy(policy_name),
            timeout_sec=timeout_sec,
            description=f"{kind} security event for {policy_name}",
        )
    except PollTimeout as timeout:
        case.record(
            Step.EVENT,
            ok=False,
            detail=str(timeout),
            expected=f"{kind} security event naming {policy_name}",
            actual="no matching event",
        )
        raise AssertionError(
            f"Enforcement happened but no security event appeared: {timeout}"
        ) from timeout

    case.event_ids.append(event.event_id)
    action_ok = bool(event.get("action")) and expected_action.upper() == str(
        event.get("action")
    ).upper()
    case.record(
        Step.EVENT,
        ok=action_ok,
        detail=f"{kind}_security_log_id={event.event_id}",
        expected={"policy": policy_name, "action": expected_action},
        actual={"policy": event.get("policy_name"), "action": event.get("action")},
    )
    assert action_ok, (
        f"Event {event.event_id} records action {event.get('action')!r}, "
        f"expected {expected_action}"
    )
    return event


def await_casb_event(
    case: CaseResult,
    casb_log: CasbLogReader,
    rule_name: str,
    *,
    timeout_sec: float,
    expected_service: str | None = None,
) -> SecurityEvent:
    """rule 이름으로 CASB(In-App Control / SaaS Access) 이벤트를 찾는다.

    CASB 이벤트는 정책을 `policy_name`이 아니라 `rule_name`으로 나타내고, 앱은
    `in_app_service.name`에 있다.

    전체 앱으로 스코프한 정책은 같은 시각의 다른 트래픽에도 매칭하므로, `expected_service`가
    주어지면 첫 rule_name 매칭을 확인하는 데 쓰지 않고 검색 조건에 넣는다.
    """
    match = matches_casb_rule(rule_name)
    if expected_service:
        def match(event: SecurityEvent, _rule=match, _service=expected_service) -> bool:
            return _rule(event) and in_app_service_name(event) == _service

    try:
        event = casb_log.wait_for_event(
            match,
            timeout_sec=timeout_sec,
            description=f"casb security event for {rule_name}",
        )
    except PollTimeout as timeout:
        case.record(
            Step.EVENT,
            ok=False,
            detail=str(timeout),
            expected=f"casb security event naming {rule_name}",
            actual="no matching event",
        )
        raise AssertionError(
            f"Enforcement happened but no security event appeared: {timeout}"
        ) from timeout

    case.event_ids.append(event.event_id)
    service = in_app_service_name(event)
    service_ok = True if not expected_service else service == expected_service
    case.record(
        Step.EVENT,
        ok=service_ok,
        detail=f"casb_security_log_id={event.event_id}",
        expected={"rule": rule_name, "service": expected_service},
        actual={"rule": event.get("rule_name"), "service": service, "uri": event.get("request_uri")},
    )
    if expected_service:
        assert service_ok, (
            f"Event {event.event_id} records app {service!r}, expected {expected_service!r}"
        )
    return event


# CASB BLOCK 검사(expect_casb_block): 전파 예산 뒤의 요청 수. 하나하나가 차단되고 자기
# BLOCK 행으로 기록돼야 한다. 비율이 아니다. 한 번이라도 렌더링되면 실패다.
CASB_HOLD_REQUESTS = 5
# 요청 사이 간격. 두 구간 모두에 쓴다.
CASB_REQUEST_GAP_SEC = 2.0
# 검사가 이미 실패한 뒤에도 행을 계속 모으는 시간. 행은 더 이상 판정을 바꿀 수 없으므로
# 근거를 기다리는 시간의 상한일 뿐이다. 측정된 단일 케이스 이벤트 지연 중 가장 긴 값을
# 덮는다.
CASB_FAILED_ROW_WAIT_SEC = 20


def _utc(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _log_read_failure(exc: Exception) -> str:
    """casb_security_log 읽기를 무엇이 막았는지를 BAT가 이미 쓰는 판정 기준으로 나눈다.

    session     콘솔 세션이 거부됨(AuthError, 'bat sweep'이 읽는 방식의 HTTP 401/403,
                GraphQL "Duplicate login"): 실행 문제라 ERROR, 'bat login'으로 해결
    self-block  SSE가 스위트 자신의 조회에 차단 페이지로 답함: 러너의 트래픽이 걸린
                다른 모든 경우와 마찬가지로 ERROR
    api         로그 API의 그 밖의 거부(HTTP 5xx, GraphQL 오류)
    network     응답이 전혀 없음(httpx 전송 오류)
    other       그 밖의 모든 것. 예상치 못한 예외로 남는다(ERROR)

    api와 network는 행을 읽지 못한 것이라 검증 불가, UNVERIFIED다.
    """
    if isinstance(exc, SelfBlockedError):
        return "self-block"
    if isinstance(exc, AuthError):
        return "session"
    if isinstance(exc, ApiError):
        if exc.status_code in (401, 403) or "duplicate login" in str(exc).lower():
            return "session"
        return "api"
    if isinstance(exc, httpx.HTTPError):
        return "network"
    return "other"


@dataclass(frozen=True)
class PolicyChange:
    """정책 변경이 끝난 시각. 전파 예산은 여기서부터 잰다."""

    what: str
    at: float  # API 호출이 돌아온 직후의 time.monotonic()
    utc: datetime


def policy_changed(case: CaseResult, what: str) -> PolicyChange:
    """정책 변경이 방금 끝났음을 적는다. API 호출이 돌아온 직후에 부른다."""
    change = PolicyChange(what, time.monotonic(), datetime.now(timezone.utc))
    case.record(Step.SETUP, ok=True, detail=f"{what} at {_utc(change.utc)}", kind=Kind.EVIDENCE)
    return change


@dataclass
class CasbVisit:
    """CASB BLOCK 검사가 보낸 요청 하나(정책 변경 시각 기준으로 잰 시간)와 그 요청 자신의 행."""

    number: int
    marker: str  # 요청의 `bat=` 값
    phase: str  # "propagation"(기한까지 돌아옴), "boundary"(기한에 나가 있음), "hold"
    sent_sec: float
    back_sec: float
    sent_utc: datetime
    back_utc: datetime
    traffic: TrafficResult
    row: SecurityEvent | None = None
    at_deadline: bool = False  # 기한이 지날 때 나가 있는 요청이 없어 기한 시각에 보냄

    @property
    def where(self) -> str:
        return (
            f"{self.traffic.url} (#{self.number} {self.phase}, sent +{self.sent_sec:.1f}s, "
            f"back +{self.back_sec:.1f}s)"
        )


def _logged_after(row: SecurityEvent, sent: datetime) -> str:
    """그 요청을 보낸 시각에 대한 행 시각의 차이. 행 시각에 시간대가 없거나 파싱되지 않으면
    "". 읽는 사람에게 보여줄 뿐 판정에는 쓰지 않는다."""
    try:
        moment = datetime.fromisoformat(str(row.get("time") or ""))
    except ValueError:
        return ""
    return f"{(moment - sent).total_seconds():+.1f}s" if moment.tzinfo else ""


def _numbered(visits: list[CasbVisit]) -> str:
    return ", ".join(f"#{v.number}" for v in visits)


def expect_casb_block(
    case: CaseResult,
    browser_session,
    casb_log: CasbLogReader,
    rule_name: str,
    url: str,
    *,
    changed: PolicyChange,
    propagation_timeout_sec: int,
    event_timeout_sec: float,
    expected_service: str,
    failure: str,
    created: PolicyChange | None = None,
    budget_spent_reason: str = "",
    hold_requests: int = CASB_HOLD_REQUESTS,
) -> SecurityEvent | None:
    """CASB SaaS Access BLOCK 단계 하나를, 정책이 바뀐 시각부터 요청 하나하나로 판정한다.

    페이지가 차단돼야 하고, 차단된 요청마다 자기 BLOCK 행이 있어야 한다: 페이지 자체는
    렌더링되는 동안에도 페이지의 하위 요청(API 호출, 텔레메트리) 행이 그 정책 이름을 달 수
    있고, 차단 페이지 한 번이 차단이 유지된다는 뜻도 아니다.

    모든 요청에 `?bat=<rule_name>-<n>`을 붙이고, CASB는 이를 request_uri에 그대로 남기므로
    행이 그 행이 설명하는 요청과 묶인다. 정책은 rule_name(정확히 일치,
    casb_security_log에는 policy_id가 없음)으로, 앱은 in_app_service로 맞춘다. 러너의 시계와
    로그의 시계가 다를 수 있으므로 행의 시각은 그 요청의 시각 옆에 보여줄 뿐 판정하지 않는다.

    기한은 이 호출 시각이 아니라 `changed`(policy_changed(), 시험 대상 구성을 완성한 변경)에
    propagation_timeout_sec를 더한 시각이다. `created`는 CASB 정책 자체가 들어간 시각으로,
    그게 더 앞섰으면 리포트에 남기되 계산에는 넣지 않는다.

    각 요청은 보낸 시각과 돌아온 시각으로 분류한다:
    propagation  기한까지 돌아온 요청. 여기서의 차단 페이지만이 정책이 기한 안에 적용됐다는
                 증거다. 한 번 막힌 뒤에도 요청을 계속 보내고, 그 뒤 페이지가 다시
                 렌더링되면 전파 안정성 위반으로, hold 결과와 상관없이 케이스는 실패한다.
    boundary     기한이 지날 때 나가 있던 요청: 기한 전에 보내 기한 뒤에 돌아온 마지막
                 요청, 없으면 기한 시각에 보낸 요청. 그 차단 페이지는 기한 전에 나왔을 수도
                 뒤에 나왔을 수도 있어 어느 쪽도 증명하지 않는다. 기한 시각에 보낸 요청이
                 렌더링되면 그때까지 정책이 적용되지 않았다는 증거다.
    hold         그 뒤 각각 얼마나 걸리든 정확히 hold_requests번의 요청. 차단 페이지는 통과,
                 렌더링된 페이지는 실패, 둘 다 아니면(탐색 오류, 5xx) UNAVAILABLE이다. 차단된
                 요청 자신의 행은 기대한 앱에 대해 BLOCK이어야 하고 아니면 실패다. 정책에 다른
                 요청의 행은 있는데 그 요청의 행이 없으면 UNAVAILABLE, 그 정책의 행이 아예
                 없으면 실패다.

    기한 안에 적용됐는지: propagation 차단이 있으면 통과, 기한 시각의 렌더링(그 전에 차단
    없음)은 실패이고 전파 지연을 기록한다. 판단을 열어 두는 경우(boundary 요청만 차단됨,
    기한에 걸쳐 나가 있던 boundary 요청이 렌더링됨, 판단 불가 응답, 기한 전 요청 없음)는
    UNAVAILABLE이다. 첫 요청 전에 예산이 이미 지난 케이스는 budget_spent_reason을 준다: 그러면
    그 구간을 판정에서 빼고 그렇게 밝히며, 통과로 기록하지는 않는다. 이유가 없으면 그
    케이스는 UNVERIFIED다. 기한 전에 남은 시간이 있으면 언제나 판정한다.

    행은 event_timeout_sec까지, 검사가 이미 실패했으면 CASB_FAILED_ROW_WAIT_SEC까지 기다린다.
    로그 읽기 실패는 _log_read_failure로 분류한다: 읽지 못한 행은 UNAVAILABLE, 세션 거부나
    self-block은 ERROR다. 위반을 한 번 보면 그 뒤에 무엇이 오든(그 오류들과 브라우저 실패
    포함) FAIL로 남는다. 무엇이든 예외를 던지기 전에 전부 기록한다. 검사가 실패하면
    AssertionError를 던지고, 그렇지 않으면 첫 hold 요청의 행이나 None을 돌려준다.
    """
    budget = propagation_timeout_sec
    deadline = changed.at + budget
    numbers = itertools.count(1)
    visits: list[CasbVisit] = []
    separator = "&" if "?" in url else "?"

    def visit(phase: str, *, at_deadline: bool = False) -> CasbVisit:
        number = next(numbers)
        marker = f"{rule_name}-{number}".lower()
        sent, sent_utc = time.monotonic(), datetime.now(timezone.utc)
        traffic = browser_session.visit(f"{url}{separator}bat={marker}", case_id=case.case_id)
        back = time.monotonic()
        if phase == "propagation" and back > deadline:
            phase = "boundary"  # 기한이 지날 때 아직 나가 있었다
        visits.append(CasbVisit(
            number=number, marker=marker, phase=phase, sent_sec=sent - changed.at,
            back_sec=back - changed.at, sent_utc=sent_utc, back_utc=datetime.now(timezone.utc),
            traffic=traffic, at_deadline=at_deadline,
        ))
        if traffic.artifact:
            case.artifacts.append(traffic.artifact)
        return visits[-1]

    began = time.monotonic() - changed.at
    late_start = began >= budget
    excluded = late_start and bool(budget_spent_reason)
    window_closed = False
    broke: Exception | None = None
    try:
        if not late_start:
            longest = 0.0
            while True:
                last = visit("propagation")
                longest = max(longest, last.back_sec - last.sent_sec)
                # 간격 하나와 그만큼 걸리는 요청 하나를 더 보내면 기한까지 돌아오지 못한다.
                if time.monotonic() + CASB_REQUEST_GAP_SEC + longest > deadline:
                    break
                time.sleep(CASB_REQUEST_GAP_SEC)
            if last.phase == "propagation":  # 기한이 지날 때 나가 있는 요청이 없었다
                time.sleep(max(deadline - time.monotonic(), 0.0))
                visit("boundary", at_deadline=True)
            # 어느 쪽이든 닫힌 구간에는 boundary 요청이 정확히 하나 있다.
        window_closed = True
        for n in range(hold_requests):
            if n:
                time.sleep(CASB_REQUEST_GAP_SEC)
            visit("hold")
    except Exception as exc:  # noqa: BLE001 - 위반이 이미 확정된 게 아니면 아래에서 다시 던진다
        broke = exc  # 브라우저 자체가 실패했다. 탐색 오류는 결과로 돌아온다

    first_sent = visits[0].sent_sec if visits else None
    since_created = changed.at - created.at if created else 0.0
    case.record(
        Step.SETUP,
        ok=True,
        detail=f"propagation deadline +{budget}s from: {changed.what} ({_utc(changed.utc)}), i.e. "
        f"{_utc(changed.utc + timedelta(seconds=budget))}"
        + (f"; the CASB policy itself went in {since_created:.1f}s before that: {created.what} "
           f"({_utc(created.utc)})" if created else "")
        + (f"; this check began at +{began:.1f}s and sent its first request at +{first_sent:.1f}s"
           + (f" (+{first_sent + since_created:.1f}s after the CASB policy went in)" if created else "")
           if first_sent is not None else f"; this check began at +{began:.1f}s and sent no request")
        + ("; the budget had already run out, so the propagation window is "
           + (f"excluded from judgment ({budget_spent_reason})" if excluded else "not observed")
           if late_start else
           f"; only a block page back by the deadline proves it took effect in time, and each of "
           f"the {hold_requests} requests after the one out at the deadline has to be blocked"),
        kind=Kind.EVIDENCE,
    )
    propagation = [v for v in visits if v.phase == "propagation"]
    boundary = next((v for v in visits if v.phase == "boundary"), None)
    hold = [v for v in visits if v.phase == "hold"]
    in_time = next((v for v in propagation if v.traffic.blocked), None)
    before_hold = propagation + ([boundary] if boundary else [])
    relapsed = [v for v in before_hold if in_time and v.number > in_time.number and v.traffic.delivered]
    failures: list[str] = []

    for v in visits:
        seen = describe(v.traffic)
        if any(r.number == v.number for r in relapsed):
            case.record(
                Step.USER_RESULT,
                ok=False,
                detail=f"{v.where}: {seen}: propagation stability violation, rendered again after "
                f"the block page of #{in_time.number}",
                expected=f"block page, as from #{in_time.number} on",
                actual=seen,
                kind=Kind.ASSERTION,
            )
        elif v.phase == "propagation":
            case.record(
                Step.USER_RESULT,
                ok=True,
                detail=f"{v.where}: {seen}, back by the {budget}s deadline (recorded, not judged)",
                expected="block page once the policy is in effect",
                actual=seen,
                kind=Kind.EVIDENCE,
            )
        elif v.phase == "boundary":
            case.record(
                Step.USER_RESULT,
                ok=True,
                detail=f"{v.where}: {seen}, "
                + ("sent at" if v.at_deadline else "in flight across")
                + f" the {budget}s deadline: no proof it took effect in time, and not one of the "
                f"{hold_requests} requests judged after it (recorded)",
                expected="block page once the policy is in effect",
                actual=seen,
                kind=Kind.EVIDENCE,
            )
        elif v.traffic.blocked or v.traffic.delivered:
            case.record(
                Step.USER_RESULT,
                ok=v.traffic.blocked,
                detail=f"{v.where}: {v.traffic.detail}",
                expected="block page",
                actual=seen,
                kind=Kind.ASSERTION,
            )
        else:
            case.record(
                Step.USER_RESULT,
                ok=False,
                detail=f"inconclusive, not judged: {v.where}: {v.traffic.detail or seen}",
                expected="block page",
                actual=seen,
                kind=Kind.UNAVAILABLE,
            )

    in_budget = f"a block page back within {budget}s of the change"
    if excluded:
        case.record(
            Step.USER_RESULT,
            ok=False,
            detail=f"propagation window excluded from judgment, not passed: {budget_spent_reason}. "
            f"The {budget}s budget had run out {began - budget:.1f}s before this check began"
            + (f" (first request +{first_sent:.1f}s after {changed.what})" if first_sent is not None else "")
            + f", so only the {hold_requests} requests after it are judged",
            expected=f"{in_budget} (not judged here)",
            actual="excluded",
            kind=Kind.EVIDENCE,
        )
    elif in_time:
        case.record(
            Step.USER_RESULT,
            ok=True,
            detail=f"block page back by the {budget}s deadline: #{in_time.number} (sent "
            f"+{in_time.sent_sec:.1f}s, back +{in_time.back_sec:.1f}s)",
            expected=in_budget,
            actual=f"#{in_time.number}, back +{in_time.back_sec:.1f}s",
            kind=Kind.ASSERTION,
        )
    elif not window_closed:
        case.record(
            Step.USER_RESULT,
            ok=False,
            detail=f"the propagation window was cut short by a browser failure: {broke}",
            expected=in_budget,
            actual="window not completed",
            kind=Kind.UNAVAILABLE,
        )
    elif late_start:
        case.record(
            Step.USER_RESULT,
            ok=False,
            detail=f"the {budget}s propagation budget had run out before this check began "
            f"(+{began:.1f}s), so whether the block took effect in time was not observed",
            expected=in_budget,
            actual="no request before the deadline",
            kind=Kind.UNAVAILABLE,
        )
    elif boundary.traffic.blocked:
        case.record(
            Step.USER_RESULT,
            ok=False,
            detail=f"no block page came back by the {budget}s deadline; the first was #{boundary.number}, "
            + ("sent at" if boundary.at_deadline else "in flight across")
            + f" it (sent +{boundary.sent_sec:.1f}s, back +{boundary.back_sec:.1f}s), which proves "
            f"neither that the block took effect in time nor that it did not",
            expected=in_budget,
            actual=f"first block page in #{boundary.number}, back +{boundary.back_sec:.1f}s",
            kind=Kind.UNAVAILABLE,
        )
    elif boundary.at_deadline and boundary.traffic.delivered:
        case.record(
            Step.USER_RESULT,
            ok=False,
            detail=f"no block page came back by the {budget}s deadline, and #{boundary.number}, sent "
            f"at it (+{boundary.sent_sec:.1f}s), still rendered",
            expected=in_budget,
            actual=f"#{boundary.number} rendered at the deadline",
            kind=Kind.ASSERTION,
        )
        failures.append(
            f"the block did not take effect within the {budget}s propagation budget (no block page "
            f"came back by the deadline, and #{boundary.number} sent at it still rendered)"
        )
    elif any(not v.traffic.delivered for v in before_hold):
        unknown = [v for v in before_hold if not v.traffic.delivered]
        case.record(
            Step.USER_RESULT,
            ok=False,
            detail=f"no block page came back by the {budget}s deadline, but {len(unknown)} of the "
            f"{len(before_hold)} requests up to it were inconclusive ({_numbered(unknown)}), so "
            f"whether the block took effect in time is unknown",
            expected=in_budget,
            actual="no block page; inconclusive requests",
            kind=Kind.UNAVAILABLE,
        )
    else:
        case.record(
            Step.USER_RESULT,
            ok=False,
            detail=f"no block page came back by the {budget}s deadline, but #{boundary.number} "
            f"rendered while in flight across it (sent +{boundary.sent_sec:.1f}s, back "
            f"+{boundary.back_sec:.1f}s) and may have been answered before it, so whether the "
            f"block took effect in time is unknown",
            expected=in_budget,
            actual=f"#{boundary.number} rendered across the deadline",
            kind=Kind.UNAVAILABLE,
        )
    if relapsed:
        failures.append(
            f"propagation stability violation: {_numbered(relapsed)} rendered again after the "
            f"block page of #{in_time.number}"
        )
    if not late_start and window_closed and not in_time:
        late = next((v for v in [boundary, *hold] if v.traffic.blocked), None)
        case.record(
            Step.USER_RESULT,
            ok=False,
            detail=(
                f"propagation delay: no block page came back by the {budget}s deadline; the first "
                f"came in #{late.number} ({late.phase}, sent +{late.sent_sec:.1f}s, back "
                f"+{late.back_sec:.1f}s)"
                if late else f"propagation delay: none of the {len(visits)} requests, up to "
                f"+{visits[-1].sent_sec:.1f}s, was blocked"
            ),
            expected=in_budget,
            actual=f"#{late.number}, sent +{late.sent_sec:.1f}s" if late else "never blocked",
            kind=Kind.EVIDENCE,
        )

    rendered = [v for v in hold if v.traffic.delivered]
    if rendered:
        failures.append(
            f"{len(rendered)} of {len(hold)} requests after the {budget}s propagation budget "
            f"rendered under the BLOCK policy: {_numbered(rendered)}"
        )
    if window_closed and len(hold) < hold_requests:
        case.record(
            Step.USER_RESULT,
            ok=False,
            detail=f"only {len(hold)} of the {hold_requests} requests after the budget were made: "
            f"the browser failed ({type(broke).__name__}: {broke})",
            expected=f"{hold_requests} requests",
            actual=f"{len(hold)} requests",
            kind=Kind.UNAVAILABLE,
        )
    if broke and not failures:
        raise broke

    rule = matches_casb_rule(rule_name)
    needed = {v.marker for v in hold if v.traffic.blocked}
    rows: dict[str, SecurityEvent] = {}
    under_rule: list[SecurityEvent] = []
    # 검사가 이미 실패했으면 행이 판정을 바꿀 수 없으므로 상한이 있는 근거 대기만 하고,
    # 그때 행이 없어도 아무것도 증명하지 않는다.
    gave_up = bool(failures)
    limit = min(event_timeout_sec, CASB_FAILED_ROW_WAIT_SEC) if gave_up else event_timeout_sec
    unreadable = ""
    wait_began = time.monotonic()

    def wrong(row: SecurityEvent) -> bool:
        return str(row.get("action") or "") != "BLOCK" or in_app_service_name(row) != expected_service

    def collect() -> bool | None:
        nonlocal gave_up
        under_rule[:] = [e for e in casb_log.events() if rule(e)]
        for event in under_rule:
            rows.setdefault(marker_of(event.get("request_uri")), event)
        found = needed & set(rows)
        if found == needed:
            return True
        if any(wrong(rows[m]) for m in found) and time.monotonic() - wait_began >= CASB_FAILED_ROW_WAIT_SEC:
            gave_up = True
            return True
        return None

    refused: Exception | None = None  # 위반이 확정되지 않았으면 ERROR가 되는 읽기 실패
    try:
        poll_until(collect, timeout_sec=limit, description=f"casb rows for the requests to {url}")
    except PollTimeout:
        pass
    except Exception as exc:  # noqa: BLE001 - _log_read_failure로 분류한다
        cause = _log_read_failure(exc)
        unreadable = f"{cause} failure, {type(exc).__name__}: {exc}"
        if cause not in ("api", "network"):
            refused = exc
    waited = time.monotonic() - wait_began

    for v in visits:
        v.row = rows.get(v.marker)
    if needed and not under_rule and not unreadable and not gave_up:
        case.record(
            Step.EVENT,
            ok=False,
            detail=f"no casb_security_log row under {rule_name} within {event_timeout_sec}s",
            expected=f"casb security event naming {rule_name}",
            actual="no matching event",
            kind=Kind.ASSERTION,
        )
        failures.append(f"no security event appeared under {rule_name}")
    first: SecurityEvent | None = None
    for v in visits:
        row = v.row
        judged = v.phase == "hold" and v.traffic.blocked
        if row is None:
            if not judged or not (under_rule or unreadable or gave_up):
                continue
            others = sorted({str(e.get("request_uri")) for e in under_rule})
            if unreadable:
                why = f"the CASB log could not be read ({unreadable})"
            elif gave_up:
                why = f"none within the {waited:.0f}s left for evidence once the check had failed"
            else:
                why = (
                    f"none within {event_timeout_sec}s; the rows under {rule_name} are for other "
                    f"requests: {others[:3]}"
                )
            case.record(
                Step.EVENT,
                ok=False,
                detail=f"no casb_security_log row for {v.where}: {why}",
                expected=f"the row for #{v.number} ({v.marker})",
                actual=others,
                kind=Kind.UNAVAILABLE,
            )
            continue
        action, service = str(row.get("action") or ""), in_app_service_name(row)
        observed = {
            "rule": row.get("rule_name"), "request": row.get("request_uri"), "action": action,
            "service": service, "time": row.get("time"),
        }
        logged = _logged_after(row, v.sent_utc)
        when = f", logged {logged} from when it was sent" if logged else ""
        if not judged:
            case.record(
                Step.EVENT,
                ok=True,
                detail=f"casb_security_log_id={row.event_id} logged {action} for {v.where}, which "
                f"came back as {describe(v.traffic)}{when} (recorded, not judged)",
                expected="recorded as-is",
                actual=observed,
                kind=Kind.EVIDENCE,
            )
            continue
        case.event_ids.append(row.event_id)
        ok = not wrong(row)
        case.record(
            Step.EVENT,
            ok=ok,
            detail=f"casb_security_log_id={row.event_id} for #{v.number}{when}",
            expected={"rule": rule_name, "request": v.traffic.url, "action": "BLOCK", "service": expected_service},
            actual=observed,
            kind=Kind.ASSERTION,
        )
        if not ok:
            failures.append(
                f"event {row.event_id} for #{v.number} records action {action!r} for {service!r}, "
                f"expected BLOCK for {expected_service!r}"
            )
        first = first or row

    case.record(
        Step.ACTION,
        ok=True,
        detail=f"{len(visits)} requests to {url} under {rule_name}: {len(propagation)} back by the "
        f"{budget}s deadline, {1 if boundary else 0} out at it, {len(hold)} after it; rows "
        f"collected for {waited:.0f}s",
        actual=[
            {
                "request": v.number,
                "marker": v.marker,
                "phase": v.phase,
                "sent": f"+{v.sent_sec:.1f}s",
                "back": f"+{v.back_sec:.1f}s",
                "sent_utc": _utc(v.sent_utc),
                "back_utc": _utc(v.back_utc),
                "result": describe(v.traffic),
                "row": None if v.row is None else {
                    "id": v.row.event_id,
                    "action": v.row.get("action"),
                    "service": in_app_service_name(v.row),
                    "time": v.row.get("time"),
                    "logged": _logged_after(v.row, v.sent_utc),
                },
            }
            for v in visits
        ],
        kind=Kind.EVIDENCE,
    )

    if failures:
        message = f"{failure}: " + "; ".join(failures)
        if broke:
            message += f" (then the browser failed: {broke})"
        if refused:
            message += f" (then the CASB log read failed: {unreadable})"
        if broke or refused:
            raise AssertionError(message) from (broke or refused)
        raise AssertionError(message)
    if refused:
        raise refused
    return first


def record_identity(case: CaseResult, event: SecurityEvent) -> None:
    """이벤트의 누가/어디서/무엇을 기록한다.

    빠진 필드는 보고하지만 그것만으로 케이스를 실패시키지 않는다: 테넌트가 어떤 필드를
    채우는지는 제품의 문제다.
    """
    identity = identity_of(event)
    missing = [name for name, value in identity.items() if value in (None, "", [])]
    case.record(
        Step.EVENT,
        ok=not missing,
        detail="identity fields" + (f"; missing: {missing}" if missing else " complete"),
        expected=sorted(identity),
        actual=identity,
        kind=Kind.EVIDENCE,
    )
    if missing:
        log.warning("Security event %s is missing fields: %s", event.event_id, missing)


def pass_case(case: CaseResult) -> None:
    """본문이 끝났다고 주장한다. 실제 판정은 bat.verdict.classify가 하며,
    @pytest.mark.verifies의 기준이 전부 통과해야만 PASS를 준다."""
    case.status = Status.PASS


class CleanupInterrupted(Exception):
    """케이스 본문이 끝나기 전에 리소스를 지우지 못해, 그 뒤의 검사가 실행되지 않았다."""


def cleanup_failed(case: CaseResult, warning: Exception) -> None:
    """케이스 본문을 감싸 잡은 CleanupWarning을 처리한다.

    본문이 완료를 주장한 뒤(pass_case)라면 삭제 실패는 정리 차원의 경고다: 검사는 전부
    돌았고, 남은 리소스는 'bat sweep'용으로 보고한다. 그 전이라면 삭제 실패로 본문의 나머지가
    건너뛰어졌는데, 그때까지 기록된 단계만으로 기준이 충족될 수도 있으므로 케이스는 ERROR로
    끝난다. 보안 FAIL과 구분되는 실행 문제다.
    """
    case.cleanup_warnings.append(str(warning))
    if case.status is not Status.PASS:
        raise CleanupInterrupted(
            f"cleanup failed before the case finished, so its remaining checks "
            f"never ran: {warning}"
        ) from warning


def unverified(case: CaseResult, step: Step, reason: str) -> NoReturn:
    """중단한다: 이 케이스가 확인하려는 동작을 확인할 수 없다."""
    case.record(step, ok=False, detail=reason, kind=Kind.UNAVAILABLE)
    raise VerificationUnavailable(reason)


def module_scope_or_stop(case: CaseResult, run_context, web_policies, executor, web_log,
                         module_rule: dict, probe_host: str = "") -> None:
    """시그니처 모듈 BLOCK 전에: 이 모듈이 어떤 목록에도 없는 요청을 잡는가?

    모듈 rule에는 목적지가 없어서 무엇에 매칭할지는 제품이 정한다. 시그니처 목록 밖의
    요청까지 매칭한다면, BLOCK은 관리 API와 자기 DELETE까지 포함해 러너의 모든 요청을 끊는다.

    그래서 모듈의 LOGGING 사본을 먼저 걸고, 그다음 probe 호스트에 LOGGING HTTP_HOST 정책을
    건다(나중에 만들어서 그 뒤에 평가된다). 하나가 기록될 때까지 probe 호스트로 marker를 단
    요청을 보낸다:
      - 대조 정책으로 기록됨: 모듈이 통과시켰으므로 BLOCK이 안전하다
      - 모듈로 기록됨: FAIL — 목록 밖까지 매칭한다. BLOCK은 시도하지 않는다
      - 시간 안에 둘 다 아님: UNVERIFIED — 역시 BLOCK하지 않는다
    probe 호스트는 probe_host(기본 BLOCK_TARGET_HOST)다.
    """
    from bat.fixtures.enums import Condition, RiskLevel, Subject
    from bat.fixtures.naming import resource_name
    from bat.fixtures.policies import WebPolicyFactory
    from bat.fixtures.testdata import BLOCK_TARGET_HOST
    from bat.traffic.http import curl_status

    host = probe_host or BLOCK_TARGET_HOST
    probe_path = "/get" if host == BLOCK_TARGET_HOST else "/"
    module_name = resource_name(case.case_id, run_context.run_id, "scope")
    control_name = resource_name(case.case_id, run_context.run_id, "scope-ctl")
    marker = f"bat={module_name.lower()}-"
    control = WebPolicyFactory.build_rule(Subject.HTTP_HOST, Condition.IS, [host])
    verdict, sent = "", 0
    with web_policies.temporary(module_name, [module_rule], action_type="LOGGING",
                                risk_level=RiskLevel.MINOR), \
            web_policies.temporary(control_name, [control], action_type="LOGGING",
                                   risk_level=RiskLevel.MINOR):
        deadline = time.monotonic() + run_context.event_poll_timeout_sec
        while time.monotonic() < deadline and not verdict:
            sent += 1
            curl_status(executor, f"https://{host}{probe_path}?{marker}{sent}")
            time.sleep(5)
            names = {e.get("policy_name") for e in web_log.security_events(lookback_min=10)
                     if marker in str(e.get("full_uri") or "")}
            verdict = "broad" if module_name in names else "narrow" if control_name in names else ""

    if verdict == "narrow":
        case.record(Step.SETUP, ok=True, kind=Kind.EVIDENCE,
                    detail=f"{module_rule['subject']} (LOGGING) left {host} to the control "
                           f"policy after {sent} request(s): it does not match unlisted traffic")
        return
    if verdict == "broad":
        message = (f"{module_rule['subject']} matched {host}, which no signature list "
                   f"names (LOGGING copy, {sent} request(s)) — as BLOCK it would cut off every "
                   f"request from this endpoint, the management API included; BLOCK not attempted")
        case.record(Step.USER_RESULT, ok=False, detail=message,
                    expected=f"only listed entries match; {host} left to the control policy",
                    actual=f"logged under {module_name}")
        raise AssertionError(message)
    unverified(case, Step.USER_RESULT,
               f"neither {module_name} nor {control_name} logged {host} within "
               f"{run_context.event_poll_timeout_sec}s ({sent} request(s)); BLOCK not attempted")
