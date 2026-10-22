"""SWG 호스트 기반 정책 케이스.

BAT-SWG-001은 모든 계층을 처음부터 끝까지 거치므로, 새 환경에서 가장 먼저 돌릴
케이스다.
"""
from __future__ import annotations

import contextlib
import logging

import pytest

from bat.clients.errors import ApiError, EndpointError
from bat.events.poller import PollTimeout, poll_until
from bat.fixtures.enums import ActionType, Condition, LogAction, RiskLevel, Subject
from bat.fixtures.naming import resource_name
from bat.fixtures.policies import CleanupWarning, WebPolicyFactory
from bat.fixtures.testdata import ALLOW_TARGET_URL, BLOCK_TARGET_HOST, BLOCK_TARGET_URL
from bat.events.web_log import matches_policy
from bat.models import Kind, Step
from tests.support import (
    await_security_event,
    cleanup_failed,
    describe,
    expect_allowed,
    expect_block,
    marker_of,
    pass_case,
    record_identity,
    unverified,
    visit_until_blocked,
)

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.product("swg"),
    pytest.mark.lane("b"),
    pytest.mark.xdist_group("lane-b"),
]


@pytest.mark.case("BAT-SWG-001")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P0")
@pytest.mark.critical
@pytest.mark.smoke
def test_http_host_block(case, run_context, web_policies, browser_session, web_log):
    """HTTP Host 조건으로 차단한 사이트가 실제로 차단되고 보안 로그에 남는다."""
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = WebPolicyFactory.build_rule(Subject.HTTP_HOST, Condition.IS, [BLOCK_TARGET_HOST])

    try:
        with web_policies.temporary(
            policy_name, [rule], action_type=ActionType.BLOCK, risk_level=RiskLevel.MAJOR
        ) as policy:
            case.policy_ids.append(policy.policy_id)
            case.record(
                Step.SETUP,
                ok=True,
                detail=f"web policy {policy_name} (id={policy.policy_id}) "
                f"blocking {BLOCK_TARGET_HOST}",
            )

            traffic = visit_until_blocked(
                browser_session,
                BLOCK_TARGET_URL,
                case.case_id,
                run_context.policy_propagation_timeout_sec,
            )
            case.record(
                Step.ACTION,
                ok=True,
                detail=f"browser visited {BLOCK_TARGET_URL} from {case.endpoint or 'runner'}",
            )
            expect_block(case, traffic, BLOCK_TARGET_URL)

            event = await_security_event(
                case,
                web_log,
                policy_name,
                timeout_sec=run_context.event_poll_timeout_sec,
                expected_action=LogAction.BLOCK,
                expected_target=BLOCK_TARGET_HOST,
                policy_id=policy.policy_id,
            )
            record_identity(case, event)
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-SWG-002")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P0")
@pytest.mark.critical
def test_non_matching_host_allowed(case, run_context, web_policies, browser_session, web_log):
    """정책에 매칭되지 않는 사이트는 정상 접속되고 보안 로그가 남지 않는다."""
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = WebPolicyFactory.build_rule(Subject.HTTP_HOST, Condition.IS, [BLOCK_TARGET_HOST])

    try:
        with web_policies.temporary(policy_name, [rule], action_type=ActionType.BLOCK) as policy:
            case.policy_ids.append(policy.policy_id)
            case.record(
                Step.SETUP, ok=True, detail=f"policy {policy_name} blocks {BLOCK_TARGET_HOST} only"
            )

            traffic = browser_session.visit(ALLOW_TARGET_URL, case_id=case.case_id)
            case.record(Step.ACTION, ok=True, detail=f"browser visited {ALLOW_TARGET_URL}")
            expect_allowed(case, traffic, ALLOW_TARGET_URL)

            # 여기서는 부재가 판정의 전부다. 이 테넌트는 접근 로그를 남기지 않으므로
            # 찾아볼 긍정 기록이 없다.
            quiet = web_log.no_security_event(
                matches_policy(policy_name)
            )
            case.record(
                Step.EVENT,
                ok=quiet,
                detail="a non-matching request must not raise a security event",
                expected="no event for this policy",
                actual="no event" if quiet else "event found",
            )
            assert quiet, f"Unexpected security event recorded for {policy_name}"
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-SWG-010")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P1")
def test_priority_decides_and_flipping_it_flips_the_outcome(
    case, run_context, web_policies, executor
):
    """겹치는 ALLOW/BLOCK의 판정은 우선순위가 정하고, 순서를 바꾸면 결과도 바뀐다.

    BAT-SWG-007과 달리 같은 두 정책의 순서만 뒤집어 판정이 따라 바뀌는지 본다.
    """
    from tests.support import curl_until_blocked, curl_until_delivered, expect_delivered

    allow_name = resource_name(case.case_id, run_context.run_id, "allow")
    block_name = resource_name(case.case_id, run_context.run_id, "block")
    rule = WebPolicyFactory.build_rule(Subject.HTTP_HOST, Condition.IS, [BLOCK_TARGET_HOST])

    try:
        with web_policies.temporary(
            allow_name, [rule], action_type=ActionType.ALLOW
        ) as allower:
            case.policy_ids.append(allower.policy_id)

            with web_policies.temporary(
                block_name,
                [rule],
                action_type=ActionType.BLOCK,
                risk_level=RiskLevel.MAJOR,
            ) as blocker:
                case.policy_ids.append(blocker.policy_id)

                # 가장 작은 번호가 이긴다. BLOCK이 먼저면 요청이 막혀야 한다.
                web_policies.set_priority([(blocker.policy_id, 1), (allower.policy_id, 2)])
                blocked = curl_until_blocked(
                    executor, BLOCK_TARGET_URL, run_context.policy_propagation_timeout_sec
                )
                case.record(
                    Step.USER_RESULT,
                    ok=blocked.blocked,
                    detail=f"BLOCK at priority 1 -> HTTP {blocked.status_code}",
                    expected="blocked",
                    actual=f"HTTP {blocked.status_code}",
                )
                assert blocked.blocked, (
                    f"The BLOCK policy at priority 1 did not stop the request "
                    f"(HTTP {blocked.status_code}), so the flip below would prove nothing"
                )

                # 같은 두 정책의 순서만 바꾼다. 판정도 따라 바뀌어야 한다.
                web_policies.set_priority([(allower.policy_id, 1), (blocker.policy_id, 2)])
                allowed = curl_until_delivered(
                    executor,
                    BLOCK_TARGET_URL,
                    run_context.policy_propagation_timeout_sec,
                    request_timeout_sec=15,
                )
                expect_delivered(
                    case,
                    allowed,
                    expected="allowed once the ALLOW outranks the BLOCK",
                    failure="Moving the ALLOW policy above the BLOCK did not change the "
                    "verdict. Priority is then not what decides",
                )
                pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


def _record_raw_ip_reach(case, run_context, web_policies, executor, web_log, ip: str, marked) -> None:
    """IP 직접 요청이 통과했으므로, SSE가 그런 요청을 아예 보는지 기록한다.

    판정 검사가 끝난 뒤 만든 LOGGING DESTINATION_IP 정책을 쓰므로 BLOCK의 매칭을
    가져갈 수 없다. 근거로만 남긴다. 오류는 예외로 던지지 않고 기록만 한다.
    """
    from bat.traffic.http import curl_status

    reach_name = resource_name(case.case_id, run_context.run_id, "reach")
    rule = WebPolicyFactory.build_rule(Subject.DESTINATION_IP, Condition.IS, [ip])
    with contextlib.ExitStack() as stack:
        try:
            reach = stack.enter_context(
                web_policies.temporary(
                    reach_name, [rule], action_type="LOGGING", risk_level=RiskLevel.MINOR
                )
            )
        except ApiError as exc:
            note = f"the LOGGING DESTINATION_IP policy for {ip} could not be created ({exc})"
            case.record(Step.EVENT, ok=False, detail=note, kind=Kind.EVIDENCE)
            return
        case.policy_ids.append(reach.policy_id)
        reach_hit = matches_policy(reach_name, reach.policy_id)
        sent: list[str] = []

        def probe():
            sent.append(marked(f"reach-{len(sent) + 1}"))
            curl_status(executor, sent[-1], timeout_sec=15)
            markers = {marker_of(url) for url in sent}
            rows = web_log.security_events()
            return next(
                (e for e in rows if reach_hit(e) and marker_of(e.get("full_uri")) in markers), None
            )

        row, trouble = None, ""
        try:
            row = poll_until(
                probe,
                timeout_sec=run_context.event_poll_timeout_sec,
                description=f"a raw-IP request under {reach_name}",
                initial_interval=2.0,
            )
        except PollTimeout:
            pass
        except (ApiError, EndpointError) as exc:
            trouble = f" (the check stopped early: {exc})"

        if row is not None:
            note = (
                f"SSE logged a raw-IP request under a LOGGING DESTINATION_IP {ip} policy "
                f"(security_log_id={row.event_id}): it sees the request, and the HTTP_HOST "
                f"rule does not match it"
            )
        else:
            note = (
                f"no raw-IP request appeared under a LOGGING DESTINATION_IP {ip} policy"
                f"{trouble or f' within {run_context.event_poll_timeout_sec}s'}, so it may "
                f"not reach SSE at all"
            )
        case.record(
            Step.EVENT,
            ok=row is not None,
            detail=note,
            expected="the raw-IP request shows up under the LOGGING reach policy",
            actual={"reach_row": row.event_id if row else None, "requests": sent},
            kind=Kind.EVIDENCE,
        )


@pytest.mark.case("BAT-SWG-022")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P2")
def test_host_block_matches_the_hostname_not_the_raw_ip(
    case, run_context, web_policies, executor, web_log
):
    """HTTP_HOST로 막은 호스트명은 차단되고, 같은 목적지를 IP로 직접 접속한 결과는 기록한다.

    HTTP_HOST는 호스트명을 보는 조건이라 IP 직접 접속에는 매칭되지 않는 게 일반적이다.
    그래서 호스트명 차단만 판정하고, IP 요청 결과와 SSE가 그 요청을 보는지는 근거로 남긴다.
    """
    from tests.support import curl_until_blocked
    from bat.traffic.http import curl_status, resolve_ip

    destination_ip = resolve_ip(executor, BLOCK_TARGET_HOST)
    case.record(Step.SETUP, ok=True, detail=f"{BLOCK_TARGET_HOST} resolved to {destination_ip}")
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = WebPolicyFactory.build_rule(Subject.HTTP_HOST, Condition.IS, [BLOCK_TARGET_HOST])

    def marked(label: str) -> str:
        return f"https://{destination_ip}/get?bat={case.case_id}-{run_context.run_id}-{label}".lower()

    try:
        with web_policies.temporary(
            policy_name, [rule], action_type=ActionType.BLOCK, risk_level=RiskLevel.MAJOR
        ) as policy:
            case.policy_ids.append(policy.policy_id)

            by_hostname = curl_until_blocked(
                executor, BLOCK_TARGET_URL, run_context.policy_propagation_timeout_sec
            )
            case.record(
                Step.USER_RESULT,
                ok=by_hostname.blocked,
                detail=f"by hostname -> HTTP {by_hostname.status_code}",
                expected="blocked by hostname",
                actual=f"HTTP {by_hostname.status_code}",
            )
            assert by_hostname.blocked, (
                f"The policy never blocked {BLOCK_TARGET_URL} by hostname, so "
                f"testing the IP-direct bypass would prove nothing"
            )

            ip_url = marked("ip")
            by_ip = curl_status(executor, ip_url, timeout_sec=15)
            case.record(
                Step.USER_RESULT,
                ok=True,
                detail=f"by raw IP ({ip_url}) -> {describe(by_ip)} (recorded, not judged: "
                f"HTTP_HOST matches the hostname, not an IP)",
                expected="recorded as-is",
                actual=describe(by_ip),
                kind=Kind.EVIDENCE,
            )
            # 판정할 검사는 모두 끝났다. 뒤따르는 것은 근거만 더하므로, 거기서 남은
            # LOGGING 정책은 ERROR가 아니라 정리 경고다.
            pass_case(case)
            if by_ip.delivered:
                _record_raw_ip_reach(
                    case, run_context, web_policies, executor, web_log, destination_ip, marked
                )

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-SWG-023")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P2")
def test_host_block_is_case_insensitive(case, run_context, web_policies, executor, browser_session):
    """HTTP_HOST 조건은 대소문자와 무관하게 매칭된다 — 호스트를 대문자 그대로 보내는 클라이언트(curl 등)도 막혀야 한다.

    브라우저는 호스트를 소문자로 정규화해 보내고 curl은 입력한 그대로 보낸다. curl이 막히면 PASS,
    curl은 통과했지만 브라우저가 막히면 UNVERIFIED(정규화하지 않는 클라이언트만 비켜 감), 둘 다
    통과하면 FAIL이다.
    """
    from tests.support import curl_until_blocked

    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = WebPolicyFactory.build_rule(Subject.HTTP_HOST, Condition.IS, [BLOCK_TARGET_HOST])
    uppercase_url = f"https://{BLOCK_TARGET_HOST.upper()}/get"

    try:
        with web_policies.temporary(
            policy_name, [rule], action_type=ActionType.BLOCK, risk_level=RiskLevel.MAJOR
        ) as policy:
            case.policy_ids.append(policy.policy_id)
            case.record(
                Step.SETUP,
                ok=True,
                detail=f"policy stores host as {BLOCK_TARGET_HOST!r} (lowercase)",
            )

            traffic = curl_until_blocked(
                executor, uppercase_url, run_context.policy_propagation_timeout_sec
            )
            case.record(
                Step.USER_RESULT,
                ok=traffic.blocked,
                detail=f"curl {uppercase_url} -> HTTP {traffic.status_code}",
                expected="blocked despite the uppercase host",
                actual=f"HTTP {traffic.status_code}",
                kind=Kind.ASSERTION if traffic.blocked else Kind.EVIDENCE,
            )
            # curl 단계가 끝나면 어느 쪽이든 전파 예산은 이미 다 썼다.
            browser = visit_until_blocked(
                browser_session, uppercase_url, case.case_id, run_context.policy_propagation_timeout_sec
            )
            case.record(
                Step.USER_RESULT,
                ok=browser.blocked,
                detail=f"browser {uppercase_url}: {describe(browser)} ({browser.detail or browser.url}); "
                f"the browser lowercases the host before sending",
                expected="blocked",
                actual=describe(browser),
                kind=Kind.EVIDENCE if traffic.blocked or browser.blocked else Kind.ASSERTION,
            )
            assert traffic.blocked or browser.blocked, (
                f"A policy blocking {BLOCK_TARGET_HOST!r} blocked neither curl nor the browser "
                f"for {uppercase_url}"
            )
            if not traffic.blocked:
                unverified(
                    case,
                    Step.USER_RESULT,
                    f"curl with the uppercase Host ({uppercase_url}) got HTTP {traffic.status_code}; "
                    f"the browser, which lowercases the host, was blocked — only clients that "
                    f"do not normalise the host get past HTTP_HOST",
                )
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)
