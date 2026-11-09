"""계층 간 cross 케이스: 두 제품이 같은 요청을 판단할 때 어떻게 되는가.

SSE는 DNS 계층(DNS Firewall), 네트워크 계층(Application Firewall), HTTP 프록시
(웹정책, DLP, CASB)에서 정책을 적용한다. 이 케이스들은 두 계층이 함께 적용될 때
사용자가 어느 계층의 결과를 겪고 어느 로그가 그것을 기록하는지 확인한다.

대상은 BLOCK_TARGET_HOST가 아니라 SECOND_HOST다. DNS 차단은 모든 레인에서 그 이름을
앗아가고, DLP 케이스가 BLOCK_TARGET_HOST를 동시에 쓰기 때문이다.
"""
from __future__ import annotations

import pytest

from bat.events.poller import PollTimeout, poll_until
from bat.events.web_log import all_of, matches_policy, matches_target
from bat.fixtures.enums import ActionType, Condition, RiskLevel, Subject
from bat.fixtures.graphql_policies import ApplicationFirewallFactory, DnsFirewallFactory
from bat.fixtures.naming import resource_name
from bat.fixtures.policies import CleanupWarning, DlpPolicyFactory, WebPolicyFactory
from bat.fixtures.testdata import POST_TARGET_URL, SECOND_HOST, SECOND_URL, keyword_payload, marker
from bat.models import Kind, Step
from bat.traffic.http import curl_status, resolve_ip
from tests.support import (
    await_network_event,
    cleanup_failed,
    curl_until_blocked,
    curl_until_unreachable,
    describe,
    dns_lookup_until_allowed,
    dns_lookup_until_blocked,
    expect_no_event,
    marked_url,
    matches_network_policy,
    pass_case,
)

pytestmark = [
    pytest.mark.product("cross"),
    pytest.mark.lane("b"),
    pytest.mark.xdist_group("lane-b"),
]


def await_baseline(executor, timeout_sec: float) -> None:
    """SECOND_HOST를 쓰기 전에 그 이름이 다시 해석될 때까지 기다린다.

    여기 있는 모든 케이스가 그 이름을 막고, 삭제된 DNS Firewall 정책은 적용이 멈추기까지
    몇 초가 걸린다.
    """
    dns_lookup_until_allowed(executor, SECOND_HOST, timeout_sec)


@pytest.mark.case("BAT-X-002")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_dns_firewall_block_survives_a_web_allow(
    case, run_context, web_policies, dns_firewall, executor, network_log
):
    """같은 호스트를 허용하는 웹정책이 있어도 DNS Firewall 차단은 유지된다."""
    await_baseline(executor, run_context.policy_propagation_timeout_sec)
    allow_name = resource_name(case.case_id, run_context.run_id, "allow")
    block_name = resource_name(case.case_id, run_context.run_id, "dns")
    allow_rule = WebPolicyFactory.build_rule(Subject.HTTP_HOST, Condition.IS, [SECOND_HOST])

    try:
        with web_policies.temporary(
            allow_name, [allow_rule], action_type=ActionType.ALLOW
        ) as allower:
            case.policy_ids.append(allower.policy_id)
            # 가장 작은 번호가 먼저 평가되므로, 웹 계층은 이 호스트에 대해 가능한 한
            # 가장 관대해진다.
            web_policies.set_priority([(allower.policy_id, 1)])

            with dns_firewall.temporary(
                block_name,
                [DnsFirewallFactory.fqdn_rule([SECOND_HOST])],
                action_type="BLOCK",
            ) as blocker:
                case.policy_ids.append(blocker.policy_id)

                traffic = dns_lookup_until_blocked(
                    executor, SECOND_HOST, run_context.policy_propagation_timeout_sec
                )
                case.record(
                    Step.USER_RESULT,
                    ok=traffic.blocked,
                    detail=traffic.detail,
                    expected="name resolution fails despite the web ALLOW",
                    actual="resolution failed" if traffic.blocked else "resolution succeeded",
                )
                assert traffic.blocked, (
                    f"A web policy allowing {SECOND_HOST} suppressed the DNS Firewall "
                    f"block on the same host: {traffic.detail}"
                )

                await_network_event(
                    case,
                    network_log,
                    block_name,
                    kind="dns",
                    timeout_sec=run_context.event_poll_timeout_sec,
                )
                pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-X-003")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_application_firewall_block_survives_a_web_allow(
    case, run_context, web_policies, application_firewall, executor, network_log
):
    """같은 호스트를 허용하는 웹정책이 있어도 Application Firewall 차단은 유지된다."""
    await_baseline(executor, run_context.policy_propagation_timeout_sec)
    allow_name = resource_name(case.case_id, run_context.run_id, "allow")
    block_name = resource_name(case.case_id, run_context.run_id, "fw")
    # DNS가 아직 동작할 때 해석해 둔다. 이 정책은 이름이 아니라 주소로 막는다.
    destination_ip = resolve_ip(executor, SECOND_HOST)
    case.record(Step.SETUP, ok=True, detail=f"{SECOND_HOST} resolved to {destination_ip}")
    allow_rule = WebPolicyFactory.build_rule(Subject.HTTP_HOST, Condition.IS, [SECOND_HOST])
    subject = ApplicationFirewallFactory.subject(
        source_ips=["0.0.0.0/0"], destination_ips=[destination_ip]
    )

    try:
        with web_policies.temporary(
            allow_name, [allow_rule], action_type=ActionType.ALLOW
        ) as allower:
            case.policy_ids.append(allower.policy_id)
            web_policies.set_priority([(allower.policy_id, 1)])

            with application_firewall.temporary(
                block_name, subject, action_type="BLOCK"
            ) as blocker:
                case.policy_ids.append(blocker.policy_id)

                traffic = curl_until_unreachable(
                    executor, SECOND_URL, run_context.policy_propagation_timeout_sec
                )
                case.record(
                    Step.USER_RESULT,
                    ok=not traffic.status_code,
                    detail=traffic.detail,
                    expected="connection refused despite the web ALLOW",
                    actual="connection refused"
                    if not traffic.status_code
                    else f"HTTP {traffic.status_code}",
                )
                assert not traffic.status_code, (
                    f"A web policy allowing {SECOND_HOST} suppressed the Application "
                    f"Firewall block on {destination_ip} (HTTP {traffic.status_code})"
                )

                await_network_event(
                    case,
                    network_log,
                    block_name,
                    kind="firewall",
                    timeout_sec=run_context.event_poll_timeout_sec,
                )
                pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-X-005")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P2")
def test_removing_one_layer_leaves_the_other_enforcing(
    case, run_context, dns_firewall, application_firewall, executor
):
    """두 계층이 같이 막고 있을 때 한쪽을 지워도 다른 쪽 차단은 그대로다.

    DNS 차단은 망에 따라 해석 실패(연결 불가) 또는 차단 페이지(403)로 나타난다(lguplus는 후자).
    """
    await_baseline(executor, run_context.policy_propagation_timeout_sec)
    dns_name = resource_name(case.case_id, run_context.run_id, "dns")
    fw_name = resource_name(case.case_id, run_context.run_id, "fw")
    destination_ip = resolve_ip(executor, SECOND_HOST)
    subject = ApplicationFirewallFactory.subject(
        source_ips=["0.0.0.0/0"], destination_ips=[destination_ip]
    )

    try:
        with application_firewall.temporary(fw_name, subject, action_type="BLOCK") as fw:
            case.policy_ids.append(fw.policy_id)

            with dns_firewall.temporary(
                dns_name,
                [DnsFirewallFactory.fqdn_rule([SECOND_HOST])],
                action_type="BLOCK",
            ) as dns:
                case.policy_ids.append(dns.policy_id)
                stacked = curl_until_unreachable(
                    executor, SECOND_URL, run_context.policy_propagation_timeout_sec
                )
                assert not stacked.status_code or stacked.blocked, (
                    "Neither layer took effect, so removing one would prove nothing"
                )

            # 여기서는 DNS Firewall 정책이 지워졌고, 네트워크 계층 정책은 남아 있다. 단말 DNS
            # 캐시에 차단 페이지 주소가 남아 있을 수 있어, 실제 목적지 IP로 붙여 확인한다.
            remaining = curl_until_unreachable(
                executor, SECOND_URL, run_context.policy_propagation_timeout_sec,
                pin_ip=destination_ip,
            )
            case.record(
                Step.USER_RESULT,
                ok=not remaining.status_code,
                detail=remaining.detail,
                expected="still blocked by the Application Firewall policy",
                actual="connection refused"
                if not remaining.status_code
                else f"HTTP {remaining.status_code}",
            )
            assert not remaining.status_code, (
                f"Deleting the DNS Firewall policy also stopped the Application "
                f"Firewall policy from blocking {destination_ip} "
                f"(HTTP {remaining.status_code})"
            )
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-X-007")
@pytest.mark.verifies(Step.EVENT)
@pytest.mark.priority("P2")
def test_dns_firewall_events_stay_out_of_the_web_log(
    case, run_context, dns_firewall, executor, network_log, web_log
):
    """DNS Firewall 차단은 DNS 보안 로그에만 남고 웹 보안 로그에는 남지 않는다."""
    await_baseline(executor, run_context.policy_propagation_timeout_sec)
    policy_name = resource_name(case.case_id, run_context.run_id)

    try:
        with dns_firewall.temporary(
            policy_name,
            [DnsFirewallFactory.fqdn_rule([SECOND_HOST])],
            action_type="BLOCK",
        ) as policy:
            case.policy_ids.append(policy.policy_id)

            traffic = dns_lookup_until_blocked(
                executor, SECOND_HOST, run_context.policy_propagation_timeout_sec
            )
            assert traffic.blocked, (
                "The DNS Firewall policy never took effect, so checking where its "
                "event landed would prove nothing"
            )

            await_network_event(
                case,
                network_log,
                policy_name,
                kind="dns",
                timeout_sec=run_context.event_poll_timeout_sec,
            )

            absent = web_log.no_security_event(matches_policy(policy_name))
            case.record(
                Step.EVENT,
                ok=absent,
                detail="web security log checked for this policy",
                expected="nothing in the web security log",
                actual="nothing" if absent else "a web security event named this policy",
            )
            assert absent, (
                f"A DNS Firewall block also produced a web security log entry for "
                f"{policy_name}; the two logs are not the separate views they appear to be"
            )
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-X-008")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_dns_layer_intercepts_before_dlp_inspection(
    case, run_context, rest, web_policies, dns_firewall, executor, network_log, web_log
):
    """DNS Firewall이 막으면 요청이 DLP 검사 단계까지 가지도 못한다.

    마지막 요청(마커) 전에 단말 DNS 캐시를 비워, 그 요청이 이름 해석부터 다시 하게 한다.
    PASS하려면 그 요청이 통과하지 않고, 요청 뒤 DNS Firewall 정책의 새 행이 생기고,
    DLP 연결 웹정책에는 그 요청의 행이 없어야 한다(뒤에 보낸 DLP 표지 요청의 행이 나타난
    다음 판정).
    """
    await_baseline(executor, run_context.policy_propagation_timeout_sec)
    dlp = DlpPolicyFactory(rest)
    token = marker(case.case_id, run_context.run_id)
    dlp_name = resource_name(case.case_id, run_context.run_id, "dlp")
    block_name = resource_name(case.case_id, run_context.run_id, "block")
    dns_name = resource_name(case.case_id, run_context.run_id, "dns")

    try:
        with dlp.temporary(
            dlp_name, [DlpPolicyFactory.keyword_rule("bat-token", [token])]
        ) as rule:
            case.policy_ids.append(f"dlp:{rule.policy_id}")

            with web_policies.temporary(
                block_name,
                [WebPolicyFactory.dlp_rule(rule.policy_id)],
                action_type=ActionType.BLOCK,
                risk_level=RiskLevel.MAJOR,
            ) as blocker:
                case.policy_ids.append(blocker.policy_id)

                # 지금 막고 있는 것이 DLP임을 먼저 확인한다. HTTP 계층이 만드는 403
                # 차단 페이지다.
                inspected = curl_until_blocked(
                    executor,
                    SECOND_URL,
                    run_context.policy_propagation_timeout_sec,
                    method="POST",
                    data=keyword_payload(token),
                )
                assert inspected.blocked, (
                    f"DLP did not block the payload on its own (HTTP "
                    f"{inspected.status_code}), so layering DNS on top would prove nothing"
                )
                case.record(
                    Step.SETUP,
                    ok=True,
                    detail=f"DLP alone: HTTP {inspected.status_code} (block page)",
                )

                with dns_firewall.temporary(
                    dns_name,
                    [DnsFirewallFactory.fqdn_rule([SECOND_HOST])],
                    action_type="BLOCK",
                ) as dns:
                    case.policy_ids.append(dns.policy_id)

                    # HTTP 요청을 판정하기 전에 DNS 계층이 실제로 적용되는지 확인한다.
                    # nslookup은 리졸버에 직접 묻기 때문에 curl과 달리 단말 자체의
                    # DNS 캐시로 응답될 수 없다.
                    lookup = dns_lookup_until_blocked(
                        executor, SECOND_HOST, run_context.policy_propagation_timeout_sec
                    )
                    assert lookup.blocked, (
                        f"The DNS Firewall policy never took effect on {SECOND_HOST}, "
                        f"so there is no second layer to test: {lookup.detail}"
                    )

                    await_network_event(
                        case,
                        network_log,
                        dns_name,
                        kind="dns",
                        timeout_sec=run_context.event_poll_timeout_sec,
                    )
                    dns_rows = matches_network_policy(dns_name)
                    seen = {e.event_id for e in network_log.dns_events() if dns_rows(e)}

                    executor.run("ipconfig /flushdns", timeout_sec=15)
                    final = marked_url(SECOND_URL, case, run_context, "final")
                    traffic = curl_status(executor, final, method="POST", data=keyword_payload(token))
                    case.record(
                        Step.USER_RESULT,
                        ok=not traffic.delivered,
                        kind=Kind.ASSERTION,
                        detail=f"{final} -> {describe(traffic)}",
                        expected="the request does not go through",
                        actual=describe(traffic),
                    )
                    assert not traffic.delivered, (
                        f"Neither the DNS Firewall block on {SECOND_HOST} nor the "
                        f"DLP-linked web policy stopped the request (HTTP "
                        f"{traffic.status_code}), even though each of them blocks it alone"
                    )

                    try:
                        new_row = poll_until(
                            lambda: next(
                                (e for e in network_log.dns_events() if dns_rows(e) and e.event_id not in seen),
                                None,
                            ),
                            timeout_sec=run_context.event_poll_timeout_sec,
                            description=f"a new {dns_name} row after the final request",
                        )
                    except PollTimeout as timeout:
                        case.record(
                            Step.EVENT, ok=False, kind=Kind.ASSERTION, detail=str(timeout),
                            expected=f"a new {dns_name} row for the final request's lookup",
                        )
                        raise AssertionError(
                            f"The final request left no new DNS Firewall row, so it was not "
                            f"stopped at the DNS layer: {timeout}"
                        ) from timeout
                    case.event_ids.append(new_row.event_id)
                    case.record(
                        Step.EVENT, ok=True, kind=Kind.ASSERTION,
                        detail=f"dns_security_log id={new_row.event_id} after the final request "
                        f"(cache flushed first)",
                        expected=f"a new {dns_name} row", actual=new_row.event_id,
                    )

                    blocker_rows = matches_policy(block_name, blocker.policy_id)

                    def sentinel() -> str:
                        url = marked_url(POST_TARGET_URL, case, run_context, "sentinel")
                        curl_status(executor, url, method="POST", data=keyword_payload(token))
                        return url

                    expect_no_event(
                        case, web_log,
                        absent=all_of(blocker_rows, matches_target(final)),
                        what=f"{block_name} (DLP) row for the final request",
                        sentinel=sentinel, sentinel_match=blocker_rows,
                        timeout_sec=run_context.event_poll_timeout_sec,
                    )
                    pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)
