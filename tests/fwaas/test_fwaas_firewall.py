"""DNS Firewall과 Application Firewall 케이스.

둘 다 콘솔 GraphQL API(SIA.network)에만 있다.

DNS Firewall: 확인된 rule subject는 "FQDN" 하나뿐이다.

Application Firewall: 빈 `source: {}`는 아무것도 매칭하지 않으므로 정책에
`source_ips=["0.0.0.0/0"]`을 명시한다. 차단은 403 차단 페이지가 아니라 네트워크
계층에서 연결을 끊는다(curl status_code 0).

이벤트는 웹 보안 로그가 아니라 GraphQL SIA.log.dns_security_log / firewall_security_log에
있다(bat/events/network_log.py 참조).

이름 해석 실패와 연결 실패는 그것만으로는 정책의 차단이라는 근거가 아니다. 그래서 정책을
만들기 전에 대상이 정상 해석·도달되는지 보고(기준선, 아니면 UNVERIFIED), 차단은 그 요청 뒤에
그 정책의 새 행(DNS는 A 레코드 행, 방화벽은 dst_ip가 그 IP인 행)이 있어야 인정한다
(tests.support.expect_dns_block / expect_unreachable). 방화벽 케이스는 IP로 좁힌 정책이 대상으로
삼은 그 IP로 붙인다(pin_ip).
"""
from __future__ import annotations

import re

import pytest

from bat.events.web_log import all_of, matches_policy, matches_target
from bat.fixtures.enums import Condition, Subject
from bat.fixtures.graphql_policies import ApplicationFirewallFactory, DnsFirewallFactory
from bat.fixtures.naming import resource_name
from bat.fixtures.policies import CleanupWarning, WebPolicyFactory
from bat.fixtures.testdata import (
    AAAA_HOSTS,
    BLOCK_TARGET_HOST,
    BLOCK_TARGET_URL,
    ECHO_HOSTS,
    SECOND_HOST,
)
from bat.models import Kind, Step
from bat.events.poller import PollTimeout, poll_until
from bat.traffic.http import curl_status, dns_lookup, resolve_ip
from tests.support import (
    across_targets,
    await_network_row,
    cleanup_failed,
    curl_until_reachable,
    describe,
    dns_baseline,
    dns_lookup_until_allowed,
    dns_lookup_until_blocked,
    environment_error,
    expect_delivered,
    expect_dns_block,
    expect_hold,
    expect_unreachable,
    expect_values,
    hold_after_change,
    ip_of,
    marked_url,
    matches_network_policy,
    network_rows,
    pass_case,
    policy_changed,
    reach_baseline,
    request_until_logged,
    require_baseline,
    unverified,
)

pytestmark = [
    pytest.mark.product("fwaas"),
    pytest.mark.lane("b"),
    pytest.mark.xdist_group("lane-b"),
]

# nslookup 응답에 든 IPv6 주소(콜론이 둘 이상인 16진수 묶음).
_IPV6_RE = re.compile(r"\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}\b", re.IGNORECASE)


def _resolved_before(executor, hosts, timeout_sec: float) -> dict:
    """정책을 만들기 전에 대상마다 해석 결과를 받아 둔다(기준선). 판정은 대상별로 require_baseline이 한다."""
    return {host: dns_lookup_until_allowed(executor, host, timeout_sec) for host in hosts}


@pytest.mark.case("BAT-FW-001")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_dns_firewall_blocks_a_domain(case, run_context, dns_firewall, executor, network_log):
    """DNS Firewall로 도메인을 차단하면 실제로 이름 해석이 실패하고 이벤트가 남는다.

    정책 하나에 대상 도메인 여러 개(ECHO_HOSTS)를 넣는다. 정책 전에 도메인마다 해석되는지 보고,
    정책 뒤에는 도메인마다 해석이 실패하고 그 조회 뒤 이 정책의 새 A 행이 BLOCK으로 남아야 한다
    (DNS 로그에는 도메인 필드가 없어 조회 전후의 행 id로 그 조회의 행을 가린다). 조회는 nslookup이라
    단말 OS의 DNS 캐시와 무관하게 리졸버에 직접 묻는다(예전 BAT-FW-008의 "새 조회는 막힌다"를 포함한다.
    curl은 OS 캐시를 쓰므로 캐시된 이름이 계속 연결되는지는 SSE가 아니라 단말의 동작이라 판정하지 않는다).
    """
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = DnsFirewallFactory.fqdn_rule(list(ECHO_HOSTS))
    budget = run_context.policy_propagation_timeout_sec
    before = _resolved_before(executor, ECHO_HOSTS, budget)

    def check(host: str) -> None:
        require_baseline(case, before[host], what=f"{host} resolves")
        expect_dns_block(
            case, executor, network_log, policy_name, host,
            budget_sec=budget, event_timeout_sec=run_context.event_poll_timeout_sec,
            failure=f"{host} still resolved with the DNS Firewall block policy active",
        )

    try:
        with dns_firewall.temporary(policy_name, [rule], action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)
            across_targets(case, ECHO_HOSTS, check, what="DNS Firewall block")
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-FW-002")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P2")
def test_dns_firewall_removal_restores_resolution(case, run_context, dns_firewall, executor, network_log):
    """DNS Firewall 정책을 지우면 도메인 이름 해석이 다시 정상 동작한다.

    정책 하나에 대상 도메인 여러 개(ECHO_HOSTS)를 넣고 도메인마다 확인한다. 정책이 실제로
    막았다는 것(해석 실패 + 그 정책의 행)을 먼저 보이고, 삭제 뒤에 주소가 담긴 응답을 요구한다.
    """
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = DnsFirewallFactory.fqdn_rule(list(ECHO_HOSTS))
    budget = run_context.policy_propagation_timeout_sec
    before = _resolved_before(executor, ECHO_HOSTS, budget)

    def check_blocked(host: str) -> None:
        require_baseline(case, before[host], what=f"{host} resolves")
        expect_dns_block(
            case, executor, network_log, policy_name, host,
            budget_sec=budget, event_timeout_sec=run_context.event_poll_timeout_sec,
            failure=f"The DNS Firewall policy never took effect on {host}, so removing it would prove nothing",
        )

    def check_restored(host: str) -> None:
        restored = dns_lookup_until_allowed(executor, host, budget)
        expect_delivered(
            case,
            restored,
            expected=f"{host}: name resolution succeeds once the policy is gone",
            failure=f"{host} still fails to resolve after the DNS Firewall policy was deleted",
        )

    with dns_firewall.temporary(policy_name, [rule], action_type="BLOCK") as policy:
        case.policy_ids.append(policy.policy_id)
        across_targets(case, ECHO_HOSTS, check_blocked, what="DNS Firewall block before removal")

    # 이 시점에는 컨텍스트 매니저가 정책을 지웠고, 목록에서 사라진 것까지 확인했다.
    across_targets(case, ECHO_HOSTS, check_restored, what="resolution after removal")
    pass_case(case)


@pytest.mark.case("BAT-FW-003")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_application_firewall_blocks_a_destination(
    case, run_context, application_firewall, executor, network_log
):
    """Application Firewall로 목적지를 차단하면 연결이 실제로 끊기고 이벤트가 남는다.

    정책이 대상으로 삼은 IP로 붙여(pin_ip) 보낸다. 정책 전에 그 IP로 응답을 받고, 정책 뒤에는
    연결이 끊기고 이 정책의 행이 dst_ip가 그 IP인 BLOCK으로 남아야 한다.
    """
    policy_name = resource_name(case.case_id, run_context.run_id)
    budget = run_context.policy_propagation_timeout_sec
    destination_ip = resolve_ip(executor, BLOCK_TARGET_HOST)
    case.record(Step.SETUP, ok=True, kind=Kind.EVIDENCE, detail=f"{BLOCK_TARGET_HOST} resolved to {destination_ip}")
    reach_baseline(case, executor, BLOCK_TARGET_URL, budget, pin_ip=destination_ip)
    # 빈 source는 어떤 트래픽도 매칭하지 않는다(모듈 docstring 참조).
    subject = ApplicationFirewallFactory.subject(
        source_ips=["0.0.0.0/0"], destination_ips=[destination_ip]
    )

    try:
        with application_firewall.temporary(policy_name, subject, action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)
            expect_unreachable(
                case, executor, network_log, policy_name, BLOCK_TARGET_URL, destination_ip,
                budget_sec=budget, event_timeout_sec=run_context.event_poll_timeout_sec,
                failure=f"Request to {BLOCK_TARGET_URL} (destination {destination_ip}) still "
                f"connected with the Application Firewall policy active",
            )
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-FW-004")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P2")
def test_application_firewall_removal_restores_connectivity(
    case, run_context, application_firewall, executor, network_log
):
    """Application Firewall 정책을 지우면 목적지로의 연결이 다시 정상 동작한다.

    차단 단계는 연결 끊김 + 이 정책의 행(dst_ip)으로 인정하고, 삭제 뒤에는 응답이 실제로
    전달(delivered)돼야 한다. 삭제 뒤에도 연결이 끊기면 FAIL, 연결은 되지만 403·5xx처럼 전달이
    아닌 응답이면 판단할 수 없어 UNVERIFIED다.
    """
    policy_name = resource_name(case.case_id, run_context.run_id)
    budget = run_context.policy_propagation_timeout_sec
    destination_ip = resolve_ip(executor, BLOCK_TARGET_HOST)
    reach_baseline(case, executor, BLOCK_TARGET_URL, budget, pin_ip=destination_ip)
    subject = ApplicationFirewallFactory.subject(
        source_ips=["0.0.0.0/0"], destination_ips=[destination_ip]
    )

    with application_firewall.temporary(policy_name, subject, action_type="BLOCK") as policy:
        case.policy_ids.append(policy.policy_id)
        expect_unreachable(
            case, executor, network_log, policy_name, BLOCK_TARGET_URL, destination_ip,
            budget_sec=budget, event_timeout_sec=run_context.event_poll_timeout_sec,
            failure="The Application Firewall policy never took effect, so removing it would prove nothing",
        )

    # 이 시점에는 컨텍스트 매니저가 정책을 지웠고, 목록에서 사라진 것까지 확인했다.
    restored = curl_until_reachable(executor, BLOCK_TARGET_URL, budget, pin_ip=destination_ip)
    expected = "the response goes through once the policy is gone"
    if not restored.status_code:
        case.record(
            Step.USER_RESULT, ok=False, kind=Kind.ASSERTION, detail=restored.detail,
            expected=expected, actual=describe(restored),
        )
        raise AssertionError(
            f"{BLOCK_TARGET_URL} ({destination_ip}) is still unreachable after the Application "
            f"Firewall policy was deleted"
        )
    if not expect_delivered(
        case, restored, expected=expected,
        failure=f"{BLOCK_TARGET_URL} is still blocked after the Application Firewall policy was deleted",
    ):
        unverified(case, Step.USER_RESULT, f"after the deletion {BLOCK_TARGET_URL} answered {describe(restored)}, which is not a delivered response")
    pass_case(case)


def _ping_answers(executor, ip: str) -> tuple[bool, str]:
    """ICMP echo가 응답을 받는가. Windows ping의 응답 줄에는 TTL=이 있다."""
    result = executor.run(f"ping -n 2 -w 2000 {ip}", timeout_sec=20)
    output = " ".join(f"{result.stdout} {result.stderr}".split())
    return "ttl=" in output.lower(), output[-200:]


@pytest.mark.case("BAT-FW-005")
@pytest.mark.known_issue(
    "protocol 조건이 적용되지 않아 다른 프로토콜까지 끊김",
    match=r"A policy scoped to protocol 1 \(ICMP\) also cut off HTTP",
)
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P2")
def test_protocol_scope_limits_what_is_blocked(
    case, run_context, application_firewall, executor, network_log
):
    """프로토콜을 지정한 Application Firewall 정책은 그 프로토콜만 막는다.

    ICMP(1)로 좁힌 BLOCK 정책을 걸고, 그 IP로 붙인 HTTP(TCP) 요청이 전파 예산 내내와 그 뒤에도
    전달되는지 본다. 그다음 정책이 실제로 적용돼 있다는 양성 확인으로, 같은 IP로의 ping이 막히고
    이 정책의 행(dst_ip)이 남아야 한다. 정책 전에 ping이 응답하지 않던 IP면 양성 확인을 할 수 없어
    UNVERIFIED, 정책 뒤에도 ping이 응답하면 ICMP가 SSE를 지나는지 알 수 없어 UNVERIFIED다.
    알려진 결함: `protocol` 값과 무관하게 목적지로 가는 모든 트래픽이 막힌다.
    """
    policy_name = resource_name(case.case_id, run_context.run_id)
    budget = run_context.policy_propagation_timeout_sec
    destination_ip = resolve_ip(executor, BLOCK_TARGET_HOST)
    reach_baseline(case, executor, BLOCK_TARGET_URL, budget, pin_ip=destination_ip)
    ping_before, ping_output = _ping_answers(executor, destination_ip)
    case.record(Step.SETUP, ok=True, kind=Kind.EVIDENCE, detail=f"baseline ping {destination_ip}: {ping_output}")
    subject = ApplicationFirewallFactory.subject(
        source_ips=["0.0.0.0/0"],
        destination_ips=[destination_ip],
        protocol=1,  # ICMP: HTTP 요청은 쓰지 않는다
    )

    try:
        with application_firewall.temporary(policy_name, subject, action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)
            change = policy_changed(case, f"BLOCK scoped to protocol 1 (ICMP) toward {destination_ip}")

            hold = hold_after_change(
                lambda: curl_status(executor, BLOCK_TARGET_URL, pin_ip=destination_ip),
                want=lambda t: t.delivered, against=lambda t: not t.status_code,
                changed_at=change.at, budget_sec=budget, steady=True,
            )
            expect_hold(
                case, hold,
                expected="HTTP still goes through: the policy only covers ICMP",
                failure=f"A policy scoped to protocol 1 (ICMP) also cut off HTTP to "
                f"{destination_ip}, so the protocol condition is not being applied",
            )

            if not ping_before:
                unverified(
                    case, Step.EVENT,
                    f"{destination_ip} gave no ICMP reply even before the policy ({ping_output}), so "
                    f"whether the ICMP-scoped policy is in effect cannot be shown; HTTP staying up proves "
                    f"nothing on its own",
                )
            seen = {e.event_id for e in network_rows(network_log, "firewall", policy_name)}
            try:
                ping_after = poll_until(
                    lambda: (lambda r: r if not r[0] else None)(_ping_answers(executor, destination_ip)),
                    timeout_sec=budget, description=f"ICMP to {destination_ip} to stop",
                )
            except PollTimeout:
                unverified(
                    case, Step.EVENT,
                    f"ping to {destination_ip} still answers with the ICMP BLOCK policy in place, so it is "
                    f"not known whether ICMP passes through SSE at all; HTTP staying up proves nothing on its own",
                )
            case.record(
                Step.SETUP, ok=True, kind=Kind.EVIDENCE,
                detail=f"ping {destination_ip} with the policy: {ping_after[1]}",
            )
            await_network_row(
                case, network_log, policy_name, kind="firewall", after=seen,
                where={"dst_ip": lambda value: ip_of(value) == destination_ip},
                timeout_sec=run_context.event_poll_timeout_sec,
                what=f"the ICMP echo to {destination_ip} (proof the ICMP-scoped policy is in effect)",
            )
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-FW-006")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P2")
def test_dns_firewall_multi_domain_rule_is_domain_specific(
    case, run_context, dns_firewall, executor, network_log
):
    """DNS Firewall 한 rule에 도메인 여러 개를 넣으면 그 도메인들만 막히고 나머지는 통과한다."""
    third_host = "www.iana.org"
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = DnsFirewallFactory.fqdn_rule([BLOCK_TARGET_HOST, SECOND_HOST])
    budget = run_context.policy_propagation_timeout_sec
    for host in (BLOCK_TARGET_HOST, SECOND_HOST, third_host):
        dns_baseline(case, executor, host, budget)

    try:
        with dns_firewall.temporary(policy_name, [rule], action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)
            case.record(
                Step.SETUP, ok=True, kind=Kind.EVIDENCE,
                detail=f"BLOCK scoped to [{BLOCK_TARGET_HOST}, {SECOND_HOST}]",
            )

            for host in (BLOCK_TARGET_HOST, SECOND_HOST):
                expect_dns_block(
                    case, executor, network_log, policy_name, host,
                    budget_sec=budget, event_timeout_sec=run_context.event_poll_timeout_sec,
                    failure=f"{host} still resolved",
                )

            third = dns_lookup(executor, third_host, timeout_sec=10)
            expect_delivered(
                case,
                third,
                expected=f"{third_host} (not in the rule's domain list) still resolves",
                failure=f"A rule listing only [{BLOCK_TARGET_HOST}, {SECOND_HOST}] also blocked "
                f"{third_host} — a multi-domain DNS Firewall rule is not domain-specific",
            )
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-FW-007")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P3")
def test_dns_firewall_apex_block_does_not_reach_subdomains(case, run_context, dns_firewall, executor, network_log):
    """DNS Firewall로 상위(apex) 도메인을 막아도 하위(서브) 도메인은 별도 취급된다.

    FQDN 매칭은 정확히 일치하는 이름만 본다. 서브도메인은 따로 넣거나 와일드카드를 쓴다.
    """
    apex = "iana.org"
    subdomain = "www.iana.org"
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = DnsFirewallFactory.fqdn_rule([apex])
    budget = run_context.policy_propagation_timeout_sec
    dns_baseline(case, executor, apex, budget)
    dns_baseline(case, executor, subdomain, budget)

    try:
        with dns_firewall.temporary(policy_name, [rule], action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)
            case.record(Step.SETUP, ok=True, kind=Kind.EVIDENCE, detail=f"BLOCK scoped to apex domain {apex!r} only")

            expect_dns_block(
                case, executor, network_log, policy_name, apex,
                budget_sec=budget, event_timeout_sec=run_context.event_poll_timeout_sec,
                failure=f"{apex} still resolved",
            )

            sub_result = dns_lookup(executor, subdomain, timeout_sec=10)
            expect_delivered(
                case,
                sub_result,
                expected=f"{subdomain} is unaffected by an apex-only rule",
                failure=f"Blocking the apex domain {apex!r} also blocked its subdomain "
                f"{subdomain!r} — FQDN matching became hierarchical (it used to be exact)",
            )
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-FW-009")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P2")
def test_dns_firewall_fqdn_match_is_case_insensitive(case, run_context, dns_firewall, executor, network_log):
    """DNS Firewall의 FQDN 조건은 대소문자와 무관하게 매칭된다.

    BAT-SWG-023(HTTP_HOST 대소문자)과 같은 점검을 DNS 계층에 한다. 정책 하나에 대상 도메인
    여러 개(ECHO_HOSTS)를 소문자로 넣고 도메인마다 대문자로 조회해, 해석이 실패하고 그 조회 뒤
    이 정책의 새 A 행이 남는지 본다.
    """
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = DnsFirewallFactory.fqdn_rule([host.lower() for host in ECHO_HOSTS])
    budget = run_context.policy_propagation_timeout_sec
    before = {host: dns_lookup_until_allowed(executor, host.upper(), budget) for host in ECHO_HOSTS}

    def check(host: str) -> None:
        uppercase_host = host.upper()
        require_baseline(case, before[host], what=f"{uppercase_host} resolves")
        expect_dns_block(
            case, executor, network_log, policy_name, uppercase_host,
            budget_sec=budget, event_timeout_sec=run_context.event_poll_timeout_sec,
            failure=f"A DNS Firewall rule blocking {host.lower()!r} did not block the uppercase "
            f"spelling {uppercase_host!r} — FQDN matching is case-sensitive",
            expected=f"{uppercase_host} fails to resolve despite the uppercase spelling",
        )

    try:
        with dns_firewall.temporary(policy_name, [rule], action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)
            case.record(
                Step.SETUP, ok=True, kind=Kind.EVIDENCE,
                detail=f"BLOCK scoped to {[h.lower() for h in ECHO_HOSTS]} (lowercase)",
            )

            across_targets(case, ECHO_HOSTS, check, what="case-insensitive FQDN block")
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-FW-010")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P2")
def test_dns_firewall_applies_only_to_its_users(case, run_context, dns_firewall, executor, network_log):
    """DNS Firewall 정책에 지정한 사용자에게만 적용되고, 다른 사용자에게는 적용되지 않는다.

    다른 사용자 id로 좁히면 전파 예산 내내와 그 뒤에도 안 막히고, 커넥터 사용자 id로 좁히면
    막히고 그 정책의 행이 남아야 한다.
    """
    probe_name = resource_name(case.case_id, run_context.run_id, "probe")
    rule = DnsFirewallFactory.fqdn_rule([BLOCK_TARGET_HOST])
    budget = run_context.policy_propagation_timeout_sec
    dns_baseline(case, executor, BLOCK_TARGET_HOST, budget)

    with dns_firewall.temporary(probe_name, [rule], action_type="LOGGING"):
        dns_lookup(executor, BLOCK_TARGET_HOST, timeout_sec=15)
        try:
            event = network_log.wait_for_dns_event(
                matches_network_policy(probe_name),
                timeout_sec=run_context.event_poll_timeout_sec,
                description="probe event naming the connector user",
            )
        except PollTimeout as timeout:
            environment_error(f"Could not determine the connector user: {timeout}")

    connector_user_id = event.get("user_id")
    if connector_user_id in (None, ""):
        environment_error("The dns security event carries no user_id, so user scoping cannot be verified")
    connector_user_id = int(connector_user_id)
    case.record(
        Step.SETUP, ok=True, kind=Kind.EVIDENCE,
        detail=f"connector user id={connector_user_id} (from dns security log)",
    )

    try:
        # 작은 id를 쓴다. 큰 값(예 12345)은 생성 mutation이 서버에서 "Allocation failed"로
        # 실패한다. 1/2 중 커넥터 자신이 아닌 쪽을 고른다.
        other_user_id = 2 if connector_user_id != 2 else 1
        other_name = resource_name(case.case_id, run_context.run_id, "other")
        with dns_firewall.temporary(
            other_name, [rule], action_type="BLOCK", users=[other_user_id], user_groups=[]
        ) as other_policy:
            case.policy_ids.append(other_policy.policy_id)
            change = policy_changed(case, f"DNS BLOCK scoped to user {other_user_id}")

            # 한 번 조회해서는 정책이 아직 안 퍼졌을 뿐인지 알 수 없다. 전파 예산 내내,
            # 그리고 그 뒤에도 연속해서 풀려야 한다.
            hold = hold_after_change(
                lambda: dns_lookup(executor, BLOCK_TARGET_HOST, timeout_sec=15),
                want=lambda t: t.delivered, against=lambda t: t.blocked,
                changed_at=change.at, budget_sec=budget,
                steady=True,
            )
            expect_hold(
                case, hold,
                expected="not blocked for a different user, through and after the propagation budget",
                failure="A DNS Firewall policy scoped to a user id that cannot be the "
                "connector still blocked resolution — the users scope is not being applied",
            )

        mine_name = resource_name(case.case_id, run_context.run_id, "mine")
        with dns_firewall.temporary(
            mine_name, [rule], action_type="BLOCK", users=[connector_user_id], user_groups=[]
        ) as my_policy:
            case.policy_ids.append(my_policy.policy_id)
            expect_dns_block(
                case, executor, network_log, mine_name, BLOCK_TARGET_HOST,
                budget_sec=budget, event_timeout_sec=run_context.event_poll_timeout_sec,
                failure=f"A DNS Firewall policy scoped to the connector's own user id "
                f"({connector_user_id}) did not block its own resolution",
                expected="blocked once scoped to the real connector user",
            )
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-FW-011")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P3")
def test_dns_firewall_blocks_aaaa_queries_too(case, run_context, dns_firewall, executor, network_log):
    """DNS Firewall 차단은 A 레코드뿐 아니라 AAAA(IPv6) 조회도 막는다.

    대상은 AAAA 레코드가 실제로 있는 도메인들(AAAA_HOSTS)이다. 정책을 만들기 전에 대상마다
    AAAA 조회가 IPv6 주소를 돌려주는지 확인한다(기준선). 기준선에서 주소가 없던 대상은
    차단으로 셀 수 없으므로 UNVERIFIED다. 기준선이 있는 대상은 정책 뒤 실패 문구가 있거나
    IPv6 주소가 없어지면 사용자 결과로 차단이고, 그 조회 뒤 이 정책의 새 행이
    record_type "AAAA", action BLOCK으로 남아야 한다(DNS 로그에는 도메인 필드가 없어서
    조회 전후의 행 id로 그 조회의 행을 가린다).
    """
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = DnsFirewallFactory.fqdn_rule(list(AAAA_HOSTS))

    def aaaa_lookup(host: str) -> tuple[bool, bool, str]:
        """(실패 문구, IPv6 주소 있음, 출력 요약)."""
        result = executor.run(f"nslookup -type=AAAA {host}", timeout_sec=15)
        output = f"{result.stdout}\n{result.stderr}"
        failed = any(
            marker in output.lower()
            for marker in ("non-existent domain", "can't find", "server failed", "no answer")
        )
        # 서버 주소(맨 위)는 빼고, 응답 부분(Name: 아래)에 IPv6 주소가 있는지 본다.
        answer = output.split("Name:", 1)[1] if "Name:" in output else ""
        return failed, bool(_IPV6_RE.search(answer)), " ".join(output.split())[-300:]

    baseline = {host: aaaa_lookup(host) for host in AAAA_HOSTS}
    for host, (failed, has_ipv6, output) in baseline.items():
        case.record(
            Step.SETUP, ok=has_ipv6 and not failed, kind=Kind.EVIDENCE,
            detail=f"baseline AAAA {host}: {'IPv6 answer' if has_ipv6 and not failed else 'no IPv6 answer'}: {output}",
        )

    def check(host: str) -> None:
        failed, has_ipv6, output = baseline[host]
        if failed or not has_ipv6:
            unverified(
                case, Step.USER_RESULT,
                f"{host} gave no IPv6 answer even before the policy, so a missing answer "
                f"afterwards proves nothing: {output}",
            )
        a_blocked = dns_lookup_until_blocked(
            executor, host, run_context.policy_propagation_timeout_sec
        )
        assert a_blocked.blocked, f"A-record lookup for {host} never blocked: {a_blocked.detail}"

        seen = {e.event_id for e in network_rows(network_log, "dns", policy_name)}
        failed, has_ipv6, output = aaaa_lookup(host)
        aaaa_blocked = failed or not has_ipv6
        case.record(
            Step.USER_RESULT,
            ok=aaaa_blocked,
            detail=f"AAAA lookup for {host} {'blocked' if aaaa_blocked else 'resolved'}: {output}",
            expected="AAAA query also fails",
            actual="blocked" if aaaa_blocked else "resolved",
        )
        assert aaaa_blocked, (
            f"A DNS Firewall rule blocking {host} stopped the A-record "
            f"query but let an AAAA (IPv6) query for the same name through: {output}"
        )
        await_network_row(
            case, network_log, policy_name, kind="dns", after=seen,
            where={"record_type": lambda value: str(value or "").upper() == "AAAA"},
            timeout_sec=run_context.event_poll_timeout_sec, what=f"the AAAA lookup for {host}",
        )

    try:
        with dns_firewall.temporary(policy_name, [rule], action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)
            across_targets(case, AAAA_HOSTS, check, what="AAAA block")
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-FW-012")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P3")
def test_dns_firewall_wildcard_value_covers_subdomains(case, run_context, dns_firewall, executor, network_log):
    """`*.domain`처럼 와일드카드로 값을 넣으면 서브도메인 전체를 막을 수 있다.

    `*.iana.org`는 서브도메인(www.iana.org)만 막고 apex(iana.org)는 막지 않는다.
    """
    apex = "iana.org"
    subdomain = "www.iana.org"
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = DnsFirewallFactory.fqdn_rule([f"*.{apex}"])
    budget = run_context.policy_propagation_timeout_sec
    dns_baseline(case, executor, subdomain, budget)
    dns_baseline(case, executor, apex, budget)

    try:
        with dns_firewall.temporary(policy_name, [rule], action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)
            case.record(Step.SETUP, ok=True, kind=Kind.EVIDENCE, detail=f"BLOCK scoped to wildcard value '*.{apex}'")

            expect_dns_block(
                case, executor, network_log, policy_name, subdomain,
                budget_sec=budget, event_timeout_sec=run_context.event_poll_timeout_sec,
                failure=f"A rule on '*.{apex}' did not block the subdomain {subdomain}",
                expected=f"{subdomain} fails to resolve under the wildcard rule",
            )

            apex_result = dns_lookup(executor, apex, timeout_sec=10)
            expect_delivered(
                case,
                apex_result,
                expected=f"{apex} itself is unaffected by a subdomain-only wildcard",
                failure=f"A wildcard rule on '*.{apex}' also blocked the apex domain {apex} itself",
            )
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-FW-013")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P2")
def test_dns_firewall_event_carries_enough_to_investigate(
    case, run_context, dns_firewall, web_policies, executor, network_log, web_log
):
    """DNS 보안로그 이벤트에 사용자·출발지 IP·국가 등 조사에 필요한 정보가 담겨 있다.

    값이 맞는지는 같은 단말의 웹 보안로그 행과 비교한다. 정책 전에 LOGGING 웹 정책으로 이 단말이
    보낸 마커 요청의 행을 받아 두고, DNS 차단 행의 user_id/user_name/src_ip/src_country_code가
    그 행과 같아야 한다(src_ip는 포트를 뺀 주소). 콘솔의 DNS 보안 로그에는 단말(device_id)
    항목이 없으므로 확인하지 않는다.
    """
    policy_name = resource_name(case.case_id, run_context.run_id)
    reference_name = resource_name(case.case_id, run_context.run_id, "ref")
    rule = DnsFirewallFactory.fqdn_rule([BLOCK_TARGET_HOST])
    budget = run_context.policy_propagation_timeout_sec
    dns_baseline(case, executor, BLOCK_TARGET_HOST, budget)

    try:
        reference_rule = WebPolicyFactory.build_rule(Subject.HTTP_HOST, Condition.IS, [BLOCK_TARGET_HOST])
        with web_policies.temporary(reference_name, [reference_rule], action_type="LOGGING") as reference:
            case.policy_ids.append(reference.policy_id)
            logged = request_until_logged(
                web_log,
                lambda url: curl_status(executor, url),
                match=matches_policy(reference_name, reference.policy_id),
                url_for=lambda n: marked_url(BLOCK_TARGET_URL, case, run_context, f"ref{n}"),
                budget_sec=budget,
                event_timeout_sec=run_context.event_poll_timeout_sec,
            )
            if not logged:
                unverified(
                    case, Step.EVENT,
                    f"no marked request from this endpoint reached the web log under {reference_name}, so "
                    f"there is no reference identity to compare the DNS row with",
                )
            web_row = web_log.wait_for_security_event(
                all_of(matches_policy(reference_name, reference.policy_id), matches_target(logged[0])),
                timeout_sec=run_context.event_poll_timeout_sec,
            )
        case.record(
            Step.SETUP, ok=True, kind=Kind.EVIDENCE,
            detail=f"reference web row id={web_row.event_id} for {logged[0]}",
        )

        with dns_firewall.temporary(policy_name, [rule], action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)
            row = expect_dns_block(
                case, executor, network_log, policy_name, BLOCK_TARGET_HOST,
                budget_sec=budget, event_timeout_sec=run_context.event_poll_timeout_sec,
                failure="Lookup never blocked",
            )
            reference_values = {
                "user_id": web_row.raw.get("user_id"),
                "user_name": web_row.raw.get("user_name"),
                "src_ip": ip_of(web_row.raw.get("src_ip")),
                "src_country_code": web_row.raw.get("src_country_code"),
            }
            unknown = [field for field, value in reference_values.items() if value in (None, "")]
            if unknown:
                unverified(case, Step.EVENT, f"the reference web row {web_row.event_id} has no {unknown}")
            # 비어 있는 필드는 조사에 쓸 수 없으니 읽지 못한 것이 아니라 틀린 값("")으로 센다.
            dns_values = {
                "user_id": row.raw.get("user_id") or "",
                "user_name": row.raw.get("user_name") or "",
                "src_ip": ip_of(row.raw.get("src_ip")),
                "src_country_code": row.raw.get("src_country_code") or "",
            }
            expect_values(
                case, f"dns_security_log id={row.event_id} identity vs this endpoint's web row {web_row.event_id}",
                {field: (reference_values[field], dns_values[field]) for field in reference_values},
                step=Step.EVENT,
            )
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)
