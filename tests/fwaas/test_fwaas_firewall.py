"""DNS Firewall과 Application Firewall 케이스.

둘 다 콘솔 GraphQL API(SIA.network)에만 있다.

DNS Firewall: 확인된 rule subject는 "FQDN" 하나뿐이다.

Application Firewall: 빈 `source: {}`는 아무것도 매칭하지 않으므로 정책에
`source_ips=["0.0.0.0/0"]`을 명시한다. 차단은 403 차단 페이지가 아니라 네트워크
계층에서 연결을 끊는다(curl status_code 0).

이벤트는 웹 보안 로그가 아니라 GraphQL SIA.log.dns_security_log / firewall_security_log에
있다(bat/events/network_log.py 참조).
"""
from __future__ import annotations

import pytest

from bat.fixtures.graphql_policies import ApplicationFirewallFactory, DnsFirewallFactory
from bat.fixtures.naming import resource_name
from bat.fixtures.policies import CleanupWarning
from bat.fixtures.testdata import BLOCK_TARGET_HOST, BLOCK_TARGET_URL, SECOND_HOST
from bat.models import Kind, Step
from bat.events.poller import PollTimeout
from bat.traffic.http import curl_status, dns_lookup, resolve_ip
from tests.support import (
    await_network_event,
    cleanup_failed,
    curl_until_reachable,
    curl_until_unreachable,
    dns_lookup_until_allowed,
    dns_lookup_until_blocked,
    expect_delivered,
    matches_network_policy,
    pass_case,
)

pytestmark = [
    pytest.mark.product("fwaas"),
    pytest.mark.lane("b"),
    pytest.mark.xdist_group("lane-b"),
]


@pytest.mark.case("BAT-FW-001")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_dns_firewall_blocks_a_domain(case, run_context, dns_firewall, executor, network_log):
    """DNS Firewall로 도메인을 차단하면 실제로 이름 해석이 실패하고 이벤트가 남는다."""
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = DnsFirewallFactory.fqdn_rule([BLOCK_TARGET_HOST])

    try:
        with dns_firewall.temporary(policy_name, [rule], action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)

            traffic = dns_lookup_until_blocked(
                executor, BLOCK_TARGET_HOST, run_context.policy_propagation_timeout_sec
            )
            case.record(
                Step.USER_RESULT,
                ok=traffic.blocked,
                detail=traffic.detail,
                expected="name resolution fails",
                actual="resolution failed" if traffic.blocked else "resolution succeeded",
            )
            assert traffic.blocked, (
                f"{BLOCK_TARGET_HOST} still resolved with the DNS Firewall block "
                f"policy active: {traffic.detail}"
            )

            await_network_event(
                case,
                network_log,
                policy_name,
                kind="dns",
                timeout_sec=run_context.event_poll_timeout_sec,
            )
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-FW-002")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P2")
def test_dns_firewall_removal_restores_resolution(case, run_context, dns_firewall, executor):
    """DNS Firewall 정책을 지우면 도메인 이름 해석이 다시 정상 동작한다."""
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = DnsFirewallFactory.fqdn_rule([BLOCK_TARGET_HOST])

    with dns_firewall.temporary(policy_name, [rule], action_type="BLOCK") as policy:
        case.policy_ids.append(policy.policy_id)
        blocked = dns_lookup_until_blocked(
            executor, BLOCK_TARGET_HOST, run_context.policy_propagation_timeout_sec
        )
        assert blocked.blocked, (
            "The DNS Firewall policy never took effect, so removing it would prove nothing"
        )

    # 이 시점에는 컨텍스트 매니저가 정책을 이미 지웠다.
    restored = dns_lookup_until_allowed(
        executor, BLOCK_TARGET_HOST, run_context.policy_propagation_timeout_sec
    )
    expect_delivered(
        case,
        restored,
        expected="name resolution succeeds once the policy is gone",
        failure=f"{BLOCK_TARGET_HOST} still fails to resolve after the DNS Firewall "
        f"policy was deleted",
    )
    pass_case(case)


@pytest.mark.case("BAT-FW-003")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_application_firewall_blocks_a_destination(
    case, run_context, application_firewall, executor, network_log
):
    """Application Firewall로 목적지를 차단하면 연결이 실제로 끊기고 이벤트가 남는다."""
    policy_name = resource_name(case.case_id, run_context.run_id)
    destination_ip = resolve_ip(executor, BLOCK_TARGET_HOST)
    case.record(
        Step.SETUP, ok=True, detail=f"{BLOCK_TARGET_HOST} resolved to {destination_ip}"
    )
    # 빈 source는 어떤 트래픽도 매칭하지 않는다(모듈 docstring 참조).
    subject = ApplicationFirewallFactory.subject(
        source_ips=["0.0.0.0/0"], destination_ips=[destination_ip]
    )

    try:
        with application_firewall.temporary(policy_name, subject, action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)

            traffic = curl_until_unreachable(
                executor, BLOCK_TARGET_URL, run_context.policy_propagation_timeout_sec
            )
            case.record(
                Step.USER_RESULT,
                ok=not traffic.status_code,
                detail=traffic.detail,
                expected="connection refused",
                actual="connection refused" if not traffic.status_code else f"HTTP {traffic.status_code}",
            )
            assert not traffic.status_code, (
                f"Request to {BLOCK_TARGET_URL} (destination {destination_ip}) still "
                f"connected (HTTP {traffic.status_code}) with the Application Firewall "
                f"policy active"
            )

            await_network_event(
                case,
                network_log,
                policy_name,
                kind="firewall",
                timeout_sec=run_context.event_poll_timeout_sec,
            )
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-FW-004")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P2")
def test_application_firewall_removal_restores_connectivity(
    case, run_context, application_firewall, executor
):
    """Application Firewall 정책을 지우면 목적지로의 연결이 다시 정상 동작한다."""
    policy_name = resource_name(case.case_id, run_context.run_id)
    destination_ip = resolve_ip(executor, BLOCK_TARGET_HOST)
    subject = ApplicationFirewallFactory.subject(
        source_ips=["0.0.0.0/0"], destination_ips=[destination_ip]
    )

    with application_firewall.temporary(policy_name, subject, action_type="BLOCK") as policy:
        case.policy_ids.append(policy.policy_id)
        blocked = curl_until_unreachable(
            executor, BLOCK_TARGET_URL, run_context.policy_propagation_timeout_sec
        )
        assert not blocked.status_code, (
            "The Application Firewall policy never took effect, so removing it "
            "would prove nothing"
        )

    # 이 시점에는 컨텍스트 매니저가 정책을 이미 지웠다.
    restored = curl_until_reachable(
        executor, BLOCK_TARGET_URL, run_context.policy_propagation_timeout_sec
    )
    case.record(
        Step.USER_RESULT,
        ok=bool(restored.status_code),
        detail=restored.detail,
        expected="connection succeeds once the policy is gone",
        actual=f"HTTP {restored.status_code}" if restored.status_code else "connection refused",
    )
    assert restored.status_code, (
        f"{BLOCK_TARGET_URL} is still unreachable after the Application Firewall "
        f"policy was deleted"
    )
    pass_case(case)


@pytest.mark.case("BAT-FW-005")
@pytest.mark.known_issue("protocol 조건이 적용되지 않아 다른 프로토콜까지 끊김")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P2")
def test_protocol_scope_limits_what_is_blocked(
    case, run_context, application_firewall, executor
):
    """프로토콜을 지정한 Application Firewall 정책은 그 프로토콜만 막는다.

    ICMP(1)로 좁힌 BLOCK 정책을 걸고 HTTP(TCP) 요청이 막히지 않는지 본다.
    알려진 결함: `protocol` 값과 무관하게 목적지로 가는 모든 트래픽이 막힌다.
    """
    policy_name = resource_name(case.case_id, run_context.run_id)
    destination_ip = resolve_ip(executor, BLOCK_TARGET_HOST)
    subject = ApplicationFirewallFactory.subject(
        source_ips=["0.0.0.0/0"],
        destination_ips=[destination_ip],
        protocol=1,  # ICMP: 이 케이스가 보내는 트래픽은 하나도 쓰지 않는다
    )

    try:
        with application_firewall.temporary(policy_name, subject, action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)
            case.record(
                Step.SETUP,
                ok=True,
                detail=f"BLOCK scoped to protocol 1 (ICMP) toward {destination_ip}",
            )

            traffic = curl_until_unreachable(
                executor, BLOCK_TARGET_URL, run_context.policy_propagation_timeout_sec
            )
            case.record(
                Step.USER_RESULT,
                ok=bool(traffic.status_code),
                detail=traffic.detail,
                expected="HTTP still works: the policy only covers ICMP",
                actual=f"HTTP {traffic.status_code}" if traffic.status_code else "connection refused",
            )
            assert traffic.status_code, (
                f"A policy scoped to protocol 1 (ICMP) also cut off HTTP to "
                f"{destination_ip}, so the protocol condition is not being applied"
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

    try:
        with dns_firewall.temporary(policy_name, [rule], action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)
            case.record(
                Step.SETUP, ok=True, detail=f"BLOCK scoped to [{BLOCK_TARGET_HOST}, {SECOND_HOST}]"
            )

            first = dns_lookup_until_blocked(
                executor, BLOCK_TARGET_HOST, run_context.policy_propagation_timeout_sec
            )
            case.record(
                Step.USER_RESULT, ok=first.blocked, detail=first.detail,
                expected=f"{BLOCK_TARGET_HOST} fails to resolve", actual=first.detail,
            )
            assert first.blocked, f"{BLOCK_TARGET_HOST} still resolved: {first.detail}"

            second = dns_lookup_until_blocked(executor, SECOND_HOST, 8)
            case.record(
                Step.USER_RESULT, ok=second.blocked, detail=second.detail,
                expected=f"{SECOND_HOST} fails to resolve", actual=second.detail,
            )
            assert second.blocked, f"{SECOND_HOST} still resolved: {second.detail}"

            third = dns_lookup(executor, third_host, timeout_sec=10)
            expect_delivered(
                case,
                third,
                expected=f"{third_host} (not in the rule's domain list) still resolves",
                failure=f"A rule listing only [{BLOCK_TARGET_HOST}, {SECOND_HOST}] also blocked "
                f"{third_host} — a multi-domain DNS Firewall rule is not domain-specific",
            )

            await_network_event(
                case, network_log, policy_name, kind="dns",
                timeout_sec=run_context.event_poll_timeout_sec,
            )
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-FW-007")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P3")
def test_dns_firewall_apex_block_does_not_reach_subdomains(case, run_context, dns_firewall, executor):
    """DNS Firewall로 상위(apex) 도메인을 막아도 하위(서브) 도메인은 별도 취급된다.

    FQDN 매칭은 정확히 일치하는 이름만 본다. 서브도메인은 따로 넣거나 와일드카드를 쓴다.
    """
    apex = "iana.org"
    subdomain = "www.iana.org"
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = DnsFirewallFactory.fqdn_rule([apex])

    try:
        with dns_firewall.temporary(policy_name, [rule], action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)
            case.record(Step.SETUP, ok=True, detail=f"BLOCK scoped to apex domain {apex!r} only")

            blocked_apex = dns_lookup_until_blocked(
                executor, apex, run_context.policy_propagation_timeout_sec
            )
            case.record(
                Step.USER_RESULT, ok=blocked_apex.blocked, detail=blocked_apex.detail,
                expected=f"{apex} fails to resolve", actual=blocked_apex.detail,
            )
            assert blocked_apex.blocked, f"{apex} still resolved: {blocked_apex.detail}"

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


@pytest.mark.case("BAT-FW-008")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P3")
def test_dns_firewall_block_does_not_evict_an_already_cached_name(
    case, run_context, dns_firewall, executor
):
    """DNS Firewall을 켜도 OS가 이미 캐싱해둔 이름은 즉시 끊기지 않고, 새 조회만 확실히 막힌다.

    curl은 OS DNS 캐시를 쓰므로 캐시된 이름은 계속 연결될 수 있다. 캐시 결과는 근거로만
    남기고, 새 조회(nslookup) 차단만 판정한다.
    """
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = DnsFirewallFactory.fqdn_rule([BLOCK_TARGET_HOST])

    warmed = curl_status(executor, BLOCK_TARGET_URL, timeout_sec=15)
    case.record(
        Step.SETUP,
        ok=bool(warmed.status_code),
        detail=f"pre-warm curl -> HTTP {warmed.status_code} (seeds the OS DNS cache)",
        expected="reachable before any policy exists",
        actual=f"HTTP {warmed.status_code}",
    )

    try:
        with dns_firewall.temporary(policy_name, [rule], action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)

            cached = curl_status(executor, BLOCK_TARGET_URL, timeout_sec=15)
            case.record(
                Step.USER_RESULT,
                ok=True,
                detail=f"curl right after the block -> HTTP {cached.status_code} "
                f"(informational only — depends on this run's cache TTL, not asserted)",
                expected="recorded as-is, not assumed",
                actual=f"HTTP {cached.status_code}" if cached.status_code else "connection refused",
                kind=Kind.EVIDENCE,
            )

            fresh = dns_lookup_until_blocked(
                executor, BLOCK_TARGET_HOST, run_context.policy_propagation_timeout_sec
            )
            case.record(
                Step.USER_RESULT, ok=fresh.blocked, detail=fresh.detail,
                expected=f"a fresh lookup for {BLOCK_TARGET_HOST} fails regardless of cache",
                actual=fresh.detail,
            )
            assert fresh.blocked, (
                f"A fresh nslookup for {BLOCK_TARGET_HOST} still resolved with the DNS "
                f"Firewall block active: {fresh.detail}"
            )
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-FW-009")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P2")
def test_dns_firewall_fqdn_match_is_case_insensitive(case, run_context, dns_firewall, executor):
    """DNS Firewall의 FQDN 조건은 대소문자와 무관하게 매칭된다.

    BAT-SWG-023(HTTP_HOST 대소문자)과 같은 점검을 DNS 계층에 한다.
    """
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = DnsFirewallFactory.fqdn_rule([BLOCK_TARGET_HOST.lower()])
    uppercase_host = BLOCK_TARGET_HOST.upper()

    try:
        with dns_firewall.temporary(policy_name, [rule], action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)
            case.record(
                Step.SETUP, ok=True, detail=f"BLOCK scoped to {BLOCK_TARGET_HOST.lower()!r} (lowercase)"
            )

            traffic = dns_lookup_until_blocked(
                executor, uppercase_host, run_context.policy_propagation_timeout_sec
            )
            case.record(
                Step.USER_RESULT,
                ok=traffic.blocked,
                detail=traffic.detail,
                expected=f"{uppercase_host} fails to resolve despite the uppercase spelling",
                actual="resolution failed" if traffic.blocked else "resolution succeeded",
            )
            assert traffic.blocked, (
                f"A DNS Firewall rule blocking {BLOCK_TARGET_HOST.lower()!r} did not block "
                f"the uppercase spelling {uppercase_host!r} — FQDN matching is case-sensitive"
            )
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-FW-010")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P2")
def test_dns_firewall_applies_only_to_its_users(case, run_context, dns_firewall, executor, network_log):
    """DNS Firewall 정책에 지정한 사용자에게만 적용되고, 다른 사용자에게는 적용되지 않는다.

    다른 사용자 id로 좁히면 안 막히고, 커넥터 사용자 id로 좁히면 막혀야 한다.
    """
    probe_name = resource_name(case.case_id, run_context.run_id, "probe")
    rule = DnsFirewallFactory.fqdn_rule([BLOCK_TARGET_HOST])

    with dns_firewall.temporary(probe_name, [rule], action_type="LOGGING"):
        dns_lookup(executor, BLOCK_TARGET_HOST, timeout_sec=15)
        try:
            event = network_log.wait_for_dns_event(
                matches_network_policy(probe_name),
                timeout_sec=run_context.event_poll_timeout_sec,
                description="probe event naming the connector user",
            )
        except PollTimeout as timeout:
            pytest.skip(f"Could not determine the connector user: {timeout}")

    connector_user_id = event.get("user_id")
    if connector_user_id in (None, ""):
        pytest.skip("The dns security event carries no user_id, so user scoping cannot be verified")
    connector_user_id = int(connector_user_id)
    case.record(
        Step.SETUP, ok=True, detail=f"connector user id={connector_user_id} (from dns security log)"
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

            traffic = dns_lookup(executor, BLOCK_TARGET_HOST, timeout_sec=15)
            expect_delivered(
                case,
                traffic,
                expected="not blocked for a different (non-existent) user",
                failure="A DNS Firewall policy scoped to a user id that cannot be the "
                "connector still blocked resolution — the users scope is not being applied",
            )

        mine_name = resource_name(case.case_id, run_context.run_id, "mine")
        with dns_firewall.temporary(
            mine_name, [rule], action_type="BLOCK", users=[connector_user_id], user_groups=[]
        ) as my_policy:
            case.policy_ids.append(my_policy.policy_id)

            blocked = dns_lookup_until_blocked(
                executor, BLOCK_TARGET_HOST, run_context.policy_propagation_timeout_sec
            )
            case.record(
                Step.USER_RESULT,
                ok=blocked.blocked,
                detail=blocked.detail,
                expected="blocked once scoped to the real connector user",
                actual="resolution failed" if blocked.blocked else "resolution succeeded",
            )
            assert blocked.blocked, (
                f"A DNS Firewall policy scoped to the connector's own user id "
                f"({connector_user_id}) did not block its own resolution"
            )
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-FW-011")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P3")
def test_dns_firewall_blocks_aaaa_queries_too(case, run_context, dns_firewall, executor):
    """DNS Firewall 차단은 A 레코드뿐 아니라 AAAA(IPv6) 조회도 막는다."""
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = DnsFirewallFactory.fqdn_rule([BLOCK_TARGET_HOST])

    def _aaaa_blocked() -> bool:
        result = executor.run(f"nslookup -type=AAAA {BLOCK_TARGET_HOST}", timeout_sec=15)
        output = f"{result.stdout}\n{result.stderr}".lower()
        return any(
            marker in output
            for marker in ("non-existent domain", "can't find", "server failed", "no answer")
        )

    try:
        with dns_firewall.temporary(policy_name, [rule], action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)

            a_blocked = dns_lookup_until_blocked(
                executor, BLOCK_TARGET_HOST, run_context.policy_propagation_timeout_sec
            )
            assert a_blocked.blocked, f"A-record lookup never blocked: {a_blocked.detail}"

            aaaa_blocked = _aaaa_blocked()
            case.record(
                Step.USER_RESULT,
                ok=aaaa_blocked,
                detail=f"AAAA lookup for {BLOCK_TARGET_HOST} {'blocked' if aaaa_blocked else 'resolved'}",
                expected="AAAA query also fails",
                actual="blocked" if aaaa_blocked else "resolved",
            )
            assert aaaa_blocked, (
                f"A DNS Firewall rule blocking {BLOCK_TARGET_HOST} stopped the A-record "
                f"query but let an AAAA (IPv6) query for the same name through"
            )
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-FW-012")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P3")
def test_dns_firewall_wildcard_value_covers_subdomains(case, run_context, dns_firewall, executor):
    """`*.domain`처럼 와일드카드로 값을 넣으면 서브도메인 전체를 막을 수 있다.

    `*.iana.org`는 서브도메인(www.iana.org)만 막고 apex(iana.org)는 막지 않는다.
    """
    apex = "iana.org"
    subdomain = "www.iana.org"
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = DnsFirewallFactory.fqdn_rule([f"*.{apex}"])

    try:
        with dns_firewall.temporary(policy_name, [rule], action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)
            case.record(Step.SETUP, ok=True, detail=f"BLOCK scoped to wildcard value '*.{apex}'")

            sub_result = dns_lookup_until_blocked(
                executor, subdomain, run_context.policy_propagation_timeout_sec
            )
            case.record(
                Step.USER_RESULT,
                ok=sub_result.blocked,
                detail=sub_result.detail,
                expected=f"{subdomain} fails to resolve under the wildcard rule",
                actual="resolution failed" if sub_result.blocked else "resolution succeeded",
            )
            assert sub_result.blocked, (
                f"A rule on '*.{apex}' did not block the subdomain {subdomain}"
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
    case, run_context, dns_firewall, executor, network_log
):
    """DNS 보안로그 이벤트에 사용자·출발지 IP·국가 등 조사에 필요한 정보가 담겨 있다.

    콘솔의 DNS 보안 로그에는 단말(device_id) 항목이 없으므로 확인하지 않는다.
    """
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = DnsFirewallFactory.fqdn_rule([BLOCK_TARGET_HOST])

    try:
        with dns_firewall.temporary(policy_name, [rule], action_type="BLOCK") as policy:
            case.policy_ids.append(policy.policy_id)

            blocked = dns_lookup_until_blocked(
                executor, BLOCK_TARGET_HOST, run_context.policy_propagation_timeout_sec
            )
            assert blocked.blocked, f"Lookup never blocked: {blocked.detail}"

            event = await_network_event(
                case, network_log, policy_name, kind="dns",
                timeout_sec=run_context.event_poll_timeout_sec,
            )
            present = {
                field: event.get(field)
                for field in ("user_id", "user_name", "src_ip", "src_country_code")
            }
            missing = [field for field, value in present.items() if value in (None, "")]
            case.record(
                Step.USER_RESULT,
                ok=not missing,
                detail=f"event fields: {present}",
                expected="user_id/user_name/src_ip/src_country_code all populated",
                actual=f"missing: {missing}" if missing else "all populated",
            )
            assert not missing, f"DNS security event is missing: {missing} ({present})"
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)
