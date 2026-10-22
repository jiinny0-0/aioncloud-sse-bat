"""HTTP_HOST/HTTP_CATEGORY 외의 웹정책 rule subject.

값 형식은 `POST /sia/v1/web/policy`로 확인했다(형식이 틀리면 400으로 거부된다).
대부분의 케이스는 보안로그와 함께 관리자 감사로그도 확인한다.
"""
from __future__ import annotations

import contextlib
import ipaddress
import json
from typing import Callable

import pytest

from bat.clients.errors import ApiError
from bat.events.audit_log import AuditLogReader, matches_resource_name
from bat.events.poller import PollTimeout, poll_until
from bat.events.web_log import all_of, matches_policy, matches_target
from bat.fixtures.enums import ActionType, Condition, RiskLevel, Subject
from bat.fixtures.graphql_policies import SignaturePatternList
from bat.fixtures.naming import resource_name
from bat.fixtures.policies import CleanupWarning, WebPolicyFactory
from bat.fixtures.testdata import (
    BLOCK_TARGET_HOST,
    BLOCK_TARGET_URL,
    EICAR_STRING,
    OTHER_COUNTRY_HOST,
    OTHER_COUNTRY_URL,
    POST_TARGET_URL,
    SECOND_HOST,
    SECOND_URL,
    SIGNATURE_DENYLIST_URL,
    SIGNATURE_TARGET_HOST,
)
from bat.models import Kind, Step
from bat.traffic.http import (
    remove_temp_file,
    resolve_ip,
    upload_content,
    upload_file,
    write_temp_file,
)
from tests.support import (
    module_scope_or_stop,
    await_security_event,
    cleanup_failed,
    curl_until_blocked,
    describe,
    expect_allowed,
    expect_block,
    expect_delivered,
    pass_case,
    visit_until_blocked,
)

pytestmark = [
    pytest.mark.product("swg"),
    pytest.mark.lane("b"),
    pytest.mark.xdist_group("lane-b"),
]


def _strip_port(value: str | None) -> str | None:
    """"ip:port" -> "ip". IPv6에는 콜론이 여러 개 있으므로, 콜론이 정확히 하나이고
    그 뒤가 숫자(실제 포트)일 때만 잘라낸다."""
    if value and value.count(":") == 1:
        host, _, port = value.partition(":")
        if port.isdigit():
            return host
    return value


def _discover_traffic_identity(
    case, run_context, web_policies, browser_session, web_log
) -> dict:
    """LOGGING 정책을 걸고 한 번 방문해, 이 러너의 트래픽이 SSE 쪽에서 실제로 어떻게
    보이는지(src_ip, src_country_code, dst_country_code) 읽어 온다."""
    probe_name = resource_name(case.case_id, run_context.run_id, "idprobe")
    rule = WebPolicyFactory.build_rule(Subject.HTTP_HOST, Condition.IS, [BLOCK_TARGET_HOST])
    with web_policies.temporary(
        probe_name, [rule], action_type="LOGGING", risk_level=RiskLevel.MINOR
    ):
        browser_session.visit(BLOCK_TARGET_URL, case_id=case.case_id)
        try:
            event = web_log.wait_for_security_event(
                matches_policy(probe_name),
                timeout_sec=run_context.event_poll_timeout_sec,
                description="probe event carrying this traffic's identity",
            )
        except PollTimeout as timeout:
            pytest.skip(f"Could not observe this runner's own traffic: {timeout}")

    identity = {
        # src_ip 끝에 ":<port>"가 붙을 수 있다. 포트가 붙은 CIDR은 거부된다.
        "src_ip": _strip_port(event.get("src_ip")),
        "src_country_code": event.get("src_country_code"),
        "dst_country_code": event.get("dst_country_code"),
    }
    missing = [k for k, v in identity.items() if not v]
    if missing:
        pytest.skip(
            f"The security event carries no {missing}, so this condition cannot be targeted"
        )
    return identity


def _check_audit_log(case, run_context, audit_log: AuditLogReader, policy_name: str) -> None:
    """정책 생성이 관리자 감사로그에도 행을 남겼는지 확인한다."""
    try:
        event = audit_log.wait_for(
            matches_resource_name(policy_name),
            timeout_sec=run_context.event_poll_timeout_sec,
            description=f"audit log entry naming {policy_name}",
        )
    except PollTimeout as timeout:
        case.record(
            Step.EVENT,
            ok=False,
            detail=str(timeout),
            expected=f"audit log entry naming {policy_name}",
            actual="no matching entry",
        )
        raise AssertionError(f"Policy was created but left no audit log entry: {timeout}") from timeout

    case.record(
        Step.EVENT,
        ok=True,
        detail=f"audit_log_id={event.event_id}, email={event.get('email')}",
        expected="create recorded in the audit log",
        actual=str(event.get("content"))[:150],
        kind=Kind.ASSERTION,
    )


# -- 출발지/목적지 조건의 음성 대조 ------------------------------------------
#
# 양성 대조만으로는 "조건이 매칭됐다"와 "조건이 무시되고 정책이 모든 것에 매칭됐다"를
# 구분할 수 없다. 음성 대조는 조건이 매칭하면 안 되는 요청을 보내고, 검증 대상 정책이
# 그 요청에 대해 아무것도 기록하지 않았는지 확인한다.
#
# 러너의 출발지는 바꿀 수 없으므로 SWG-011/012는 대신 정책 값을 바꾼다(아무도 매칭할
# 수 없는 값). SWG-013은 트래픽을 바꾼다. 다른 나라에 있는 목적지이고, 그 요청 자신의
# 로그 행으로 증명한다.
#
# "아무것도 기록 안 됨"은 요청이 평가됐을 때만 의미가 있으므로, 검증 대상 정책 뒤에 둔
# LOGGING reach probe가 바로 그 요청을 기록해야 한다. 아니면 대조는 UNVERIFIED다.

# RFC 5737 TEST-NET-1: 문서용으로만 쓰이고 라우팅되지 않으므로, 어떤 실제 클라이언트
# (이 러너 포함)도 이 대역을 출발지로 요청을 보낼 수 없다.
UNROUTABLE_SOURCE = ipaddress.ip_network("192.0.2.0/24")
UNROUTABLE_SOURCE_IP = "192.0.2.1"
# 남극. ZTNA 케이스와 같다. 유효한 ISO 코드이지만 여기서 그곳을 출발지로 하는 트래픽은 없다.
NOBODY_COUNTRY = "AQ"
NEGATIVE_SETTLE_SEC = 5.0


def _marked(url: str, case, run_context, label: str) -> str:
    """다른 어떤 요청도 갖지 않는 URL을 만들어, 로그 행을 이 요청에 묶을 수 있게 한다."""
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}bat={case.case_id}-{run_context.run_id}-{label}".lower()


def _created_priority(run_context, audit_log: AuditLogReader, name: str) -> int | None:
    """웹정책이 생성될 때의 priority를 그 감사로그 행에서 읽는다.

    REST로 읽은 웹정책에는 `priority`가 없고, 감사로그 행의 `content.next[]`에는 있다.
    가장 작은 번호가 먼저 평가된다.
    """
    try:
        row = audit_log.wait_for(
            matches_resource_name(name),
            timeout_sec=run_context.event_poll_timeout_sec,
            description=f"audit log entry naming {name}",
        )
        content = json.loads(str(row.get("content") or ""))
    except (PollTimeout, ValueError):
        return None
    items = content.get("next") if isinstance(content, dict) else None
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict) and item.get("name") == name and isinstance(item.get("priority"), int):
            return item["priority"]
    return None


def _negative_unverified(case, reason: str, actual=None) -> None:
    # 예외를 던지지 않고 기록만 한다. 양성 대조는 그대로 실행되고 거기서 실패하면
    # 케이스는 여전히 FAIL이다. 이 기록은 케이스가 PASS로 끝나는 것만 막는다.
    case.record(
        Step.EVENT,
        ok=False,
        detail=f"negative control not established: {reason}",
        expected="the policy under test logs nothing for a request it must not match",
        actual=actual,
        kind=Kind.UNAVAILABLE,
    )


def _negative_control(
    case,
    run_context,
    web_policies,
    browser_session,
    web_log,
    audit_log: AuditLogReader,
    *,
    judged,
    judged_name: str,
    request_url: str,
    request_host: str,
    any_request: bool,
    unproven: Callable[[object], str | None] = lambda event: None,
) -> None:
    """`judged`가 매칭하면 안 되는 요청을 하나 보내고 로그로 판정한다.

    any_request: 판정 대상 정책이 어떤 트래픽도 매칭할 수 없는 값을 갖고 있으므로,
    어떤 요청에서든 그 정책의 이벤트가 나오면 조건이 적용되지 않는다는 뜻이다. 아니면
    이 요청의 이벤트만 센다(그 정책은 다른 트래픽을 정당하게 기록한다).
    unproven(reach_event)는 그 요청이 불일치한다고 증명되지 않는 이유를 반환하고,
    증명되면 None을 반환한다.
    """
    reach_name = resource_name(case.case_id, run_context.run_id, "reach")
    reach_rule = WebPolicyFactory.build_rule(Subject.HTTP_HOST, Condition.IS, [request_host])
    with web_policies.temporary(
        reach_name, [reach_rule], action_type="LOGGING", risk_level=RiskLevel.MINOR
    ) as reach:
        case.policy_ids.append(reach.policy_id)
        order = (
            _created_priority(run_context, audit_log, judged_name),
            _created_priority(run_context, audit_log, reach_name),
        )
        if None in order or not order[0] < order[1]:
            _negative_unverified(
                case,
                f"cannot show {judged_name} is evaluated before the reach probe "
                f"(creation priorities {order})",
            )
            return

        url = _marked(request_url, case, run_context, "neg")
        traffic = browser_session.visit(url, case_id=case.case_id)
        if not traffic.delivered:
            _negative_unverified(
                case, f"{url} was not delivered ({describe(traffic)}: {traffic.detail})"
            )
            return

        this_request = matches_target(url)
        judged_hit = matches_policy(judged_name, judged.policy_id)
        if not any_request:
            judged_hit = all_of(judged_hit, this_request)
        reach_hit = all_of(matches_policy(reach_name, reach.policy_id), this_request)

        def probe():
            hits = [e for e in web_log.security_events() if judged_hit(e) or reach_hit(e)]
            return hits or None

        try:
            poll_until(
                probe,
                timeout_sec=run_context.event_poll_timeout_sec,
                description=f"log rows for the negative-control request {url}",
            )
        except PollTimeout as timeout:
            _negative_unverified(
                case, f"the request never appeared under the reach probe: {timeout}"
            )
            return

        # 한 요청의 행들은 조금씩 시차를 두고 들어올 수 있으므로, 잠시 뒤 다시 본다.
        violated = not web_log.no_security_event(judged_hit, settle_sec=NEGATIVE_SETTLE_SEC)
        events = web_log.security_events()
        reach_event = next((e for e in events if reach_hit(e)), None)
        # 이 요청의 어느 행이든 그 요청을 설명한다(dst 국가 등). reach probe까지
        # 가지 못했다면 판정 대상 정책 자신의 행도 포함된다.
        request_row = reach_event or next((e for e in events if this_request(e)), None)
        logged_under = sorted({str(e.get("policy_name")) for e in events if this_request(e)})
        actual = {
            "request": url,
            "policies that logged it": logged_under,
            "dst_country_code": request_row.get("dst_country_code") if request_row else None,
        }
        # 불일치부터 확인한다. 그 요청이 결국 조건에 매칭되는 것으로 드러나면, 정책이
        # 그것을 기록한 것은 실패가 아니라 올바른 동작이다.
        reason = unproven(request_row) if request_row is not None else None
        if reason:
            _negative_unverified(case, reason, actual)
            return
        if violated:
            case.record(
                Step.EVENT,
                ok=False,
                detail=f"{judged_name} (id={judged.policy_id}) logged a request its condition excludes",
                expected=f"no event for policy id {judged.policy_id}",
                actual=actual,
            )
            raise AssertionError(
                f"{judged_name} logged {url}, which its condition does not match — "
                f"the condition is not being applied"
            )
        if reach_event is None:
            _negative_unverified(case, "the reach probe's row for the request disappeared", actual)
            return
        case.record(
            Step.EVENT,
            ok=True,
            detail=f"negative control: {judged_name} (id={judged.policy_id}) logged nothing "
            f"for a request it must not match, which the reach probe shows was evaluated",
            expected=f"no event for policy id {judged.policy_id}",
            actual=actual,
            kind=Kind.ASSERTION,
        )


def _value_controlled_negative(
    case, run_context, web_policies, browser_session, web_log, audit_log, *, rule, describe_value
) -> None:
    """SWG-011/012: 러너 트래픽은 그대로 두고, 그 트래픽이 매칭할 수 없음이 분명한 정책 값을 쓴다."""
    name = resource_name(case.case_id, run_context.run_id, "neg")
    with contextlib.ExitStack() as stack:
        try:
            judged = stack.enter_context(
                web_policies.temporary(
                    name, [rule], action_type="LOGGING", risk_level=RiskLevel.MINOR
                )
            )
        except ApiError as exc:
            _negative_unverified(case, f"the control value {describe_value} was rejected: {exc}")
            return
        case.policy_ids.append(judged.policy_id)
        case.record(
            Step.SETUP,
            ok=True,
            detail=f"negative control: LOGGING {describe_value} — the runner's own source "
            f"cannot be varied, so the policy value is varied instead",
        )
        _negative_control(
            case, run_context, web_policies, browser_session, web_log, audit_log,
            judged=judged, judged_name=name, request_url=SECOND_URL,
            request_host=SECOND_HOST, any_request=True,
        )


@pytest.mark.case("BAT-SWG-011")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P2")
def test_source_ip_block(
    case, run_context, web_policies, browser_session, web_log, audit_log: AuditLogReader
):
    """SOURCE_IP로 이 러너의 출발지 IP를 차단하면 실제로 막히고 보안로그·감사로그 둘 다에 남는다.

    BLOCK을 쓰지 않는다: 러너 자신의 IP를 막으면 관리 API와 정책 삭제 요청까지 막힌다.
    LOGGING으로 조건 매칭만 보고, 음성 대조는 `192.0.2.1/32` 정책으로 한다.
    """
    identity = _discover_traffic_identity(case, run_context, web_policies, browser_session, web_log)
    src_ip = identity["src_ip"]
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = WebPolicyFactory.build_rule(Subject.SOURCE_IP, Condition.IS, [f"{src_ip}/32"])

    try:
        try:
            outside = ipaddress.ip_address(src_ip) not in UNROUTABLE_SOURCE
        except ValueError:
            outside = False
        if outside:
            _value_controlled_negative(
                case, run_context, web_policies, browser_session, web_log, audit_log,
                rule=WebPolicyFactory.build_rule(
                    Subject.SOURCE_IP, Condition.IS, [f"{UNROUTABLE_SOURCE_IP}/32"]
                ),
                describe_value=f"SOURCE_IP {UNROUTABLE_SOURCE_IP}/32 (the runner is {src_ip})",
            )
        else:
            _negative_unverified(
                case, f"cannot show the runner's source {src_ip!r} is outside {UNROUTABLE_SOURCE}"
            )

        with web_policies.temporary(
            policy_name, [rule], action_type="LOGGING", risk_level=RiskLevel.MINOR
        ) as policy:
            case.policy_ids.append(policy.policy_id)
            case.record(Step.SETUP, ok=True, detail=f"LOGGING scoped to source IP {src_ip}/32")

            url = _marked(BLOCK_TARGET_URL, case, run_context, "pos")
            traffic = browser_session.visit(url, case_id=case.case_id)
            expect_allowed(case, traffic, url)

            await_security_event(
                case, web_log, policy_name, timeout_sec=run_context.event_poll_timeout_sec,
                expected_action="LOGGING",
                expected_target=url,
                target_in_search=True,
                policy_id=policy.policy_id,
            )
            _check_audit_log(case, run_context, audit_log, policy_name)
            pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-SWG-012")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P2")
def test_source_ip_geo_block(
    case, run_context, web_policies, browser_session, web_log, audit_log: AuditLogReader
):
    """SOURCE_IP_GEO로 이 러너가 실제로 접속해오는 국가가 조건과 매칭되는지 확인한다.

    BLOCK을 쓰지 않는다: 러너 자신의 국가를 막으면 러너의 모든 트래픽이 막힌다.
    LOGGING으로 조건 매칭만 보고, 음성 대조는 `AQ`(남극) 정책으로 한다.
    """
    identity = _discover_traffic_identity(case, run_context, web_policies, browser_session, web_log)
    country = identity["src_country_code"]
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = WebPolicyFactory.build_rule(Subject.SOURCE_IP_GEO, Condition.IN, [country])

    try:
        if str(country).upper() != NOBODY_COUNTRY:
            _value_controlled_negative(
                case, run_context, web_policies, browser_session, web_log, audit_log,
                rule=WebPolicyFactory.build_rule(
                    Subject.SOURCE_IP_GEO, Condition.IN, [NOBODY_COUNTRY]
                ),
                describe_value=f"SOURCE_IP_GEO {NOBODY_COUNTRY} (the runner is {country})",
            )
        else:
            _negative_unverified(case, f"the runner's own source country is {NOBODY_COUNTRY}")

        with web_policies.temporary(
            policy_name, [rule], action_type="LOGGING", risk_level=RiskLevel.MINOR
        ) as policy:
            case.policy_ids.append(policy.policy_id)
            case.record(Step.SETUP, ok=True, detail=f"LOGGING scoped to source country {country}")

            url = _marked(BLOCK_TARGET_URL, case, run_context, "pos")
            traffic = browser_session.visit(url, case_id=case.case_id)
            expect_allowed(case, traffic, url)

            await_security_event(
                case, web_log, policy_name, timeout_sec=run_context.event_poll_timeout_sec,
                expected_action="LOGGING",
                expected_target=url,
                target_in_search=True,
                policy_id=policy.policy_id,
            )
            _check_audit_log(case, run_context, audit_log, policy_name)
            pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-SWG-013")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P2")
def test_destination_ip_geo_block(
    case, run_context, web_policies, browser_session, web_log, audit_log: AuditLogReader
):
    """DESTINATION_IP_GEO로 목적지 사이트의 호스팅 국가가 조건과 매칭되는지 확인한다.

    BLOCK을 쓰지 않는다: 국가 단위 차단은 관리 API 호스트까지 막을 수 있다.
    음성 대조는 다른 나라 사이트(OTHER_COUNTRY_HOST) 요청으로 하고, 그 요청의
    dst_country_code가 정책 국가와 같으면 UNVERIFIED다.
    """
    identity = _discover_traffic_identity(case, run_context, web_policies, browser_session, web_log)
    country = identity["dst_country_code"]
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = WebPolicyFactory.build_rule(Subject.DESTINATION_IP_GEO, Condition.IN, [country])

    def elsewhere(reach_event) -> str | None:
        landed = reach_event.get("dst_country_code")
        if landed and str(landed).upper() != str(country).upper():
            return None
        return (
            f"{OTHER_COUNTRY_HOST} was logged with dst_country_code {landed!r}, so it is "
            f"not a destination outside {country}"
        )

    try:
        with web_policies.temporary(
            policy_name, [rule], action_type="LOGGING", risk_level=RiskLevel.MINOR
        ) as policy:
            case.policy_ids.append(policy.policy_id)
            case.record(
                Step.SETUP, ok=True, detail=f"LOGGING scoped to destination country {country}"
            )

            url = _marked(BLOCK_TARGET_URL, case, run_context, "pos")
            traffic = browser_session.visit(url, case_id=case.case_id)
            expect_allowed(case, traffic, url)

            await_security_event(
                case, web_log, policy_name, timeout_sec=run_context.event_poll_timeout_sec,
                expected_action="LOGGING",
                expected_target=url,
                target_in_search=True,
                policy_id=policy.policy_id,
            )
            _negative_control(
                case, run_context, web_policies, browser_session, web_log, audit_log,
                judged=policy, judged_name=policy_name, request_url=OTHER_COUNTRY_URL,
                request_host=OTHER_COUNTRY_HOST, any_request=False, unproven=elsewhere,
            )
            _check_audit_log(case, run_context, audit_log, policy_name)
            pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-SWG-014")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P2")
def test_http_url_block_is_more_specific_than_host(
    case, run_context, web_policies, browser_session, web_log, audit_log: AuditLogReader
):
    """HTTP_URL로 특정 URL 하나만 막으면 그 URL만 막히고, 같은 호스트의 다른 경로는 통과한다.

    값은 스킴을 포함한 전체 URL이다. 실패하면 먼저 단독 재실행으로 재현되는지 확인한다.
    """
    other_path_url = f"https://{BLOCK_TARGET_HOST}/headers"
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = WebPolicyFactory.build_rule(Subject.HTTP_URL, Condition.IS, [BLOCK_TARGET_URL])

    try:
        with web_policies.temporary(
            policy_name, [rule], action_type=ActionType.BLOCK, risk_level=RiskLevel.MAJOR
        ) as policy:
            case.policy_ids.append(policy.policy_id)
            case.record(Step.SETUP, ok=True, detail=f"BLOCK scoped to exactly {BLOCK_TARGET_URL}")

            traffic = visit_until_blocked(
                browser_session, BLOCK_TARGET_URL, case.case_id, run_context.policy_propagation_timeout_sec
            )
            expect_block(case, traffic, BLOCK_TARGET_URL)

            other = browser_session.visit(other_path_url, case_id=case.case_id)
            expect_delivered(
                case,
                other,
                expected=f"{other_path_url} still loads (URL-specific, not host-wide)",
                failure=f"A policy scoped to the exact URL {BLOCK_TARGET_URL} also blocked "
                f"{other_path_url} on the same host — HTTP_URL is not URL-specific",
            )

            await_security_event(
                case, web_log, policy_name, timeout_sec=run_context.event_poll_timeout_sec,
                policy_id=policy.policy_id,
            )
            _check_audit_log(case, run_context, audit_log, policy_name)
            pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-SWG-015")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P2")
def test_upload_file_extension_block_is_extension_specific(
    case, run_context, web_policies, executor, web_log, audit_log: AuditLogReader
):
    """HTTP_UPLOADFILE_EXTENSION으로 특정 확장자 업로드만 막으면 그 확장자만 막힌다.

    값은 점 없는 확장자다(GenAI `GENAI_FILE_UPLOAD`의 형식과 다르다).
    """
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = WebPolicyFactory.build_rule(Subject.HTTP_UPLOADFILE_EXTENSION, Condition.IN, ["txt"])
    blocked_path = allowed_path = ""

    try:
        with web_policies.temporary(
            policy_name, [rule], action_type=ActionType.BLOCK, risk_level=RiskLevel.MAJOR
        ) as policy:
            case.policy_ids.append(policy.policy_id)
            case.record(Step.SETUP, ok=True, detail="BLOCK scoped to .txt uploads")

            blocked_name = f"{case.case_id}-{run_context.run_id}.txt"
            blocked_path = write_temp_file(executor, "BAT upload-extension probe\n", blocked_name)

            def probe():
                result = upload_file(executor, POST_TARGET_URL, remote_path=blocked_path)
                return result if result.blocked else None

            try:
                traffic = poll_until(
                    probe,
                    timeout_sec=run_context.policy_propagation_timeout_sec,
                    description="txt upload to be refused",
                    initial_interval=2.0,
                )
            except PollTimeout as timeout:
                raise AssertionError(f".txt upload was never blocked: {timeout}") from timeout
            case.record(
                Step.USER_RESULT,
                ok=traffic.blocked,
                detail=f"HTTP {traffic.status_code}",
                expected="blocked",
                actual=f"HTTP {traffic.status_code}",
            )

            allowed_name = f"{case.case_id}-{run_context.run_id}.csv"
            allowed_path = write_temp_file(executor, "BAT upload-extension probe\n", allowed_name)
            other = upload_file(executor, POST_TARGET_URL, remote_path=allowed_path)
            expect_delivered(
                case,
                other,
                expected="a .csv upload is not blocked by a .txt-scoped policy",
                failure=f"A policy scoped to .txt uploads also blocked a .csv upload "
                f"(HTTP {other.status_code}) — the extension condition is not specific",
            )

            await_security_event(
                case, web_log, policy_name, timeout_sec=run_context.event_poll_timeout_sec,
                policy_id=policy.policy_id,
            )
            _check_audit_log(case, run_context, audit_log, policy_name)
            pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)
    finally:
        if blocked_path:
            remove_temp_file(executor, blocked_path)
        if allowed_path:
            remove_temp_file(executor, allowed_path)


@pytest.mark.case("BAT-SWG-016")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P2")
def test_anti_virus_signature_blocks_eicar(
    case, run_context, web_policies, executor, web_log, audit_log: AuditLogReader
):
    """ANTI_VIRUS 시그니처를 켜면 EICAR 테스트 파일 업로드가 차단될 수 있다.

    EICAR은 실제 악성코드가 아닌 표준 테스트 문자열이다. 단말 백신이 디스크의 EICAR을
    지우므로 `upload_content()`로 디스크를 거치지 않고 보낸다. 엔진이 인식하지 않으면
    FAIL이 아니라 SKIP이다.
    """
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = WebPolicyFactory.module_rule(Subject.ANTI_VIRUS)

    try:
        module_scope_or_stop(case, run_context, web_policies, executor, web_log, rule)
        with web_policies.temporary(
            policy_name, [rule], action_type=ActionType.BLOCK, risk_level=RiskLevel.MAJOR
        ) as policy:
            case.policy_ids.append(policy.policy_id)
            case.record(Step.SETUP, ok=True, detail="ANTI_VIRUS module BLOCK enabled")

            def probe():
                result = upload_content(
                    executor, POST_TARGET_URL, EICAR_STRING, filename="eicar.txt"
                )
                return result if result.blocked else None

            try:
                traffic = poll_until(
                    probe,
                    timeout_sec=run_context.policy_propagation_timeout_sec,
                    description="EICAR upload to be refused",
                    initial_interval=2.0,
                )
            except PollTimeout as timeout:
                pytest.skip(
                    f"EICAR upload was not recognised by ANTI_VIRUS this time: {timeout} "
                    f"— content delivery was independently confirmed intact (httpbin echo), "
                    f"so this depends on the product's own engine, not a transport problem"
                )
            case.record(
                Step.USER_RESULT,
                ok=traffic.blocked,
                detail=f"HTTP {traffic.status_code}",
                expected="blocked",
                actual=f"HTTP {traffic.status_code}",
            )

            await_security_event(
                case, web_log, policy_name, timeout_sec=run_context.event_poll_timeout_sec,
                policy_id=policy.policy_id,
            )
            _check_audit_log(case, run_context, audit_log, policy_name)
            pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-SWG-017")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P3")
def test_cnc_traffic_signature(case, run_context, web_policies, executor, web_log, console):
    """BLOCK_CNC_TRAFFIC을 켜면 Signature Management C&C 차단 목록에 등록된 대상 접속이 차단된다.

    이 모듈은 C&C 차단 목록에 등록된 URL/IP만 잡는다. 케이스가 자기 대상
    (SIGNATURE_TARGET_HOST)을 목록에 넣고 끝나면 빼며, 다른 항목은 그대로 둔다.
    """
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = WebPolicyFactory.module_rule(Subject.BLOCK_CNC_TRAFFIC)

    try:
        with SignaturePatternList(console).temporary_deny("CNC", SIGNATURE_TARGET_HOST):
            case.record(
                Step.SETUP, ok=True, kind=Kind.EVIDENCE,
                detail=f"{SIGNATURE_TARGET_HOST} added to the C&C deny list",
            )
            module_scope_or_stop(case, run_context, web_policies, executor, web_log, rule)
            with web_policies.temporary(
                policy_name, [rule], action_type=ActionType.BLOCK, risk_level=RiskLevel.MAJOR
            ) as policy:
                case.policy_ids.append(policy.policy_id)
                case.record(Step.SETUP, ok=True, detail="BLOCK_CNC_TRAFFIC module BLOCK enabled")

                traffic = curl_until_blocked(
                    executor, SIGNATURE_DENYLIST_URL, run_context.policy_propagation_timeout_sec
                )
                case.record(
                    Step.USER_RESULT,
                    ok=traffic.blocked,
                    detail=f"HTTP {traffic.status_code}",
                    expected=f"blocked ({SIGNATURE_DENYLIST_URL} is registered in this "
                    f"workspace's C&C deny list)",
                    actual=f"HTTP {traffic.status_code}",
                )
                assert traffic.blocked, (
                    f"{SIGNATURE_DENYLIST_URL} is registered in this workspace's C&C "
                    f"Signature Management deny list but was not blocked "
                    f"(HTTP {traffic.status_code})"
                )

                await_security_event(
                    case, web_log, policy_name, timeout_sec=run_context.event_poll_timeout_sec,
                    policy_id=policy.policy_id,
                )
                pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-SWG-018")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P2")
def test_http_path_block_is_path_specific(
    case, run_context, web_policies, executor, web_log, audit_log: AuditLogReader
):
    """HTTP_PATH로 특정 경로만 막으면 그 경로만 막히고, 같은 호스트의 다른 경로는 통과한다.

    값은 `IS` + `/`로 시작하는 경로다(예 `"/get"`).
    """
    other_path_url = f"https://{BLOCK_TARGET_HOST}/headers"
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = WebPolicyFactory.build_rule(Subject.HTTP_PATH, Condition.IS, ["/get"])

    try:
        with web_policies.temporary(
            policy_name, [rule], action_type=ActionType.BLOCK, risk_level=RiskLevel.MAJOR
        ) as policy:
            case.policy_ids.append(policy.policy_id)
            case.record(Step.SETUP, ok=True, detail="BLOCK scoped to HTTP_PATH /get")

            traffic = curl_until_blocked(
                executor, BLOCK_TARGET_URL, run_context.policy_propagation_timeout_sec
            )
            case.record(
                Step.USER_RESULT,
                ok=traffic.blocked,
                detail=f"HTTP {traffic.status_code}",
                expected=f"{BLOCK_TARGET_URL} (/get) is blocked",
                actual=f"HTTP {traffic.status_code}",
            )
            assert traffic.blocked, (
                f"A policy scoped to HTTP_PATH /get did not block {BLOCK_TARGET_URL} "
                f"(HTTP {traffic.status_code})"
            )

            other = curl_until_blocked(executor, other_path_url, 8)
            expect_delivered(
                case,
                other,
                expected=f"{other_path_url} still loads (path-specific, not host-wide)",
                failure=f"A policy scoped to HTTP_PATH /get also blocked {other_path_url} on "
                f"the same host — HTTP_PATH is not path-specific",
            )

            await_security_event(
                case, web_log, policy_name, timeout_sec=run_context.event_poll_timeout_sec,
                policy_id=policy.policy_id,
            )
            _check_audit_log(case, run_context, audit_log, policy_name)
            pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-SWG-019")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P2")
def test_http_method_condition_matches_real_traffic(
    case, run_context, web_policies, executor, web_log, audit_log: AuditLogReader
):
    """HTTP_METHOD 조건이 실제 트래픽의 메서드와 매칭되는지 확인한다.

    값은 `IN` + 대문자 메서드명이다. BLOCK을 쓰지 않는다: 메서드 조건은 목적지를
    가리지 않아 러너 자신의 콘솔 로그인(POST)까지 막는다. LOGGING으로 매칭만 본다.
    """
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = WebPolicyFactory.build_rule(Subject.HTTP_METHOD, Condition.IN, ["POST"])

    try:
        with web_policies.temporary(
            policy_name, [rule], action_type="LOGGING", risk_level=RiskLevel.MINOR
        ) as policy:
            case.policy_ids.append(policy.policy_id)
            case.record(Step.SETUP, ok=True, detail="LOGGING scoped to HTTP_METHOD POST")

            traffic = curl_until_blocked(
                executor,
                POST_TARGET_URL,
                run_context.policy_propagation_timeout_sec,
                method="POST",
                data="bat=probe",
            )
            expect_allowed(case, traffic, POST_TARGET_URL)

            await_security_event(
                case, web_log, policy_name, timeout_sec=run_context.event_poll_timeout_sec,
                expected_action="LOGGING",
                policy_id=policy.policy_id,
            )
            _check_audit_log(case, run_context, audit_log, policy_name)
            pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-SWG-020")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P2")
def test_destination_ip_block_is_ip_specific(
    case, run_context, web_policies, executor, web_log, audit_log: AuditLogReader
):
    """DESTINATION_IP로 특정 IP 하나만 막으면 그 IP만 막히고, 다른 목적지는 통과한다.

    값은 `IS` + plain IP 또는 `/32`다(`/24` 같은 넓은 CIDR은 거부된다).
    """
    policy_name = resource_name(case.case_id, run_context.run_id)
    target_ip = resolve_ip(executor, BLOCK_TARGET_HOST)
    rule = WebPolicyFactory.build_rule(Subject.DESTINATION_IP, Condition.IS, [target_ip])

    try:
        with web_policies.temporary(
            policy_name, [rule], action_type=ActionType.BLOCK, risk_level=RiskLevel.MAJOR
        ) as policy:
            case.policy_ids.append(policy.policy_id)
            case.record(
                Step.SETUP, ok=True, detail=f"BLOCK scoped to DESTINATION_IP {target_ip}"
            )

            # IP를 고정한다. httpbin.org에는 A 레코드가 여러 개 있어서, 고정하지 않은
            # 요청은 정책이 지정하지 않은 IP로 갈 수 있다.
            traffic = curl_until_blocked(
                executor, BLOCK_TARGET_URL, run_context.policy_propagation_timeout_sec,
                pin_ip=target_ip,
            )
            case.record(
                Step.USER_RESULT,
                ok=traffic.blocked,
                detail=f"HTTP {traffic.status_code} (connected to {target_ip})",
                expected=f"{BLOCK_TARGET_URL} ({target_ip}) is blocked",
                actual=f"HTTP {traffic.status_code}",
            )
            assert traffic.blocked, (
                f"A policy scoped to DESTINATION_IP {target_ip} did not block "
                f"{BLOCK_TARGET_URL} (HTTP {traffic.status_code})"
            )

            other = curl_until_blocked(executor, SECOND_URL, 8)
            expect_delivered(
                case,
                other,
                expected=f"{SECOND_URL} (different IP) still loads (IP-specific)",
                failure=f"A policy scoped to DESTINATION_IP {target_ip} also blocked "
                f"{SECOND_URL} — DESTINATION_IP is not IP-specific",
            )

            await_security_event(
                case, web_log, policy_name, timeout_sec=run_context.event_poll_timeout_sec,
                policy_id=policy.policy_id,
            )
            _check_audit_log(case, run_context, audit_log, policy_name)
            pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-SWG-021")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P3")
def test_risky_website_signature(case, run_context, web_policies, executor, web_log, console):
    """BLOCK_RISKY_WEBSITES를 켜면 Signature Management Risky Website 차단 목록에 등록된 대상 접속이 차단된다.

    BAT-SWG-017과 같은 방식이다(Risky Website 차단 목록).
    """
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = WebPolicyFactory.module_rule(Subject.BLOCK_RISKY_WEBSITES)

    try:
        with SignaturePatternList(console).temporary_deny("RISKY_WEBSITE", SIGNATURE_TARGET_HOST):
            case.record(
                Step.SETUP, ok=True, kind=Kind.EVIDENCE,
                detail=f"{SIGNATURE_TARGET_HOST} added to the Risky Website deny list",
            )
            module_scope_or_stop(case, run_context, web_policies, executor, web_log, rule)
            with web_policies.temporary(
                policy_name, [rule], action_type=ActionType.BLOCK, risk_level=RiskLevel.MAJOR
            ) as policy:
                case.policy_ids.append(policy.policy_id)
                case.record(Step.SETUP, ok=True, detail="BLOCK_RISKY_WEBSITES module BLOCK enabled")

                traffic = curl_until_blocked(
                    executor, SIGNATURE_DENYLIST_URL, run_context.policy_propagation_timeout_sec
                )
                case.record(
                    Step.USER_RESULT,
                    ok=traffic.blocked,
                    detail=f"HTTP {traffic.status_code}",
                    expected=f"blocked ({SIGNATURE_DENYLIST_URL} is registered in this "
                    f"workspace's Risky Website deny list)",
                    actual=f"HTTP {traffic.status_code}",
                )
                assert traffic.blocked, (
                    f"{SIGNATURE_DENYLIST_URL} is registered in this workspace's Risky "
                    f"Website Signature Management deny list but was not blocked "
                    f"(HTTP {traffic.status_code})"
                )

                await_security_event(
                    case, web_log, policy_name, timeout_sec=run_context.event_poll_timeout_sec,
                    policy_id=policy.policy_id,
                )
                pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)
