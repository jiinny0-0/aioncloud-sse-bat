"""DLP 케이스.

DLP 정책 자체는 탐지 룰만 정의한다. 적용은 웹 정책이 DLP_POLICY subject로 그 정책을
참조할 때 일어나므로, 여기 모든 케이스는 둘 다 만든 뒤 커넥터를 통해 실제 데이터를 보낸다.

모든 페이로드는 합성값이다. 여기에는 실제 개인정보가 없다.
"""
from __future__ import annotations

import time

import pytest

from bat.fixtures.enums import ActionType, Condition, RiskLevel, Subject
from bat.fixtures.naming import resource_name
from bat.fixtures.policies import CleanupWarning, DlpPolicyFactory, WebPolicyFactory
from bat.fixtures.testdata import (
    CUSTOM_REGEX,
    ECHO_HOSTS,
    SYNTHETIC_CARD,
    POST_TARGET_URL,
    clean_payload,
    echo_url,
    keyword_payload,
    marker,
    regex_sample,
)
from bat.traffic.http import post_payload
from tests.support import (
    MISSING,
    across_targets,
    await_security_event,
    cleanup_failed,
    curl_until_blocked,
    describe,
    endpoint_device_id,
    environment_error,
    expect_block,
    expect_hold,
    expect_no_event,
    expect_values,
    hold_after_change,
    marked_url,
    matches_any_target,
    pass_case,
    policy_changed,
    record_identity,
    unverified,
)
from bat.events.web_log import all_of, matches_policy
from bat.models import Kind, Step

pytestmark = [
    pytest.mark.product("dlp"),
    pytest.mark.lane("c"),
    pytest.mark.xdist_group("lane-c"),
]


def _attach(web_policies: WebPolicyFactory, policy_name: str, dlp_policy_id: str):
    """DLP 정책 하나를 업로드 내용에 적용하는 웹 정책."""
    return web_policies.temporary(
        policy_name,
        [WebPolicyFactory.dlp_rule(dlp_policy_id)],
        action_type=ActionType.BLOCK,
        risk_level=RiskLevel.MAJOR,
    )


def _await_dlp_event(case, run_context, web_log, web_name: str, policy, url: str):
    """마커를 단 그 요청(url) 자신의 DLP 이벤트. 정책 하나가 여러 호스트를 막고, 같은 호스트의
    다른 요청 행과도 섞이지 않게 마커로 찾는다."""
    return await_security_event(
        case, web_log, web_name, timeout_sec=run_context.event_poll_timeout_sec,
        policy_id=policy.policy_id, marker_url=url,
    )


def _post_url(case, run_context, host: str, label: str) -> str:
    return marked_url(echo_url(host, "/post"), case, run_context, f"{label}-{host.split('.')[0]}")


@pytest.mark.case("BAT-DLP-001")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P0")
@pytest.mark.gate
@pytest.mark.critical
@pytest.mark.smoke
def test_keyword_detection_blocks_upload(
    case, run_context, rest, web_policies, executor, web_log
):
    """DLP 키워드 룰에 걸리는 데이터를 전송하면 차단되고 이벤트가 남는다."""
    dlp = DlpPolicyFactory(rest)
    token = marker(case.case_id, run_context.run_id)
    dlp_name = resource_name(case.case_id, run_context.run_id, "dlp")
    web_name = resource_name(case.case_id, run_context.run_id)

    try:
        with dlp.temporary(dlp_name, [DlpPolicyFactory.keyword_rule("bat-token", [token])]) as rule:
            case.policy_ids.append(f"dlp:{rule.policy_id}")

            with _attach(web_policies, web_name, rule.policy_id) as policy:
                case.policy_ids.append(policy.policy_id)
                case.record(
                    Step.SETUP,
                    ok=True,
                    detail=f"DLP {dlp_name} referenced by web policy {web_name}",
                )

                def check(host: str) -> None:
                    url = _post_url(case, run_context, host, "kw")
                    traffic = curl_until_blocked(
                        executor,
                        url,
                        run_context.policy_propagation_timeout_sec,
                        method="POST",
                        data=keyword_payload(token),
                    )
                    case.record(
                        Step.USER_RESULT,
                        ok=traffic.blocked,
                        detail=f"{url}: HTTP {traffic.status_code}",
                        expected="blocked",
                        actual=f"HTTP {traffic.status_code}",
                    )
                    assert traffic.blocked, (
                        f"Upload containing the DLP keyword to {url} returned HTTP "
                        f"{traffic.status_code}; expected it to be refused"
                    )

                    event = _await_dlp_event(case, run_context, web_log, web_name, policy, url)
                    record_identity(case, event)

                across_targets(case, ECHO_HOSTS, check, what="DLP keyword block")
                pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-DLP-003")
@pytest.mark.verifies(Step.EVENT)
@pytest.mark.priority("P1")
def test_regex_detection_blocks_upload(
    case, run_context, rest, web_policies, executor, web_log
):
    """DLP 정규식 룰에 매칭되는 데이터가 차단된다."""
    dlp = DlpPolicyFactory(rest)
    dlp_name = resource_name(case.case_id, run_context.run_id, "dlp")
    web_name = resource_name(case.case_id, run_context.run_id)

    try:
        with dlp.temporary(
            dlp_name, [DlpPolicyFactory.regex_rule("bat-code", [CUSTOM_REGEX])]
        ) as rule:
            case.policy_ids.append(f"dlp:{rule.policy_id}")

            with _attach(web_policies, web_name, rule.policy_id) as policy:
                case.policy_ids.append(policy.policy_id)

                def check(host: str) -> None:
                    url = _post_url(case, run_context, host, "re")
                    traffic = curl_until_blocked(
                        executor,
                        url,
                        run_context.policy_propagation_timeout_sec,
                        method="POST",
                        data=f"code={regex_sample()}",
                    )
                    assert traffic.blocked, (
                        f"Payload matching {CUSTOM_REGEX} to {url} returned HTTP {traffic.status_code}"
                    )
                    _await_dlp_event(case, run_context, web_log, web_name, policy, url)

                across_targets(case, ECHO_HOSTS, check, what="DLP regex block", step=Step.EVENT)
                pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-DLP-005")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P0")
@pytest.mark.gate
@pytest.mark.critical
def test_clean_payload_passes(case, run_context, rest, web_policies, executor, web_log):
    """탐지 조건에 걸리지 않는 데이터는 정상 전송되고 이벤트도 남지 않는다.

    같은 정책이 키워드 데이터를 실제로 막고 그 요청의 이벤트를 남기는 것을 먼저 증명한다
    (양성 대조). 그 뒤 깨끗한 데이터를 대상마다 HOLD_REPEATS번 보내 모두 통과해야 하고,
    마지막에 키워드 데이터로 표지 요청을 보내 그 행이 로그에 나타난 다음 깨끗한 요청들의
    행이 이 정책으로 하나도 없는지 판정한다.
    """
    dlp = DlpPolicyFactory(rest)
    token = marker(case.case_id, run_context.run_id)
    dlp_name = resource_name(case.case_id, run_context.run_id, "dlp")
    web_name = resource_name(case.case_id, run_context.run_id)
    clean = {
        host: marked_url(echo_url(host, "/post"), case, run_context, f"clean{number}")
        for number, host in enumerate(ECHO_HOSTS, start=1)
    }

    try:
        with dlp.temporary(dlp_name, [DlpPolicyFactory.keyword_rule("bat-token", [token])]) as rule:
            case.policy_ids.append(f"dlp:{rule.policy_id}")

            with _attach(web_policies, web_name, rule.policy_id) as policy:
                case.policy_ids.append(policy.policy_id)
                mine = matches_policy(web_name, policy.policy_id)

                positive = marked_url(POST_TARGET_URL, case, run_context, "positive")
                blocked = curl_until_blocked(
                    executor, positive, run_context.policy_propagation_timeout_sec,
                    method="POST", data=keyword_payload(token),
                )
                expect_block(case, blocked, positive)
                await_security_event(
                    case, web_log, web_name, timeout_sec=run_context.event_poll_timeout_sec,
                    policy_id=policy.policy_id, marker_url=positive,
                )

                def check(host: str) -> None:
                    url = clean[host]
                    hold = hold_after_change(
                        lambda: post_payload(executor, url, clean_payload()),
                        want=lambda t: t.delivered, against=lambda t: t.blocked,
                        changed_at=time.monotonic(), budget_sec=0, steady=True,
                    )
                    expect_hold(
                        case, hold, expected=f"clean payload delivered to {url} every time",
                        failure=f"A payload without the keyword was refused by {url}; this is a false positive",
                    )

                across_targets(case, ECHO_HOSTS, check, what="clean payload delivered")

                def sentinel() -> str:
                    url = marked_url(POST_TARGET_URL, case, run_context, "sentinel")
                    post_payload(executor, url, keyword_payload(token))
                    return url

                expect_no_event(
                    case, web_log,
                    absent=all_of(mine, matches_any_target(clean.values())),
                    what=f"{web_name} rows for the clean payloads",
                    sentinel=sentinel, sentinel_match=mine,
                    timeout_sec=run_context.event_poll_timeout_sec,
                )
                pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-DLP-006")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P3")
def test_disabling_the_policy_restores_delivery(
    case, run_context, rest, web_policies, executor, web_log
):
    """정책을 비활성화하면 같은 데이터가 다시 정상 전송된다.

    차단은 그 요청 자신의 정책 행(마커)까지 확인한다. 비활성화는 다시 읽어 enable=false로
    저장됐는지 보고(set_enabled), 그 뒤 대상마다 전파 예산 안에 통과가 시작되고 예산이 지난 뒤에도
    HOLD_REPEATS번 연속 통과해야 한다.
    """
    dlp = DlpPolicyFactory(rest)
    token = marker(case.case_id, run_context.run_id)
    dlp_name = resource_name(case.case_id, run_context.run_id, "dlp")
    web_name = resource_name(case.case_id, run_context.run_id)
    payload = keyword_payload(token)

    try:
        with dlp.temporary(dlp_name, [DlpPolicyFactory.keyword_rule("bat-token", [token])]) as rule:
            case.policy_ids.append(f"dlp:{rule.policy_id}")

            with _attach(web_policies, web_name, rule.policy_id) as policy:
                case.policy_ids.append(policy.policy_id)

                def check_blocked(host: str) -> None:
                    url = _post_url(case, run_context, host, "on")
                    blocked = curl_until_blocked(
                        executor, url, run_context.policy_propagation_timeout_sec,
                        method="POST", data=payload,
                    )
                    case.record(
                        Step.USER_RESULT, ok=blocked.blocked, kind=Kind.ASSERTION, detail=blocked.detail,
                        expected=f"{url} blocked while the policy is enabled", actual=describe(blocked),
                    )
                    assert blocked.blocked, (
                        f"The policy never took effect on {host}, so disabling it would prove nothing"
                    )
                    _await_dlp_event(case, run_context, web_log, web_name, policy, url)

                def check_delivered(host: str) -> None:
                    hold = hold_after_change(
                        lambda: post_payload(executor, echo_url(host, "/post"), payload),
                        want=lambda t: t.delivered, against=lambda t: t.blocked,
                        changed_at=disabled.at, budget_sec=run_context.policy_propagation_timeout_sec,
                    )
                    expect_hold(
                        case, hold,
                        expected=f"delivered to {host} once disabled, and still after the budget",
                        failure=f"Still blocked on {host} after the policy was disabled",
                    )

                across_targets(case, ECHO_HOSTS, check_blocked, what="DLP block before disabling")
                web_policies.set_enabled(policy, False)  # 다시 읽어 enable=false가 아니면 ApiError
                disabled = policy_changed(case, f"{web_name} disabled (read back as enable=false)")
                across_targets(case, ECHO_HOSTS, check_delivered, what="delivery after disabling")
                pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-DLP-007")
@pytest.mark.verifies(Step.EVENT)
@pytest.mark.priority("P2")
def test_event_carries_enough_to_investigate(
    case, run_context, lane, rest, web_policies, executor, web_log, auth_log
):
    """DLP 이벤트에 사용자·단말·정책·행위·대상이 모두 기록된다.

    필드가 있는지만이 아니라 값이 맞는지 본다. 마커를 단 요청 자신의 행이어야 하고(대상
    URL), device_id는 이 단말의 id(설정값 또는 하드웨어 UUID), user_name은 같은 단말의 인증
    로그(로그인·터널 연결 행)의 user_name, policy_name/action은 이 정책과 BLOCK이어야 한다.
    """
    dlp = DlpPolicyFactory(rest)
    token = marker(case.case_id, run_context.run_id)
    dlp_name = resource_name(case.case_id, run_context.run_id, "dlp")
    web_name = resource_name(case.case_id, run_context.run_id)

    try:
        with dlp.temporary(dlp_name, [DlpPolicyFactory.keyword_rule("bat-token", [token])]) as rule:
            case.policy_ids.append(f"dlp:{rule.policy_id}")

            with _attach(web_policies, web_name, rule.policy_id) as policy:
                case.policy_ids.append(policy.policy_id)

                url = marked_url(POST_TARGET_URL, case, run_context, "inspect")
                traffic = curl_until_blocked(
                    executor,
                    url,
                    run_context.policy_propagation_timeout_sec,
                    method="POST",
                    data=keyword_payload(token),
                )
                assert traffic.blocked, "No detection, so there is no event to inspect"

                event = await_security_event(
                    case, web_log, web_name, timeout_sec=run_context.event_poll_timeout_sec,
                    policy_id=policy.policy_id, marker_url=url,
                )
                from bat.events.web_log import details_of

                case.record(
                    Step.EVENT,
                    ok=True,
                    detail=f"detail fields on the event: {details_of(event)}",
                    kind=Kind.EVIDENCE,
                )
                detail = web_log.event_detail(event.event_id)
                case.record(
                    Step.EVENT,
                    ok=bool(detail),
                    detail=f"detail keys: {sorted(detail) if isinstance(detail, dict) else '?'}",
                    expected="event detail retrievable by id",
                    actual="retrieved" if detail else "empty",
                )
                record_identity(case, event)

                device, source = endpoint_device_id(lane, executor)
                if not device:
                    unverified(case, Step.EVENT, f"no device id for this endpoint ({source}) to compare with")
                sessions = [
                    e for e in auth_log.events(lookback_min=24 * 60, device_id=device)
                    if str(e.get("device_id") or "") == device
                    and str(e.get("auth_result") or "") in ("AUTH_SUCCESS_SDP", "AUTH_CONNECT_VPN")
                ]
                user = next((str(e.get("user_name")) for e in sessions if e.get("user_name")), "")
                if not user:
                    unverified(case, Step.EVENT, f"no auth_log sign-in row of device {device} in 24h names a user to compare with")
                # 비어 있는 필드는 조사에 쓸 수 없으니 읽지 못한 것이 아니라 틀린 값("")으로 센다.
                expect_values(
                    case, f"security event {event.event_id} of {url}",
                    {
                        "user_name": (user, event.get("user_name") or ""),
                        "device_id": (device, event.get("device_id") or ""),
                        "policy_name": (web_name, event.get("policy_name") or ""),
                        "action": ("BLOCK", str(event.get("action") or "").upper()),
                    },
                    step=Step.EVENT,
                )
                pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)

@pytest.mark.case("BAT-DLP-002")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P0")
@pytest.mark.gate
@pytest.mark.critical
def test_predefined_rule_detects_card_number(
    case, run_context, rest, web_policies, executor, web_log
):
    """내장 탐지 룰(카드번호)이 실제 전송에서 동작한다."""
    dlp = DlpPolicyFactory(rest)

    # 일부러 주민등록번호를 쓰지 않는다: 체크섬을 통과하는 번호는 실제 누군가의 것일
    # 수 있다. SYNTHETIC_CARD는 예약된 Visa 테스트 번호라 Visa 탐지기를 우선한다. 다른
    # 브랜드의 룰은 이 번호에 매칭되지 않는다.
    predefined = dlp.predefined_rules()
    haystacks = [
        (item, f"{item.get('code','')} {item.get('display_name','')}".lower())
        for item in predefined
        if isinstance(item, dict)
    ]
    card = next((item for item, text in haystacks if "visa" in text), None) or next(
        (item for item, text in haystacks if "card" in text), None
    )
    if not card:
        available = [item.get("code") for item, _ in haystacks]
        environment_error(
            f"No card-number rule among the predefined detectors: {available}. "
            f"Resident-registration detection is deliberately not exercised here."
        )

    dlp_name = resource_name(case.case_id, run_context.run_id, "dlp")
    web_name = resource_name(case.case_id, run_context.run_id)
    rule = DlpPolicyFactory.predefined_rule(card["code"])

    try:
        with dlp.temporary(dlp_name, [rule]) as dlp_policy:
            case.policy_ids.append(f"dlp:{dlp_policy.policy_id}")
            case.record(
                Step.SETUP, ok=True, detail=f"predefined detector {card.get('code')}"
            )

            with _attach(web_policies, web_name, dlp_policy.policy_id) as policy:
                case.policy_ids.append(policy.policy_id)

                def check(host: str) -> None:
                    url = _post_url(case, run_context, host, "card")
                    traffic = curl_until_blocked(
                        executor,
                        url,
                        run_context.policy_propagation_timeout_sec,
                        method="POST",
                        data=f"card={SYNTHETIC_CARD}",
                    )
                    case.record(
                        Step.USER_RESULT,
                        ok=traffic.blocked,
                        detail=f"{url}: HTTP {traffic.status_code}",
                        expected="blocked",
                        actual=f"HTTP {traffic.status_code}",
                    )
                    assert traffic.blocked, (
                        f"The test card number sent to {url} was not detected by "
                        f"{card.get('code')} (HTTP {traffic.status_code})"
                    )
                    _await_dlp_event(case, run_context, web_log, web_name, policy, url)

                across_targets(case, ECHO_HOSTS, check, what="DLP predefined card block")
                pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)

@pytest.mark.case("BAT-DLP-004")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_file_upload_detection(case, run_context, rest, web_policies, executor, web_log):
    """민감 문자열이 포함된 파일을 업로드하면 차단된다.

    대상마다 그 업로드 요청 자신의 행(마커)을 찾고, 그 행의 file_name이 업로드한 파일 이름과
    같아야 한다(행에 file_name이 없으면 UNVERIFIED).
    """
    from bat.fixtures.testdata import upload_file_body
    from bat.traffic.http import remove_temp_file, upload_file, write_temp_file

    dlp = DlpPolicyFactory(rest)
    token = marker(case.case_id, run_context.run_id)
    dlp_name = resource_name(case.case_id, run_context.run_id, "dlp")
    web_name = resource_name(case.case_id, run_context.run_id)
    file_name = f"{case.case_id}-{run_context.run_id}.txt"

    remote_path = write_temp_file(executor, upload_file_body(token), file_name)
    case.record(Step.SETUP, ok=True, detail=f"synthetic file written to {remote_path}")

    try:
        with dlp.temporary(dlp_name, [DlpPolicyFactory.keyword_rule("bat-token", [token])]) as rule:
            case.policy_ids.append(f"dlp:{rule.policy_id}")

            with _attach(web_policies, web_name, rule.policy_id) as policy:
                case.policy_ids.append(policy.policy_id)

                from bat.events.poller import PollTimeout, poll_until

                def check(host: str) -> None:
                    url = _post_url(case, run_context, host, "file")

                    def probe():
                        result = upload_file(executor, url, remote_path=remote_path)
                        return result if result.blocked else None

                    try:
                        traffic = poll_until(
                            probe,
                            timeout_sec=run_context.policy_propagation_timeout_sec,
                            description=f"upload to {url} to be refused",
                            initial_interval=2.0,
                        )
                    except PollTimeout as timeout:
                        raise AssertionError(
                            f"The file containing the DLP keyword was delivered to {url}: {timeout}"
                        ) from timeout

                    case.record(
                        Step.USER_RESULT,
                        ok=True,
                        detail=f"{url}: HTTP {traffic.status_code}",
                        expected="blocked",
                        actual=f"HTTP {traffic.status_code}",
                        kind=Kind.ASSERTION,
                    )

                    event = _await_dlp_event(case, run_context, web_log, web_name, policy, url)
                    case.record(
                        Step.EVENT, ok=True, kind=Kind.EVIDENCE,
                        detail=f"file_action on the event: {event.get('file_action')!r}",
                    )
                    expect_values(
                        case, f"security event {event.event_id} of the upload to {url}",
                        {"file_name": (file_name, event.raw.get("file_name") or MISSING)},
                        step=Step.EVENT,
                    )

                across_targets(case, ECHO_HOSTS, check, what="DLP file upload block")
                pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)
    finally:
        remove_temp_file(executor, remote_path)


@pytest.mark.case("BAT-DLP-008")
@pytest.mark.known_issue(
    "한 DLP 정책 안의 두 번째(정규식) 룰이 탐지하지 않음",
    match=r"A payload matching only the second rule was delivered",
)
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_one_policy_with_two_rules_catches_either_of_them(
    case, run_context, rest, web_policies, executor, web_log
):
    """한 DLP 정책에 여러 룰을 넣으면 그 중 어느 룰에 걸려도 차단된다.

    키워드 룰과 정규식 룰을 한 정책에 넣고, 각각만 맞는 페이로드를 마커가 다른 요청으로 따로
    보낸다. 요청마다 막히고 그 요청 자신의 행이 남아야 한다.
    알려진 결함: 키워드 룰과 함께 있으면 정규식 룰이 탐지하지 않는다(룰 순서 무관).
    """
    dlp = DlpPolicyFactory(rest)
    token = marker(case.case_id, run_context.run_id)
    dlp_name = resource_name(case.case_id, run_context.run_id, "dlp")
    web_name = resource_name(case.case_id, run_context.run_id)
    rules = [
        DlpPolicyFactory.keyword_rule("bat-token", [token]),
        DlpPolicyFactory.regex_rule("bat-regex", [CUSTOM_REGEX]),
    ]

    try:
        with dlp.temporary(dlp_name, rules) as rule:
            case.policy_ids.append(f"dlp:{rule.policy_id}")
            case.record(
                Step.SETUP,
                ok=True,
                detail=f"one DLP policy carrying {len(rules)} rules (keyword + regex)",
            )

            with _attach(web_policies, web_name, rule.policy_id) as policy:
                case.policy_ids.append(policy.policy_id)

                keyword_url = marked_url(POST_TARGET_URL, case, run_context, "keyword")
                regex_url = marked_url(POST_TARGET_URL, case, run_context, "regex")
                by_keyword = curl_until_blocked(
                    executor,
                    keyword_url,
                    run_context.policy_propagation_timeout_sec,
                    method="POST",
                    data=keyword_payload(token),
                )
                case.record(
                    Step.USER_RESULT,
                    ok=by_keyword.blocked,
                    detail=f"keyword-only payload -> HTTP {by_keyword.status_code}",
                    expected="blocked by the keyword rule",
                    actual=f"HTTP {by_keyword.status_code}",
                )
                assert by_keyword.blocked, (
                    f"The keyword rule in a two-rule policy did not block its own "
                    f"payload (HTTP {by_keyword.status_code})"
                )
                _await_dlp_event(case, run_context, web_log, web_name, policy, keyword_url)

                by_regex = curl_until_blocked(
                    executor,
                    regex_url,
                    run_context.policy_propagation_timeout_sec,
                    method="POST",
                    data=regex_sample(),
                )
                case.record(
                    Step.USER_RESULT,
                    ok=by_regex.blocked,
                    detail=f"regex-only payload -> HTTP {by_regex.status_code}",
                    expected="blocked by the regex rule as well",
                    actual=f"HTTP {by_regex.status_code}",
                )
                assert by_regex.blocked, (
                    f"A payload matching only the second rule was delivered (HTTP "
                    f"{by_regex.status_code}); rules in one policy are not independent, "
                    f"so a multi-rule policy catches less than its rules suggest"
                )
                _await_dlp_event(case, run_context, web_log, web_name, policy, regex_url)
                pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)
