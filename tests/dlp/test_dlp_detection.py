"""DLP 케이스.

DLP 정책 자체는 탐지 룰만 정의한다. 적용은 웹 정책이 DLP_POLICY subject로 그 정책을
참조할 때 일어나므로, 여기 모든 케이스는 둘 다 만든 뒤 커넥터를 통해 실제 데이터를 보낸다.

모든 페이로드는 합성값이다. 여기에는 실제 개인정보가 없다.
"""
from __future__ import annotations

import pytest

from bat.fixtures.enums import ActionType, Condition, RiskLevel, Subject
from bat.fixtures.naming import resource_name
from bat.fixtures.policies import CleanupWarning, DlpPolicyFactory, WebPolicyFactory
from bat.fixtures.testdata import (
    CUSTOM_REGEX,
    SYNTHETIC_CARD,
    POST_TARGET_URL,
    clean_payload,
    keyword_payload,
    marker,
    regex_sample,
)
from bat.traffic.http import post_payload
from tests.support import (
    await_security_event,
    cleanup_failed,
    curl_until_blocked,
    curl_until_delivered,
    expect_delivered,
    pass_case,
    record_identity,
)
from bat.events.web_log import matches_policy
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


@pytest.mark.case("BAT-DLP-001")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P0")
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

                traffic = curl_until_blocked(
                    executor,
                    POST_TARGET_URL,
                    run_context.policy_propagation_timeout_sec,
                    method="POST",
                    data=keyword_payload(token),
                )
                case.record(
                    Step.USER_RESULT,
                    ok=traffic.blocked,
                    detail=f"HTTP {traffic.status_code}",
                    expected="blocked",
                    actual=f"HTTP {traffic.status_code}",
                )
                assert traffic.blocked, (
                    f"Upload containing the DLP keyword returned HTTP "
                    f"{traffic.status_code}; expected it to be refused"
                )

                event = await_security_event(
                    case, web_log, web_name, timeout_sec=run_context.event_poll_timeout_sec,
                    policy_id=policy.policy_id,
                )
                record_identity(case, event)
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

                traffic = curl_until_blocked(
                    executor,
                    POST_TARGET_URL,
                    run_context.policy_propagation_timeout_sec,
                    method="POST",
                    data=f"code={regex_sample()}",
                )
                assert traffic.blocked, (
                    f"Payload matching {CUSTOM_REGEX} returned HTTP {traffic.status_code}"
                )
                await_security_event(
                    case, web_log, web_name, timeout_sec=run_context.event_poll_timeout_sec,
                    policy_id=policy.policy_id,
                )
                pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-DLP-005")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P0")
@pytest.mark.critical
def test_clean_payload_passes(case, run_context, rest, web_policies, executor, web_log):
    """탐지 조건에 걸리지 않는 데이터는 정상 전송되고 이벤트도 남지 않는다."""
    dlp = DlpPolicyFactory(rest)
    token = marker(case.case_id, run_context.run_id)
    dlp_name = resource_name(case.case_id, run_context.run_id, "dlp")
    web_name = resource_name(case.case_id, run_context.run_id)

    try:
        with dlp.temporary(dlp_name, [DlpPolicyFactory.keyword_rule("bat-token", [token])]) as rule:
            case.policy_ids.append(f"dlp:{rule.policy_id}")

            with _attach(web_policies, web_name, rule.policy_id) as policy:
                case.policy_ids.append(policy.policy_id)

                traffic = post_payload(executor, POST_TARGET_URL, clean_payload())
                expect_delivered(
                    case,
                    traffic,
                    expected="delivered",
                    failure=f"A payload without the keyword was refused (HTTP "
                    f"{traffic.status_code}); this is a false positive",
                )

                quiet = web_log.no_security_event(
                    matches_policy(web_name)
                )
                case.record(
                    Step.EVENT,
                    ok=quiet,
                    detail="a clean payload must not raise a DLP event",
                    expected="no event",
                    actual="no event" if quiet else "event found",
                )
                assert quiet, f"Unexpected DLP event for {web_name}"
                pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-DLP-006")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P3")
def test_disabling_the_policy_restores_delivery(
    case, run_context, rest, web_policies, executor, web_log
):
    """정책을 비활성화하면 같은 데이터가 다시 정상 전송된다."""
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

                blocked = curl_until_blocked(
                    executor,
                    POST_TARGET_URL,
                    run_context.policy_propagation_timeout_sec,
                    method="POST",
                    data=payload,
                )
                assert blocked.blocked, (
                    "The policy never took effect, so disabling it would prove nothing"
                )

                web_policies.set_enabled(policy, False)

                # post_payload()가 보내는 것과 같은 요청을, 통과할 때까지 재시도한다.
                delivered = curl_until_delivered(
                    executor,
                    POST_TARGET_URL,
                    run_context.policy_propagation_timeout_sec,
                    method="POST",
                    data=payload,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                expect_delivered(
                    case,
                    delivered,
                    expected="delivered once disabled",
                    failure="Still blocked after the policy was disabled",
                )
                pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-DLP-007")
@pytest.mark.verifies(Step.EVENT)
@pytest.mark.priority("P2")
def test_event_carries_enough_to_investigate(
    case, run_context, rest, web_policies, executor, web_log
):
    """DLP 이벤트에 사용자·단말·정책·행위·대상이 모두 기록된다."""
    dlp = DlpPolicyFactory(rest)
    token = marker(case.case_id, run_context.run_id)
    dlp_name = resource_name(case.case_id, run_context.run_id, "dlp")
    web_name = resource_name(case.case_id, run_context.run_id)

    try:
        with dlp.temporary(dlp_name, [DlpPolicyFactory.keyword_rule("bat-token", [token])]) as rule:
            case.policy_ids.append(f"dlp:{rule.policy_id}")

            with _attach(web_policies, web_name, rule.policy_id) as policy:
                case.policy_ids.append(policy.policy_id)

                traffic = curl_until_blocked(
                    executor,
                    POST_TARGET_URL,
                    run_context.policy_propagation_timeout_sec,
                    method="POST",
                    data=keyword_payload(token),
                )
                assert traffic.blocked, "No detection, so there is no event to inspect"

                event = await_security_event(
                    case, web_log, web_name, timeout_sec=run_context.event_poll_timeout_sec,
                    policy_id=policy.policy_id,
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

                required = ("user_name", "policy_name", "action")
                missing = [name for name in required if not event.get(name)]
                assert not missing, (
                    f"Event {event.event_id} is missing {missing}, which makes it "
                    f"unusable for investigation"
                )
                pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)

@pytest.mark.case("BAT-DLP-002")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P0")
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
        pytest.skip(
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

                traffic = curl_until_blocked(
                    executor,
                    POST_TARGET_URL,
                    run_context.policy_propagation_timeout_sec,
                    method="POST",
                    data=f"card={SYNTHETIC_CARD}",
                )
                case.record(
                    Step.USER_RESULT,
                    ok=traffic.blocked,
                    detail=f"HTTP {traffic.status_code}",
                    expected="blocked",
                    actual=f"HTTP {traffic.status_code}",
                )
                assert traffic.blocked, (
                    f"The test card number was not detected by {card.get('code')} "
                    f"(HTTP {traffic.status_code})"
                )

                await_security_event(
                    case, web_log, web_name, timeout_sec=run_context.event_poll_timeout_sec,
                    policy_id=policy.policy_id,
                )
                pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)

@pytest.mark.case("BAT-DLP-004")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_file_upload_detection(case, run_context, rest, web_policies, executor, web_log):
    """민감 문자열이 포함된 파일을 업로드하면 차단된다."""
    from bat.fixtures.testdata import upload_file_body
    from bat.traffic.http import remove_temp_file, upload_file, write_temp_file

    dlp = DlpPolicyFactory(rest)
    token = marker(case.case_id, run_context.run_id)
    dlp_name = resource_name(case.case_id, run_context.run_id, "dlp")
    web_name = resource_name(case.case_id, run_context.run_id)

    remote_path = write_temp_file(
        executor, upload_file_body(token), f"{case.case_id}-{run_context.run_id}.txt"
    )
    case.record(Step.SETUP, ok=True, detail=f"synthetic file written to {remote_path}")

    try:
        with dlp.temporary(dlp_name, [DlpPolicyFactory.keyword_rule("bat-token", [token])]) as rule:
            case.policy_ids.append(f"dlp:{rule.policy_id}")

            with _attach(web_policies, web_name, rule.policy_id) as policy:
                case.policy_ids.append(policy.policy_id)

                from bat.events.poller import PollTimeout, poll_until

                def probe():
                    result = upload_file(executor, POST_TARGET_URL, remote_path=remote_path)
                    return result if result.blocked else None

                try:
                    traffic = poll_until(
                        probe,
                        timeout_sec=run_context.policy_propagation_timeout_sec,
                        description="upload to be refused",
                        initial_interval=2.0,
                    )
                except PollTimeout as timeout:
                    raise AssertionError(
                        f"The file containing the DLP keyword was delivered: {timeout}"
                    ) from timeout

                case.record(
                    Step.USER_RESULT,
                    ok=True,
                    detail=f"HTTP {traffic.status_code}",
                    expected="blocked",
                    actual=f"HTTP {traffic.status_code}",
                    kind=Kind.ASSERTION,
                )

                event = await_security_event(
                    case, web_log, web_name, timeout_sec=run_context.event_poll_timeout_sec,
                    policy_id=policy.policy_id,
                )
                case.record(
                    Step.EVENT,
                    ok=True,
                    detail=f"file_name on the event: {event.get('file_name')!r}, "
                    f"file_action: {event.get('file_action')!r}",
                    expected="the event identifies the file",
                    actual={
                        "file_name": event.get("file_name"),
                        "file_action": event.get("file_action"),
                    },
                    kind=Kind.EVIDENCE,
                )
                pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)
    finally:
        remove_temp_file(executor, remote_path)


@pytest.mark.case("BAT-DLP-008")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_one_policy_with_two_rules_catches_either_of_them(
    case, run_context, rest, web_policies, executor, web_log
):
    """한 DLP 정책에 여러 룰을 넣으면 그 중 어느 룰에 걸려도 차단된다.

    키워드 룰과 정규식 룰을 한 정책에 넣고, 각각만 맞는 페이로드를 따로 보낸다.
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

                by_keyword = curl_until_blocked(
                    executor,
                    POST_TARGET_URL,
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

                by_regex = curl_until_blocked(
                    executor,
                    POST_TARGET_URL,
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

                await_security_event(
                    case,
                    web_log,
                    web_name,
                    timeout_sec=run_context.event_poll_timeout_sec,
                    policy_id=policy.policy_id,
                )
                pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)
