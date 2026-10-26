"""엔드투엔드 사용자 여정 케이스.

DLP 연결 웹정책, CASB SaaS Access, GenAI 정책을 한 세션에서 함께 걸어, 여러 제품이
동시에 켜져 있을 때만 드러나는 회귀를 잡는다. 실제 브라우저와 CASB/GenAI 콘솔
세션이 필요해서 lane d에서 돈다.
"""
from __future__ import annotations

import pytest

from bat.fixtures.enums import ActionType, RiskLevel
from bat.fixtures.graphql_policies import GenAIPolicyFactory
from bat.fixtures.naming import resource_name
from bat.fixtures.policies import CleanupWarning, DlpPolicyFactory, WebPolicyFactory
from bat.fixtures.testdata import (
    ALLOW_TARGET_URL,
    CASB_SAAS_APP_ID,
    CASB_SAAS_APP_NAME,
    CASB_SAAS_URL,
    GENAI_TOPIC_ALL_RULES,
    POST_TARGET_URL,
    keyword_payload,
    marker,
)
from bat.models import Step
from tests.support import (
    await_security_event,
    cleanup_failed,
    curl_until_blocked,
    environment_error,
    expect_casb_block,
    expect_delivered,
    pass_case,
    policy_changed,
)

pytestmark = [
    pytest.mark.product("cross"),
    pytest.mark.lane("d"),
    pytest.mark.xdist_group("lane-d"),
]

GENAI_TARGET_APP = "chatgpt"


@pytest.fixture
def genai_policies(console) -> GenAIPolicyFactory:
    return GenAIPolicyFactory(console)


@pytest.mark.case("BAT-X-010")
@pytest.mark.parked  # GenAI 단계가 있어 GenAI와 함께 보류
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_normal_workday_journey(
    case,
    run_context,
    rest,
    web_policies,
    saas_access,
    genai_policies,
    browser_session,
    executor,
    web_log,
    casb_log,
):
    """평범히 웹을 쓰다가 민감정보 업로드, 위험 SaaS 접속, GenAI 사용을 차례로 시도하면 각각 걸린다.

    GenAI 단계는 정책 생성·조회만 본다. BAT는 로그인 없이 프롬프트를 보낼 수 없어
    실제 프롬프트 차단은 확인하지 못한다.
    """
    dlp = DlpPolicyFactory(rest)
    token = marker(case.case_id, run_context.run_id)
    dlp_name = resource_name(case.case_id, run_context.run_id, "dlp")
    dlp_block_name = resource_name(case.case_id, run_context.run_id, "dlpblock")
    casb_name = resource_name(case.case_id, run_context.run_id, "casb")
    genai_name = resource_name(case.case_id, run_context.run_id, "genai")

    genai_app = genai_policies.find_app(GENAI_TARGET_APP)
    if not genai_app:
        environment_error(f"No GenAI app matching {GENAI_TARGET_APP!r} in SIA.common.genai_app")
    try:
        # 1단계: 이 케이스가 정책을 하나도 만들기 전의 평범한 브라우징.
        baseline = browser_session.visit(ALLOW_TARGET_URL, case_id=case.case_id)
        expect_delivered(
            case,
            baseline,
            step=Step.ACTION,
            expected="page rendered",
            failure=f"Baseline browsing to {ALLOW_TARGET_URL} was already blocked before "
            f"this case created anything",
        )

        # 2단계: 민감한 내용을 보내려 한다. DLP가 잡아야 한다.
        with dlp.temporary(
            dlp_name, [DlpPolicyFactory.keyword_rule("bat-token", [token])]
        ) as rule:
            case.policy_ids.append(f"dlp:{rule.policy_id}")

            with web_policies.temporary(
                dlp_block_name,
                [WebPolicyFactory.dlp_rule(rule.policy_id)],
                action_type=ActionType.BLOCK,
                risk_level=RiskLevel.MAJOR,
            ) as dlp_web_policy:
                case.policy_ids.append(dlp_web_policy.policy_id)

                dlp_traffic = curl_until_blocked(
                    executor,
                    POST_TARGET_URL,
                    run_context.policy_propagation_timeout_sec,
                    method="POST",
                    data=keyword_payload(token),
                )
                case.record(
                    Step.USER_RESULT,
                    ok=dlp_traffic.blocked,
                    detail=f"HTTP {dlp_traffic.status_code}",
                    expected="blocked (DLP leg)",
                    actual=f"HTTP {dlp_traffic.status_code}",
                )
                assert dlp_traffic.blocked, (
                    f"The DLP leg of the journey did not block a payload carrying "
                    f"the marker (HTTP {dlp_traffic.status_code})"
                )
                await_security_event(
                    case, web_log, dlp_block_name, timeout_sec=run_context.event_poll_timeout_sec,
                    policy_id=dlp_web_policy.policy_id,
                )

        # 3단계: 조직이 차단한 SaaS 앱에 접속하려 한다. CASB가 잡아야 한다.
        with saas_access.temporary(
            casb_name, [CASB_SAAS_APP_ID], action_type="BLOCK", risk_level="Major"
        ) as casb_policy:
            created = policy_changed(case, f"SaaS Access BLOCK {casb_name} created")
            case.policy_ids.append(casb_policy.policy_id)

            # BAT-CASB-004와 같이 판정한다. 페이지가 차단돼야 하고, 그 요청 자신의
            # 로그 행이 BLOCK이어야 한다.
            expect_casb_block(
                case,
                browser_session,
                casb_log,
                casb_name,
                CASB_SAAS_URL,
                changed=created,
                propagation_timeout_sec=run_context.policy_propagation_timeout_sec,
                event_timeout_sec=run_context.event_poll_timeout_sec,
                expected_service=CASB_SAAS_APP_NAME,
                failure=f"The CASB leg of the journey did not block {CASB_SAAS_APP_NAME}",
            )

        # 4단계: 이 앱에 대한 GenAI 정책. 생성·조회만 본다(docstring 참조).
        with genai_policies.temporary(
            genai_name, [int(genai_app["id"])], action_type="BLOCK",
            rules=GENAI_TOPIC_ALL_RULES, blockpage_id=0,
        ) as genai_policy:
            case.policy_ids.append(genai_policy.policy_id)
            found = genai_policies.find_id_by_name(genai_name)
            case.record(
                Step.EVENT,
                ok=bool(found),
                detail=f"GenAI policy lookup returned id={found}",
                expected="the policy is listed",
                actual=found,
            )
            assert found, f"GenAI policy {genai_name} was created but is not listed"
            # 마지막 단계 안에서 부르므로, 모든 검증이 끝난 뒤 이 정책 하나의 삭제가
            # 실패해도 정리 경고(cleanup_failed)로 남는다.
            pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)


@pytest.mark.case("BAT-X-011")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P2")
def test_incident_lockdown_channels_stay_independent(
    case,
    run_context,
    rest,
    web_policies,
    saas_access,
    executor,
    browser_session,
    web_log,
    casb_log,
):
    """의심 정황 이후 DLP·CASB 차단을 동시에 걸어도 각자 자기 트래픽만 정확히 막는다.

    CASB 전파 예산은 CASB 정책 생성 시각부터 잰다. DLP 채널이 도는 동안 예산이 지났으면
    전파 구간은 판정에서 제외하고(리포트에 사유를 남김), 예산 뒤 요청은 그대로 판정한다.
    """
    token = marker(case.case_id, run_context.run_id)
    dlp = DlpPolicyFactory(rest)
    dlp_name = resource_name(case.case_id, run_context.run_id, "dlp")
    dlp_block_name = resource_name(case.case_id, run_context.run_id, "dlpblock")
    casb_name = resource_name(case.case_id, run_context.run_id, "casb")

    try:
        with dlp.temporary(
            dlp_name, [DlpPolicyFactory.keyword_rule("bat-token", [token])]
        ) as rule:
            case.policy_ids.append(f"dlp:{rule.policy_id}")

            with web_policies.temporary(
                dlp_block_name,
                [WebPolicyFactory.dlp_rule(rule.policy_id)],
                action_type=ActionType.BLOCK,
                risk_level=RiskLevel.MAJOR,
            ) as dlp_web_policy:
                case.policy_ids.append(dlp_web_policy.policy_id)

                with saas_access.temporary(
                    casb_name, [CASB_SAAS_APP_ID], action_type="BLOCK", risk_level="Major"
                ) as casb_policy:
                    casb_created = policy_changed(case, f"SaaS Access BLOCK {casb_name} created")
                    case.policy_ids.append(casb_policy.policy_id)
                    case.record(
                        Step.SETUP,
                        ok=True,
                        detail=f"DLP-linked web BLOCK ({dlp_block_name}) and CASB SaaS "
                        f"Access BLOCK ({casb_name}) both active at once",
                    )

                    # 채널 A: DLP가 탐지하는 업로드.
                    dlp_traffic = curl_until_blocked(
                        executor,
                        POST_TARGET_URL,
                        run_context.policy_propagation_timeout_sec,
                        method="POST",
                        data=keyword_payload(token),
                    )
                    case.record(
                        Step.USER_RESULT,
                        ok=dlp_traffic.blocked,
                        detail=f"DLP channel: HTTP {dlp_traffic.status_code}",
                        expected="blocked",
                        actual=f"HTTP {dlp_traffic.status_code}",
                    )
                    assert dlp_traffic.blocked, (
                        f"With a CASB BLOCK also active, the DLP-linked web policy "
                        f"stopped blocking its own traffic (HTTP "
                        f"{dlp_traffic.status_code}) — the two channels are not "
                        f"independent"
                    )
                    dlp_event = await_security_event(
                        case,
                        web_log,
                        dlp_block_name,
                        timeout_sec=run_context.event_poll_timeout_sec,
                        policy_id=dlp_web_policy.policy_id,
                    )

                    # 채널 B: 다른 호스트인 위험 SaaS 앱. BAT-CASB-004와 같이 판정한다.
                    # 그 행이 없으면 None이다(UNVERIFIED).
                    casb_event = expect_casb_block(
                        case,
                        browser_session,
                        casb_log,
                        casb_name,
                        CASB_SAAS_URL,
                        changed=casb_created,
                        budget_spent_reason=(
                            "the DLP channel ran first and outlasted the CASB policy's budget; this "
                            "case asks whether the block holds while both channels are active, and "
                            "BAT-CASB-004 judges how fast it takes effect"
                        ),
                        propagation_timeout_sec=run_context.policy_propagation_timeout_sec,
                        event_timeout_sec=run_context.event_poll_timeout_sec,
                        expected_service=CASB_SAAS_APP_NAME,
                        failure=f"With a DLP block also active, the CASB channel did not "
                        f"block {CASB_SAAS_APP_NAME}",
                    )

                    # 어느 채널의 이벤트도 상대 정책의 이름을 달고 있으면 안 된다.
                    mixed_up = dlp_event.get("policy_name") == casb_name or (
                        casb_event is not None
                        and str(casb_event.get("rule_name")) == dlp_block_name
                    )
                    case.record(
                        Step.EVENT,
                        ok=not mixed_up,
                        detail="cross-checked which policy each event names",
                        expected="each event names only its own policy",
                        actual={
                            "dlp_event_policy": dlp_event.get("policy_name"),
                            "casb_event_rule": casb_event.get("rule_name") if casb_event else None,
                        },
                    )
                    assert not mixed_up, (
                        "The DLP and CASB events were attributed to each other's "
                        "policy — the two simultaneously active BLOCK channels are "
                        "not actually independent"
                    )
                    pass_case(case)

    except CleanupWarning as warning:
        cleanup_failed(case, warning)
