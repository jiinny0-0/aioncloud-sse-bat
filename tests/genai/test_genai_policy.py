"""GenAI 케이스.

GenAI 정책은 대상 서비스를 id로 지정하므로, 모든 케이스는 id를 하드코딩하지 않고 먼저
조회한다: 카탈로그는 테넌트마다 다르고 시간이 지나면 늘어난다.
"""
from __future__ import annotations

import pytest

from bat.fixtures.graphql_policies import GenAIPolicyFactory
from bat.fixtures.naming import resource_name
from bat.fixtures.policies import CleanupWarning
from bat.models import Step
from tests.support import cleanup_failed, environment_error, expect_values, pass_case, row_named, rule_values, stored

pytestmark = [
    pytest.mark.product("genai"),
    pytest.mark.lane("d"),
    pytest.mark.xdist_group("lane-d"),
]

TARGET_APP = "chatgpt"


@pytest.fixture
def genai_policies(console) -> GenAIPolicyFactory:
    return GenAIPolicyFactory(console)


def _resolve_app(genai_policies: GenAIPolicyFactory) -> dict:
    app = genai_policies.find_app(TARGET_APP)
    if not app:
        available = [str(item.get("name")) for item in genai_policies.apps()]
        environment_error(
            f"No GenAI service matching {TARGET_APP!r} in this tenant. "
            f"Available: {available}"
        )
    return app


@pytest.mark.case("BAT-GEN-001")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P1")
def test_keyword_policy_round_trip(case, run_context, genai_policies):
    """GenAI 키워드 탐지 정책을 생성하면 요청한 내용대로 저장되고, 삭제하면 사라진다.

    프롬프트 차단 자체는 검증하지 않는다: 카탈로그의 앱은 모두 로그인해야 프롬프트를
    보낼 수 있어, 생성·조회·삭제만 확인한다. 생성 직후 목록을 다시 읽어 action_type, 키워드
    rule의 값, 대상 앱(gen_ai_app)이 요청값과 같아야 한다(목록에 있다는 것은 생성이 이미
    확인한다). 삭제는 팩토리가 목록에서 사라진 것까지 확인한다.
    """
    app = _resolve_app(genai_policies)
    policy_name = resource_name(case.case_id, run_context.run_id)
    rule = [{"id": 1, "subject": "GENAI_REQUEST_KEYWORD", "condition": "IN", "value": ["password"]}]

    try:
        with genai_policies.temporary(
            policy_name,
            [int(app["id"])],
            action_type="LOGGING",
            risk_level="Minor",
            rules=[rule],
            blockpage_id=0,
        ) as policy:
            case.policy_ids.append(policy.policy_id)
            case.record(
                Step.SETUP,
                ok=True,
                detail=f"GenAI keyword policy {policy_name} (id={policy.policy_id})",
            )

            row = row_named(genai_policies.list(), policy_name)
            expect_values(case, f"GenAI policy {policy_name} as read back", {
                "action_type": ("LOGGING", stored(row, "action_type")),
                "keyword": (["password"], rule_values(stored(row, "rules"), "GENAI_REQUEST_KEYWORD")),
                "gen_ai_app": ([int(app["id"])], stored(row, "gen_ai_app")),
            })
            pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)
