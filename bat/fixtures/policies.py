"""정책 팩토리.

팩토리마다 `temporary()` 컨텍스트 매니저를 제공해, 케이스가 실패해도 정책이
남지 않게 한다. SWG와 DLP는 REST를, RBI와 CASB는 콘솔 GraphQL을 쓴다. DLP에
연결된 웹 정책은 REST가 거부하므로 역시 GraphQL로 만든다.
"""
from __future__ import annotations

import logging
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator

from bat.clients.errors import ApiError
from bat.clients.graphql import GraphQLClient
from bat.clients.rest import RestClient, pick_id
from bat.fixtures.enums import (
    ActionType,
    Condition,
    DlpRuleType,
    RiskLevel,
    Subject,
    validate_rule,
)

log = logging.getLogger(__name__)

WEB_POLICY_PATH = "/sia/v1/web/policy"
DLP_POLICY_PATH = "/sia/v1/dlp/policy"

# REST는 DLP_POLICY 연결 rule을 "400 invalid parameter"로 거부하고, 콘솔 자신도
# 이 GraphQL mutation으로 만든다. 다른 rule subject는 전부 REST를 쓴다.
CREATE_WEB_SECURITY = """
mutation BatCreateWebSecurity(
  $name: String!, $enable: Boolean, $description: String,
  $rules: [WebRuleInputType]!, $rewrite_rules: [WebRuleInputType]!,
  $blockpage_id: Int, $action_type: ACTION_TYPE!, $event_logging: Boolean!,
  $risk_level: RiskLevelEnum!, $users: [Int], $user_groups: [Int]
) {
  SIA { security { createWebSecurity(
    name: $name, enable: $enable, description: $description, rules: $rules,
    rewrite_rules: $rewrite_rules, blockpage_id: $blockpage_id,
    action_type: $action_type, event_logging: $event_logging,
    risk_level: $risk_level, users: $users, user_groups: $user_groups
  ) { id name } } }
}
"""

DELETE_WEB_SECURITY = """
mutation BatDeleteWebSecurity($id: [Int]) {
  SIA { security { deleteWebSecurity(id: $id) { result } } }
}
"""

# rb_options와 rules는 공개된 입력 타입이 없어 리터럴로 직접 넣는다.
CREATE_RBI_POLICY_TEMPLATE = """
mutation BatCreateRBIPolicy(
  $name: String!, $enable: Boolean, $users: [Int], $user_groups: [Int],
  $description: String
) {
  SIA { security { createRBIPolicy(
    name: $name, enable: $enable, users: $users, user_groups: $user_groups,
    rb_options: %(rb_options)s, rules: %(rules)s, description: $description
  ) { id name enable } } }
}
"""

DELETE_RBI_POLICY = """
mutation BatDeleteRBIPolicy($id: [Int]) {
  SIA { security { deleteRBIPolicy(id: $id) { result } } }
}
"""

# 스칼라 타입명은 RiskLevelEnum과 ACTION_TYPE이다(sia 접두사 없음).
# `application`은 공개된 입력 타입이 없어 리터럴로 직접 넣는다.
CREATE_IN_APP_CONTROL_TEMPLATE = """
mutation BatCreateInAppControl(
  $name: String!, $enable: Boolean, $event_logging: Boolean!,
  $risk_level: RiskLevelEnum!, $users: [Int], $user_groups: [Int],
  $action_type: ACTION_TYPE!, $blockpage_id: Int, $description: String
) {
  SIA { casb { in_app_control { create(
    name: $name, enable: $enable, event_logging: $event_logging,
    risk_level: $risk_level, users: $users, user_groups: $user_groups,
    action_type: $action_type, blockpage_id: $blockpage_id,
    application: %(application)s, description: $description
  ) { status } } } }
}
"""

DELETE_IN_APP_CONTROL = """
mutation BatDeleteInAppControl($id: [Int]) {
  SIA { casb { in_app_control { delete(id: $id) { status } } } }
}
"""


@dataclass
class PolicyHandle:
    """케이스가 자신이 만든 정책에 대해 알아야 하는 정보."""

    policy_id: str
    name: str
    product: str
    api: str  # "rest" | "graphql"
    payload: dict[str, Any] = field(default_factory=dict)


class GraphQLEnum(str):
    """따옴표 없는 GraphQL enum 리터럴로 렌더링되는 문자열.

    _as_graphql_literal은 다른 문자열을 전부 따옴표로 감싸는데, RBI rule의
    `subject`/`condition` 같은 enum 타입 필드는 이를 거부한다.
    """


def _as_graphql_literal(value: Any) -> str:
    """공개된 입력 타입이 없는 인자를 위해 Python 값을 GraphQL 리터럴로 렌더링한다."""
    if isinstance(value, GraphQLEnum):
        return str(value)
    if isinstance(value, dict):
        inner = ", ".join(f"{k}: {_as_graphql_literal(v)}" for k, v in value.items())
        return f"{{{inner}}}"
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_as_graphql_literal(item) for item in value) + "]"
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


class CleanupWarning(Exception):
    """케이스 본문이 성공한 뒤 리소스를 지우지 못했을 때 발생한다."""


# 본문이 이미 실패해서 예외로 올릴 수 없었던 정리 실패. case fixture가 이를
# 리포트의 정리 경고로 옮겨 적는다.
UNRAISED_CLEANUP_FAILURES: list[str] = []


@contextmanager
def _cleanup_guard(delete: Any, handle: "PolicyHandle", label: str) -> Iterator[None]:
    """빠져나갈 때 리소스를 지우되, 실제 실패를 가리지 않는다.

    삭제 실패는 본문이 성공했을 때만 CleanupWarning을 올린다. 그렇지 않으면
    본문 자신의 예외가 가려지지 않도록 UNRAISED_CLEANUP_FAILURES에 기록한다.
    """
    body_failed = False
    try:
        yield
    except BaseException:
        body_failed = True
        raise
    finally:
        try:
            delete(handle)
            log.info("Deleted %s %s", label, handle.name)
        except Exception as exc:
            log.warning("Cleanup failed for %s %s: %s", label, handle.name, exc)
            if not body_failed:
                raise CleanupWarning(f"{label} {handle.name}: {exc}") from exc
            UNRAISED_CLEANUP_FAILURES.append(f"{label} {handle.name}: {exc}")



class WebPolicyFactory:
    """REST로 만드는 SWG 웹 정책.

    `gql`은 DLP_POLICY 연결 rule에만 필요하다. `GraphQLClient`이거나 그것을
    돌려주는 인자 없는 callable일 수 있어서, 콘솔 세션은 필요할 때 늦게 얻는다.
    """

    def __init__(
        self,
        rest: RestClient,
        gql: "GraphQLClient | Callable[[], GraphQLClient] | None" = None,
    ) -> None:
        self.rest = rest
        self.gql = gql

    def _gql_client(self) -> GraphQLClient:
        client = self.gql() if callable(self.gql) else self.gql
        if not client:
            raise ApiError(
                "This web policy needs a GraphQL client (a DLP-linked rule, or "
                "deleting a policy created that way) but WebPolicyFactory has none "
                "— pass `gql=` when constructing it"
            )
        return client

    @staticmethod
    def build_rule(subject: str, condition: str, values: list[str], priority: int = 1) -> dict:
        validate_rule(subject, condition)
        return {
            "subject": subject,
            "condition": condition,
            "priority": priority,
            "value": values,
        }

    @staticmethod
    def dlp_rule(dlp_policy_id: str | int, priority: int = 1) -> dict:
        """DLP 정책을 웹 정책에 연결한다(id는 문자열로 보낸다).

            {"subject": "DLP_POLICY", "condition": "IS", "value": ["6"]}
        """
        return WebPolicyFactory.build_rule(
            Subject.DLP_POLICY, Condition.IS, [str(dlp_policy_id)], priority
        )

    @staticmethod
    def module_rule(subject: str, priority: int = 1, value: list[str] | None = None) -> dict:
        """시그니처 모듈 rule. 모듈은 값이 "true"인 스위치다.

            {"subject": "BLOCK_PUBLIC_PROXY", "condition": "IS", "value": ["true"]}
        """
        return WebPolicyFactory.build_rule(subject, Condition.IS, value or ["true"], priority)

    # id 0은 전체 사용자를 뜻한다. 빈 목록은 받아지지만 아무에게도 매칭되지 않는다.
    # 생성은 평범한 id 배열을 받고, 조회는 user_groups를 객체로 펼쳐 돌려준다.
    ALL_USERS: list[int] = [0]
    ALL_USER_GROUPS: list[int] = [0]

    def create(
        self,
        name: str,
        rules: list[dict],
        *,
        action_type: str = ActionType.BLOCK,
        risk_level: str = RiskLevel.MAJOR,
        enable: bool = True,
        event_logging: bool = True,
        description: str = "",
        users: list[int] | None = None,
        user_groups: list[int] | None = None,
        blockpage_id: int | None = None,
        extra: dict[str, Any] | None = None,
    ) -> PolicyHandle:
        users = self.ALL_USERS if users is None else users
        user_groups = self.ALL_USER_GROUPS if user_groups is None else user_groups
        description = description or f"BAT generated policy {name}"

        if any(rule.get("subject") == Subject.DLP_POLICY for rule in rules):
            return self._create_via_graphql(
                name,
                rules,
                action_type=action_type,
                risk_level=risk_level,
                enable=enable,
                event_logging=event_logging,
                description=description,
                users=users,
                user_groups=user_groups,
                blockpage_id=blockpage_id,
            )

        body: dict[str, Any] = {
            "name": name,
            "description": description,
            "enable": enable,
            "event_logging": event_logging,
            "action_type": action_type,
            "risk_level": risk_level,
            "users": users,
            "user_groups": user_groups,
            "rules": rules,
        }
        if blockpage_id is not None:
            body["blockpage_id"] = blockpage_id
        if extra:
            body.update(extra)

        payload = self.rest.post(WEB_POLICY_PATH, json=body)
        policy_id = pick_id(payload, "id", "policy_id")
        if not policy_id:
            policy_id = self._find_id_by_name(name)
        if not policy_id:
            raise ApiError(f"Created web policy {name} but could not resolve its id")
        log.info("Created web policy %s (id=%s, action=%s)", name, policy_id, action_type)
        return PolicyHandle(policy_id, name, "swg", "rest", body)

    def _create_via_graphql(
        self,
        name: str,
        rules: list[dict],
        *,
        action_type: str,
        risk_level: str,
        enable: bool,
        event_logging: bool,
        description: str,
        users: list[int],
        user_groups: list[int],
        blockpage_id: int | None,
    ) -> PolicyHandle:
        gql = self._gql_client()
        # WebRuleInputType에는 `priority` 필드가 없으므로 REST 형태 rule에서 뺀다.
        graphql_rules = [{k: v for k, v in rule.items() if k != "priority"} for rule in rules]
        variables: dict[str, Any] = {
            "name": name,
            "enable": enable,
            "description": description,
            "rules": graphql_rules,
            "rewrite_rules": [],
            "blockpage_id": blockpage_id,
            "action_type": action_type,
            "event_logging": event_logging,
            "risk_level": risk_level,
            "users": users,
            "user_groups": user_groups,
        }
        data = gql.execute(CREATE_WEB_SECURITY, variables)
        created = ((data.get("SIA") or {}).get("security") or {}).get("createWebSecurity") or {}
        policy_id = str(created.get("id") or "")
        if not policy_id:
            raise ApiError(f"createWebSecurity returned no id for {name}")
        log.info(
            "Created web policy %s via GraphQL (id=%s, action=%s, DLP-linked)",
            name,
            policy_id,
            action_type,
        )
        return PolicyHandle(policy_id, name, "swg", "graphql", variables)

    def _find_id_by_name(self, name: str) -> str | None:
        payload = self.rest.get(WEB_POLICY_PATH + "/list", params={"offset": 1, "limit": 100})
        rows = payload.get("policies") or payload.get("list") or payload.get("data") or []
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict) and row.get("name") == name:
                return str(row.get("id") or row.get("policy_id") or "")
        return None

    def set_enabled(self, handle: PolicyHandle, enabled: bool) -> None:
        self.rest.patch(
            f"{WEB_POLICY_PATH}/{handle.policy_id}/enable",
            json={"enable": enabled},
        )

    def get(self, handle: PolicyHandle) -> dict:
        return self.rest.get(f"{WEB_POLICY_PATH}/{handle.policy_id}")

    def set_priority(self, order: list[tuple[str | int, int]]) -> None:
        """정책 순서를 바꾼다. priority 숫자가 가장 작은 것부터 평가된다."""
        self.rest.patch(
            f"{WEB_POLICY_PATH}/priority",
            json={
                "policies": [
                    {"id": int(policy_id), "priority": int(priority)}
                    for policy_id, priority in order
                ]
            },
        )

    def delete(self, handle: PolicyHandle) -> None:
        if handle.api == "graphql":
            self._gql_client().execute(DELETE_WEB_SECURITY, {"id": [int(handle.policy_id)]})
            return
        # 웹 엔드포인트는 "ids"를, DLP 엔드포인트는 "policy_ids"를 받는다.
        self.rest.delete(WEB_POLICY_PATH, json={"ids": [int(handle.policy_id)]})

    @contextmanager
    def temporary(self, *args: Any, **kwargs: Any) -> Iterator[PolicyHandle]:
        handle = self.create(*args, **kwargs)
        with _cleanup_guard(self.delete, handle, "web policy"):
            yield handle


class DlpPolicyFactory:
    """DLP 탐지 룰. 실제 적용은 이를 참조하는 웹 정책을 통해 일어나므로, DLP
    케이스는 항상 이것을 WebPolicyFactory와 짝지어 쓴다."""

    def __init__(self, rest: RestClient) -> None:
        self.rest = rest

    @staticmethod
    def keyword_rule(name: str, keywords: list[str]) -> dict:
        return {"name": name, "type": DlpRuleType.KEYWORD, "enable": True, "content": keywords}

    @staticmethod
    def regex_rule(name: str, patterns: list[str]) -> dict:
        return {"name": name, "type": DlpRuleType.REGEX, "enable": True, "content": patterns}

    @staticmethod
    def predefined_rule(code: str) -> dict:
        """code로 이름을 붙인 기본 제공 탐지기(예: "KR_RESIDENT_NUMBER").

        keyword/regex 룰과 달리 `content`가 없다. `content`를 보내면
        "invalid parameter"로 거부된다.
        """
        return {"name": code, "type": DlpRuleType.PREDEFINED, "enable": True}

    def create(self, name: str, rules: list[dict], description: str = "") -> PolicyHandle:
        body = {
            "name": name,
            "description": description or f"BAT generated DLP policy {name}",
            "rules": rules,
        }
        payload = self.rest.post(DLP_POLICY_PATH, json=body)
        policy_id = pick_id(payload, "id", "policy_id")
        if not policy_id:
            found = self.rest.get(DLP_POLICY_PATH, params={"name": name})
            policy_id = pick_id(found, "id", "policy_id")
        if not policy_id:
            raise ApiError(f"Created DLP policy {name} but could not resolve its id")
        log.info("Created DLP policy %s (id=%s)", name, policy_id)
        return PolicyHandle(policy_id, name, "dlp", "rest", body)

    def predefined_rules(self) -> list[dict]:
        payload = self.rest.get(f"{DLP_POLICY_PATH}/predefined")
        # 응답은 {"total": n, "items": [...]}이고, 나머지는 대비용이다.
        rows = payload.get("items") or payload.get("rules") or payload.get("data") or payload
        return rows if isinstance(rows, list) else []

    def delete(self, handle: PolicyHandle) -> None:
        self.rest.delete(DLP_POLICY_PATH, json={"policy_ids": [int(handle.policy_id)]})

    @contextmanager
    def temporary(self, *args: Any, **kwargs: Any) -> Iterator[PolicyHandle]:
        handle = self.create(*args, **kwargs)
        with _cleanup_guard(self.delete, handle, "dlp policy"):
            yield handle


class RbiPolicyFactory:
    """RBI 정책. GraphQL 전용이다.

    RBI는 자체 `rules`로 대상 트래픽을 정한다(enum 타입 `subject`/
    `condition`: 호스트명을 주는 `SPECIFIC_WEBSITE`, 또는 `["true"]`를 주는
    `ALL_WEBSITE`). 웹 정책은 관여하지 않는다. 웹 정책의 `rbi_policy_id`는
    받아지지만 무시된다.
    """

    def __init__(self, gql: GraphQLClient) -> None:
        self.gql = gql

    @staticmethod
    def website_rule(hosts: list[str], *, priority: int = 1) -> dict:
        """특정 호스트명을 격리한다."""
        return {
            "subject": GraphQLEnum("SPECIFIC_WEBSITE"),
            "condition": GraphQLEnum("IS"),
            "value": list(hosts),
        }

    def create(
        self,
        name: str,
        rules: Any,
        rb_options: dict[str, Any],
        *,
        enable: bool = True,
        users: list[int] | None = None,
        user_groups: list[int] | None = None,
        description: str = "",
    ) -> PolicyHandle:
        variables = {
            "name": name,
            "enable": enable,
            "users": users or [],
            "user_groups": user_groups or [],
            "description": description or f"BAT generated RBI policy {name}",
        }
        query = CREATE_RBI_POLICY_TEMPLATE % {
            "rb_options": _as_graphql_literal(rb_options),
            "rules": _as_graphql_literal(rules),
        }
        data = self.gql.execute(query, variables)
        policy = ((data.get("SIA") or {}).get("security") or {}).get("createRBIPolicy") or {}
        policy_id = str(policy.get("id") or "")
        if not policy_id:
            raise ApiError(f"createRBIPolicy returned no id for {name}")
        log.info("Created RBI policy %s (id=%s)", name, policy_id)
        return PolicyHandle(policy_id, name, "rbi", "graphql", variables)

    def delete(self, handle: PolicyHandle) -> None:
        self.gql.execute(DELETE_RBI_POLICY, {"id": [int(handle.policy_id)]})

    @contextmanager
    def temporary(self, *args: Any, **kwargs: Any) -> Iterator[PolicyHandle]:
        handle = self.create(*args, **kwargs)
        with _cleanup_guard(self.delete, handle, "rbi policy"):
            yield handle


class InAppControlFactory:
    """CASB in-app control. create()는 status만 돌려주므로, id는 그 뒤 목록
    조회로 찾아야 한다."""

    def __init__(self, gql: GraphQLClient) -> None:
        self.gql = gql

    @staticmethod
    def application_from(reference: Any) -> Any:
        """create가 요구하는 `id`, `saas_desc_id`, `function` 필드만 남긴다."""
        if isinstance(reference, list):
            return [
                {
                    "id": item["id"],
                    "saas_desc_id": item["saas_desc_id"],
                    "function": item["function"],
                }
                for item in reference
                if isinstance(item, dict)
                and item.get("id") is not None
                and item.get("saas_desc_id") is not None
                and item.get("function") is not None
            ]
        return reference

    def create(
        self,
        name: str,
        application: Any,
        *,
        action_type: str = "BLOCK",
        risk_level: str = "Major",
        enable: bool = True,
        event_logging: bool = True,
        users: list[int] | None = None,
        user_groups: list[int] | None = None,
        blockpage_id: int | None = None,
        description: str = "",
    ) -> PolicyHandle:
        variables: dict[str, Any] = {
            "name": name,
            "enable": enable,
            "event_logging": event_logging,
            "risk_level": risk_level,
            "users": users if users is not None else [0],
            "user_groups": user_groups if user_groups is not None else [0],
            "action_type": action_type,
            "description": description or f"BAT generated CASB policy {name}",
        }
        if blockpage_id is not None:
            variables["blockpage_id"] = blockpage_id

        query = CREATE_IN_APP_CONTROL_TEMPLATE % {
            "application": _as_graphql_literal(self.application_from(application))
        }
        self.gql.execute(query, variables)

        policy_id = self.find_id_by_name(name)
        if not policy_id:
            raise ApiError(f"Created in-app control {name} but could not resolve its id")
        log.info("Created in-app control %s (id=%s)", name, policy_id)
        return PolicyHandle(policy_id, name, "casb", "graphql", variables)

    def delete(self, handle: PolicyHandle) -> None:
        self.gql.execute(DELETE_IN_APP_CONTROL, {"id": [int(handle.policy_id)]})
        if self.find_id_by_name(handle.name):
            raise ApiError(
                f"CASB policy {handle.name} (id={handle.policy_id}) still exists after "
                f"delete reported success. Remove it from the console."
            )

    @contextmanager
    def temporary(self, *args: Any, **kwargs: Any) -> Iterator[PolicyHandle]:
        handle = self.create(*args, **kwargs)
        with _cleanup_guard(self.delete, handle, "casb policy"):
            yield handle

    def find_id_by_name(self, name: str) -> str | None:
        from bat.fixtures.graphql_policies import InAppControlReader

        for row in InAppControlReader(self.gql).list():
            haystack = f"{row.get('name') or ''} {row.get('description') or ''}"
            if name in haystack:
                return str(row.get("id") or "")
        return None
