"""콘솔 GraphQL 정책 팩토리: GenAI, ZTNA, FWaaS, CASB SaaS Access, 시그니처.

이 제품들은 콘솔 API에만 있고 introspection은 차단돼 있다. 목록 쿼리 형태가
공개되지 않은 곳에서는 후보 형태 몇 개를 시도하고, 하나도 안 되면 명확한
오류를 낸다.
"""
from __future__ import annotations

import logging
import re
from contextlib import contextmanager
from typing import Any, Iterator

from bat.clients.errors import ApiError
from bat.clients.graphql import GraphQLClient
from bat.fixtures.policies import PolicyHandle, _as_graphql_literal, _cleanup_guard
from bat.fixtures.testdata import GENAI_TOPIC_ALL_RULES

log = logging.getLogger(__name__)

# --- GenAI -------------------------------------------------------------

CREATE_GENAI_POLICY = """
mutation BatCreateGenAIPolicy(
  $name: String!, $enable: Boolean, $description: String,
  $users: [Int], $user_groups: [Int], $sub_orgs: [Int],
  $gen_ai_app: [Int]!, $action_type: ACTION_TYPE!, $event_logging: Boolean!,
  $risk_level: RiskLevelEnum!, $blockpage_id: Int, $rules: [[GenAIRuleInputType]]
) {
  SIA { genai { genAIPolicy { create(
    name: $name, enable: $enable, description: $description,
    users: $users, user_groups: $user_groups, sub_orgs: $sub_orgs,
    gen_ai_app: $gen_ai_app, action_type: $action_type,
    event_logging: $event_logging, risk_level: $risk_level,
    blockpage_id: $blockpage_id, rules: $rules
  ) { status } } } }
}
"""

DELETE_GENAI_POLICY = """
mutation BatDeleteGenAIPolicy($id: [Int]) {
  SIA { genai { genAIPolicy { delete(id: $id) { status } } } }
}
"""

# GenAI 정책 목록 쿼리 후보(genAIPolicy는 리스트가 아니라 객체다).
GENAI_LIST_CANDIDATES = (
    "query BatListGenAIPolicy { SIA { genai { genAIPolicy { list { id name enable } } } } }",
    "query BatListGenAIPolicy { SIA { genai { genAIPolicy { policies { id name enable } } } } }",
    "query BatListGenAIPolicy { SIA { genai { genAIPolicy { items { id name enable } } } } }",
    "query BatListGenAIPolicy { SIA { genai { genAIPolicy { genai_policy { id name enable } } } } }",
    "query BatListGenAIPolicy { SIA { genai { genai_policy { id name enable } } } }",
)

LIST_GENAI_APPS = """
query BatGenAIApps { SIA { common { genai_app { id name } } } }
"""

# --- ZTNA --------------------------------------------------------------

CREATE_ACCESS_POLICY = """
mutation BatCreateAccessPolicy(
  $name: String!, $rules: [AccessPolicyRuleInputType]!, $action_type: ACTION_TYPE!
) {
  SIA { ztna { accessPolicy { create(
    name: $name, rules: $rules, action_type: $action_type
  ) { status } } } }
}
"""

DELETE_ACCESS_POLICY = """
mutation BatDeleteAccessPolicy($id: [Int]) {
  SIA { ztna { accessPolicy { delete(id: $id) { status } } } }
}
"""

LIST_ACCESS_POLICY = """
query BatListAccessPolicy { SIA { ztna { accessPolicy { id name ctime mtime } } } }
"""

# --- FWaaS ---------------------------------------------------------------
#
# GenAI/ZTNA와 달리 이 create mutation들은 새 id를 바로 돌려준다.

CREATE_DNS_FIREWALL = """
mutation BatCreateDnsFirewall(
  $name: String!, $rules: [DNSFWRuleInputType]!, $action_type: ACTION_TYPE!,
  $risk_level: RiskLevelEnum!, $event_logging: Boolean!,
  $users: [Int], $user_groups: [Int]
) {
  SIA { network { dns_firewall { create(
    name: $name, rules: $rules, action_type: $action_type,
    risk_level: $risk_level, event_logging: $event_logging,
    users: $users, user_groups: $user_groups
  ) { id } } } }
}
"""

DELETE_DNS_FIREWALL = """
mutation BatDeleteDnsFirewall($id: [Int]) {
  SIA { network { dns_firewall { delete(id: $id) { result } } } }
}
"""

# Application Firewall에는 users/user_groups 인자가 없고, 네트워크 주소로만
# 스코프한다.
CREATE_APPLICATION_FIREWALL = """
mutation BatCreateApplicationFirewall(
  $name: String!, $subject: FirewallSubjectInputType!, $action_type: ACTION_TYPE!,
  $risk_level: RiskLevelEnum!, $event_logging: Boolean!
) {
  SIA { network { firewall { create(
    name: $name, subject: $subject, action_type: $action_type,
    risk_level: $risk_level, event_logging: $event_logging
  ) { id } } } }
}
"""

DELETE_APPLICATION_FIREWALL = """
mutation BatDeleteApplicationFirewall($id: [Int]) {
  SIA { network { firewall { delete(id: $id) { result } } } }
}
"""

# --- CASB SaaS Access ------------------------------------------------------
#
# `application`은 SaaS 카탈로그 id(in_app_control의 saas_desc_id 값)로 된 평범한
# [Int]!라서, 리터럴로 직접 넣지 않고 일반 변수로 보낸다.

CREATE_SAAS_ACCESS = """
mutation BatCreateSaasAccess(
  $name: String!, $application: [Int]!, $action_type: ACTION_TYPE!,
  $risk_level: RiskLevelEnum!, $event_logging: Boolean!,
  $users: [Int], $user_groups: [Int]
) {
  SIA { casb { saas_access { create(
    name: $name, application: $application, action_type: $action_type,
    risk_level: $risk_level, event_logging: $event_logging,
    users: $users, user_groups: $user_groups
  ) { status } } } }
}
"""

DELETE_SAAS_ACCESS = """
mutation BatDeleteSaasAccess($id: [Int]) {
  SIA { casb { saas_access { delete(id: $id) { status } } } }
}
"""


# --- 적응형 필드 선택 ------------------------------------------
#
# 목록 쿼리는 필드가 공개되지 않은 객체를 돌려준다. 그럴듯한 필드 집합을
# 요청하고 서버가 모른다고 지목한 필드는 뺀다. 결과는 실행 동안 캐시한다.

_MISSING_FIELD_RE = re.compile(r'Cannot query field "([^"]+)" on type')
_NEEDS_SELECTION_RE = re.compile(r'Field "([^"]+)" of type "[^"]+" must have a sub selection')
_FIELD_CACHE: dict[str, dict[str, str]] = {}

# 서브셀렉션을 요구하는 필드의 기본 서브셀렉션.
NESTED_SUBFIELDS = "id name"

# 쓸모 있는 내용이 {id name}이 아닌 중첩 객체의 서브셀렉션.
NESTED_PREFERRED = {
    "rules": "id subject condition value",
    "rewrite_rules": "id subject condition value",
    "application": "id saas_desc_id function",
    # 단일 객체: print, watermark, clip(클립보드), dn(다운로드), up(업로드),
    # 각각 "ON"/"OFF".
    "rb_options": "print watermark clip dn up",
    "users": "id name",
    "user_groups": "id name",
}

COMMON_POLICY_FIELDS = [
    "id",
    "name",
    "enable",
    "description",
    "action_type",
    "risk_level",
    "event_logging",
    "priority",
    "users",
    "user_groups",
    "blockpage_id",
    "application",
    "rb_options",
    "rules",
    "ctime",
    "mtime",
]


def _render(selection: dict[str, str]) -> str:
    return " ".join(
        name if not sub else f"{name} {{ {sub} }}" for name, sub in selection.items()
    )


def query_rows(
    gql: GraphQLClient,
    path: tuple[str, ...],
    *,
    fields: list[str] | None = None,
    cache_key: str = "",
) -> list[dict]:
    """SIA.<path>의 객체 목록을 읽되, 받아질 때까지 셀렉션을 다듬는다.

    모르는 필드는 뺀다. 서브셀렉션이 필요한 필드는 한 번 펼쳐 보고, 그래도
    실패하면 뺀다. `path`는 SIA 아래 경로다. 예: ("casb", "in_app_control").
    """
    key = cache_key or ".".join(path)
    selection: dict[str, str] = dict(
        _FIELD_CACHE.get(key) or {name: "" for name in (fields or COMMON_POLICY_FIELDS)}
    )

    for _ in range(2 * len(COMMON_POLICY_FIELDS)):
        if not selection:
            raise ApiError(f"No usable fields remain for SIA.{key}")

        body = _render(selection)
        for part in reversed(path):
            body = f"{part} {{ {body} }}"

        try:
            data = gql.execute(f"query BatRows {{ SIA {{ {body} }} }}")
        except ApiError as exc:
            message = str(exc)
            unknown = set(_MISSING_FIELD_RE.findall(message))
            needs_selection = set(_NEEDS_SELECTION_RE.findall(message))

            changed = False
            for name in unknown:
                # 중첩 서브셀렉션을 먼저 확인한다. 오류는 필드 이름만 주고 부모는
                # 알려주지 않으며, "id" 같은 이름은 최상위에서는 유효해도 중첩
                # 객체에서는 모르는 필드일 수 있다.
                matched_nested = False
                for parent, sub in list(selection.items()):
                    if sub and name in sub.split():
                        remaining = " ".join(x for x in sub.split() if x != name)
                        if remaining:
                            selection[parent] = remaining
                        else:
                            del selection[parent]
                        changed = True
                        matched_nested = True

                if not matched_nested and name in selection:
                    del selection[name]
                    changed = True

            for name in needs_selection:
                if selection.get(name) == "":
                    selection[name] = NESTED_PREFERRED.get(name, NESTED_SUBFIELDS)
                    changed = True
                elif name in selection:
                    del selection[name]
                    changed = True

            if not changed:
                raise
            log.info("SIA.%s selection adjusted to: %s", key, _render(selection))
            continue

        _FIELD_CACHE[key] = selection
        node = data.get("SIA") or {}
        for part in path:
            node = (node or {}).get(part) if isinstance(node, dict) else node
        return _flatten_rows(node)

    raise ApiError(f"Could not find a workable field set for SIA.{key}")


def _rules_are_complete(rules: Any) -> bool:
    """모든 rule이 create mutation이 요구하는 필드를 갖고 있으면 True."""
    required = {"subject", "condition"}
    groups = rules if isinstance(rules, list) else []
    for group in groups:
        entries = group if isinstance(group, list) else [group]
        for entry in entries:
            if not isinstance(entry, dict) or not required <= set(entry):
                return False
    return bool(groups)


def _flatten_rows(node: Any) -> list[dict]:
    """서버가 어떤 컨테이너로 감쌌든 그 안에서 정책 행을 꺼낸다."""
    if isinstance(node, list):
        return [row for row in node if isinstance(row, dict)]
    if isinstance(node, dict):
        for value in node.values():
            rows = _flatten_rows(value)
            if rows:
                return rows
    return []


def _nested(data: dict, *path: str) -> Any:
    node: Any = data
    for key in path:
        node = (node or {}).get(key) if isinstance(node, dict) else None
    return node


class GenAIPolicyFactory:
    def __init__(self, gql: GraphQLClient) -> None:
        self.gql = gql

    def apps(self) -> list[dict]:
        """정책이 대상으로 삼을 수 있는 GenAI 서비스를 {id, name}으로 돌려준다."""
        data = self.gql.execute(LIST_GENAI_APPS)
        rows = _nested(data, "SIA", "common", "genai_app") or []
        return [row for row in rows if isinstance(row, dict)]

    def find_app(self, name_contains: str) -> dict | None:
        needle = name_contains.lower()
        for app in self.apps():
            if needle in str(app.get("name", "")).lower():
                return app
        return None

    # genAIPolicy는 리스트가 아니라 객체이고, 정책은 `list` 아래에 있다.
    LIST_PATHS = (
        ("genai", "genAIPolicy", "list"),
        ("genai", "genAIPolicy", "policies"),
    )

    def list(self) -> list[dict]:
        errors: list[str] = []
        for path in self.LIST_PATHS:
            try:
                return query_rows(self.gql, path, cache_key="genai")
            except Exception as exc:
                errors.append(f"{'.'.join(path)}: {str(exc)[:100]}")

        raise ApiError(
            "Could not read the GenAI policy list. Tried:\n  " + "\n  ".join(errors)
        )

    def create(
        self,
        name: str,
        app_ids: list[int],
        *,
        action_type: str = "BLOCK",
        risk_level: str = "Major",
        enable: bool = True,
        event_logging: bool = True,
        users: list[int] | None = None,
        user_groups: list[int] | None = None,
        rules: list[list[dict]] | None = None,
        blockpage_id: int | None = None,
        description: str = "",
    ) -> PolicyHandle:
        if rules is None:
            # rule의 `id`는 정책별 rule id가 아니라 토픽 카탈로그 id다.
            # 필수 값이므로 빼면 안 된다.
            rules = GENAI_TOPIC_ALL_RULES
        if blockpage_id is None:
            blockpage_id = 0

        if not _rules_are_complete(rules):
            raise ApiError(
                "A GenAI policy needs rules carrying subject and condition; an "
                "empty or partial set is accepted but never enforces."
            )

        variables: dict[str, Any] = {
            "name": name,
            "enable": enable,
            "description": description or f"BAT generated GenAI policy {name}",
            "users": users if users is not None else [0],
            "user_groups": user_groups if user_groups is not None else [0],
            "sub_orgs": [],
            "gen_ai_app": app_ids,
            "action_type": action_type,
            "event_logging": event_logging,
            "risk_level": risk_level,
            "blockpage_id": blockpage_id,
            "rules": rules,
        }
        self.gql.execute(CREATE_GENAI_POLICY, variables)

        policy_id = self.find_id_by_name(name)
        if not policy_id:
            raise ApiError(
                f"Created GenAI policy {name} but could not find it in the list query. "
                f"Delete it by hand in the console if it exists."
            )
        log.info(
            "Created GenAI policy %s (id=%s, rules=%d, blockpage=%s)",
            name,
            policy_id,
            len(rules),
            blockpage_id,
        )
        return PolicyHandle(policy_id, name, "genai", "graphql", variables)

    def find_id_by_name(self, name: str) -> str | None:
        """이름으로 정책을 찾고, 없으면 팩토리가 쓴 description으로 찾는다."""
        for row in self.list():
            haystack = f"{row.get('name') or ''} {row.get('description') or ''}"
            if name in haystack:
                return str(row.get("id") or "")
        return None

    def delete(self, handle: PolicyHandle) -> None:
        self.gql.execute(DELETE_GENAI_POLICY, {"id": [int(handle.policy_id)]})

        # 이 mutation은 아무것도 지우지 않았을 때도 성공을 보고한다.
        if self.find_id_by_name(handle.name):
            raise ApiError(
                f"GenAI policy {handle.name} (id={handle.policy_id}) still exists after "
                f"delete returned success. Remove it from the console."
            )

    @contextmanager
    def temporary(self, *args: Any, **kwargs: Any) -> Iterator[PolicyHandle]:
        handle = self.create(*args, **kwargs)
        with _cleanup_guard(self.delete, handle, "genai policy"):
            yield handle


class InAppControlReader:
    """CASB in-app control 목록(SIA.casb.in_app_control). 읽기 전용이다."""

    def __init__(self, gql: GraphQLClient) -> None:
        self.gql = gql

    def list(self) -> list[dict]:
        return query_rows(self.gql, ("casb", "in_app_control"), cache_key="casb")


class SaasAccessFactory:
    """CASB SaaS Access(SIA.casb.saas_access): SaaS 앱 전체를 허용하거나 차단한다.

    `application`은 SaaS 카탈로그 id의 평평한 리스트이고, 빈 리스트는 전체
    앱을 뜻한다.
    """

    def __init__(self, gql: GraphQLClient) -> None:
        self.gql = gql

    def list(self) -> list[dict]:
        return query_rows(
            self.gql,
            ("casb", "saas_access"),
            fields=["id", "name", "enable", "application", "users", "user_groups"],
            cache_key="casb.saas_access",
        )

    def create(
        self,
        name: str,
        application: list[int],
        *,
        action_type: str = "BLOCK",
        risk_level: str = "Major",
        event_logging: bool = True,
        users: list[int] | None = None,
        user_groups: list[int] | None = None,
    ) -> PolicyHandle:
        variables = {
            "name": name,
            "application": application,
            "action_type": action_type,
            "risk_level": risk_level,
            "event_logging": event_logging,
            "users": [0] if users is None else users,
            "user_groups": [0] if user_groups is None else user_groups,
        }
        self.gql.execute(CREATE_SAAS_ACCESS, variables)

        policy_id = self.find_id_by_name(name)
        if not policy_id:
            raise ApiError(f"Created SaaS Access policy {name} but could not resolve its id")
        log.info("Created SaaS Access policy %s (id=%s)", name, policy_id)
        return PolicyHandle(policy_id, name, "casb", "graphql", variables)

    def find_id_by_name(self, name: str) -> str | None:
        for row in self.list():
            if name in str(row.get("name") or ""):
                return str(row.get("id") or "")
        return None

    def delete(self, handle: PolicyHandle) -> None:
        self.gql.execute(DELETE_SAAS_ACCESS, {"id": [int(handle.policy_id)]})
        if self.find_id_by_name(handle.name):
            raise ApiError(
                f"SaaS Access policy {handle.name} (id={handle.policy_id}) still exists "
                f"after delete reported success. Remove it from the console."
            )

    @contextmanager
    def temporary(self, *args: Any, **kwargs: Any) -> Iterator[PolicyHandle]:
        handle = self.create(*args, **kwargs)
        with _cleanup_guard(self.delete, handle, "casb saas access policy"):
            yield handle


class RbiPolicyReader:
    """RBI 정책 목록. mutation과 달리 SIA.security가 아니라 SIA.rbi 아래에 있다."""

    # 실제 경로는 SIA.rbi.list이고, 나머지는 대비용이다.
    LIST_PATHS = (
        ("rbi", "list"),
        ("rbi", "policy"),
        ("rbi", "policies"),
    )

    def __init__(self, gql: GraphQLClient) -> None:
        self.gql = gql

    def list(self) -> list[dict]:
        errors: list[str] = []
        for path in self.LIST_PATHS:
            try:
                return query_rows(self.gql, path, cache_key="rbi")
            except Exception as exc:
                errors.append(f"SIA.{'.'.join(path)}: {str(exc)[:100]}")

        raise ApiError(
            "Could not read the RBI policy list. Tried:\n  " + "\n  ".join(errors)
        )


class AccessPolicyFactory:
    """ZTNA access policy.

    rules는 user_id, ip, country를 키로 하는 조건 그룹의 리스트다. 이 조건은
    커넥터 세션 자체를 스코프하므로, 러너에 매칭되는 BLOCK은 스위트를 끊는다:

        [{"user_id": [3], "ip": ["10.0.0.5"]}, {"country": ["KR"]}]
    """

    def __init__(self, gql: GraphQLClient) -> None:
        self.gql = gql

    @staticmethod
    def rule(
        *,
        user_ids: list[int] | None = None,
        ips: list[str] | None = None,
        countries: list[str] | None = None,
    ) -> dict:
        group: dict[str, Any] = {}
        if user_ids is not None:
            group["user_id"] = user_ids
        if ips is not None:
            group["ip"] = ips
        if countries is not None:
            group["country"] = countries
        if not group:
            raise ValueError("An access policy rule needs at least one condition")
        return group

    def list(self) -> list[dict]:
        return query_rows(
            self.gql,
            ("ztna", "accessPolicy"),
            fields=["id", "name", "ctime", "mtime"],
            cache_key="ztna.accessPolicy",
        )

    def create(
        self, name: str, rules: list[dict], *, action_type: str = "BLOCK"
    ) -> PolicyHandle:
        variables = {"name": name, "rules": rules, "action_type": action_type}
        self.gql.execute(CREATE_ACCESS_POLICY, variables)

        policy_id = self.find_id_by_name(name)
        if not policy_id:
            raise ApiError(
                f"Created access policy {name} but could not find it in the list query. "
                f"Delete it by hand in the console if it exists."
            )
        log.info("Created ZTNA access policy %s (id=%s)", name, policy_id)
        return PolicyHandle(policy_id, name, "ztna", "graphql", variables)

    def find_id_by_name(self, name: str) -> str | None:
        """이름으로 정책을 찾고, 없으면 description으로 찾는다."""
        for row in self.list():
            haystack = f"{row.get('name') or ''} {row.get('description') or ''}"
            if name in haystack:
                return str(row.get("id") or "")
        return None

    def delete(self, handle: PolicyHandle) -> None:
        self.gql.execute(DELETE_ACCESS_POLICY, {"id": [int(handle.policy_id)]})

    @contextmanager
    def temporary(self, *args: Any, **kwargs: Any) -> Iterator[PolicyHandle]:
        handle = self.create(*args, **kwargs)
        with _cleanup_guard(self.delete, handle, "ztna access policy"):
            yield handle


class DnsFirewallFactory:
    """DNS Firewall 정책(SIA.network.dns_firewall).

    rules는 웹 정책과 같은 {subject, condition, value} 형태이고, 알려진
    subject는 "FQDN"뿐이다. FQDN 값은 와일드카드(`*.example.com`)를 받는다.
    """

    def __init__(self, gql: GraphQLClient) -> None:
        self.gql = gql

    @staticmethod
    def fqdn_rule(domains: list[str], condition: str = "IS") -> dict:
        return {"subject": "FQDN", "condition": condition, "value": list(domains)}

    def list(self) -> list[dict]:
        return query_rows(
            self.gql,
            ("network", "dns_firewall"),
            fields=[
                "id", "name", "enable", "action_type", "risk_level",
                "event_logging", "rules", "users", "user_groups",
            ],
            cache_key="network.dns_firewall",
        )

    def create(
        self,
        name: str,
        rules: list[dict],
        *,
        action_type: str = "BLOCK",
        risk_level: str = "Major",
        event_logging: bool = True,
        users: list[int] | None = None,
        user_groups: list[int] | None = None,
    ) -> PolicyHandle:
        variables = {
            "name": name,
            "rules": rules,
            "action_type": action_type,
            "risk_level": risk_level,
            "event_logging": event_logging,
            # 0은 전체 사용자를 뜻하고, 빈 리스트는 아무에게도 매칭되지 않는다.
            "users": [0] if users is None else users,
            "user_groups": [0] if user_groups is None else user_groups,
        }
        data = self.gql.execute(CREATE_DNS_FIREWALL, variables)
        policy_id = _nested(data, "SIA", "network", "dns_firewall", "create", "id")
        if not policy_id:
            raise ApiError(f"Created DNS Firewall policy {name} but the response had no id")
        log.info("Created DNS Firewall policy %s (id=%s)", name, policy_id)
        return PolicyHandle(str(policy_id), name, "fwaas", "graphql", variables)

    def delete(self, handle: PolicyHandle) -> None:
        self.gql.execute(DELETE_DNS_FIREWALL, {"id": [int(handle.policy_id)]})

    @contextmanager
    def temporary(self, *args: Any, **kwargs: Any) -> Iterator[PolicyHandle]:
        handle = self.create(*args, **kwargs)
        with _cleanup_guard(self.delete, handle, "dns firewall policy"):
            yield handle


class ApplicationFirewallFactory:
    """Application Firewall 정책(SIA.network.firewall).

    네트워크 주소로만 스코프한다. `subject`는 {source, destination} 단일
    객체이고 둘 다 필수이며, 각각 `ip_address`를 갖는다. source가 비면 아무것도
    매칭되지 않으니 전체는 `0.0.0.0/0`을 쓴다. users/user_groups 인자는 없다.
    선택 항목인 `subject.service`는 `protocol`과 `application` id 리스트를
    받는데, 둘 다 쓸 때 값을 검증하지 않고 포트 필드는 없다. 매칭되면 차단
    페이지를 보여주지 않고 연결을 끊는다.
    """

    TCP = 6
    UDP = 17

    def __init__(self, gql: GraphQLClient) -> None:
        self.gql = gql

    @staticmethod
    def subject(
        *,
        source_ips: list[str] | None = None,
        destination_ips: list[str] | None = None,
        protocol: int | None = None,
    ) -> dict:
        subject: dict[str, Any] = {"source": {}, "destination": {}}
        if source_ips is not None:
            subject["source"]["ip_address"] = list(source_ips)
        if destination_ips is not None:
            subject["destination"]["ip_address"] = list(destination_ips)
        if protocol is not None:
            subject["service"] = {"protocol": protocol}
        return subject

    def list(self) -> list[dict]:
        return query_rows(
            self.gql,
            ("network", "firewall"),
            fields=["id", "name", "enable", "action_type", "risk_level", "event_logging"],
            cache_key="network.firewall",
        )

    def create(
        self,
        name: str,
        subject: dict,
        *,
        action_type: str = "BLOCK",
        risk_level: str = "Major",
        event_logging: bool = True,
    ) -> PolicyHandle:
        variables = {
            "name": name,
            "subject": subject,
            "action_type": action_type,
            "risk_level": risk_level,
            "event_logging": event_logging,
        }
        data = self.gql.execute(CREATE_APPLICATION_FIREWALL, variables)
        policy_id = _nested(data, "SIA", "network", "firewall", "create", "id")
        if not policy_id:
            raise ApiError(f"Created Application Firewall policy {name} but the response had no id")
        log.info("Created Application Firewall policy %s (id=%s)", name, policy_id)
        return PolicyHandle(str(policy_id), name, "fwaas", "graphql", variables)

    def delete(self, handle: PolicyHandle) -> None:
        self.gql.execute(DELETE_APPLICATION_FIREWALL, {"id": [int(handle.policy_id)]})

    @contextmanager
    def temporary(self, *args: Any, **kwargs: Any) -> Iterator[PolicyHandle]:
        handle = self.create(*args, **kwargs)
        with _cleanup_guard(self.delete, handle, "application firewall policy"):
            yield handle


# --- Signature Management ------------------------------------------------

#: 스키마가 받는 pattern_type 값(따옴표 없는 enum 리터럴이어야 하고, 따옴표로
#: 감싼 문자열은 거부된다). Malware에는 목록이 없다.
SIGNATURE_PATTERN_TYPES = ("CNC", "ATP", "PROXY_SERVER", "RISKY_WEBSITE", "ANTI_VIRUS")


class SignaturePatternList:
    """시그니처 모듈(C&C, Risky Website, ...) 뒤에 있는 allow/deny 목록.

    목록은 워크스페이스 전체에 걸리고 mutation이 목록을 통째로 바꾸므로, 쓸
    때마다 새로 읽은 두 목록을 기존 항목을 유지한 채 전부 보내고, 다시 읽어
    확인한다.
    """

    def __init__(self, gql: GraphQLClient) -> None:
        self.gql = gql

    @staticmethod
    def _checked(pattern_type: str) -> str:
        # 쿼리 문자열에 enum 리터럴로 들어가므로 알려진 이름만 허용한다.
        if pattern_type not in SIGNATURE_PATTERN_TYPES:
            raise ValueError(f"Unknown signature pattern type {pattern_type!r}")
        return pattern_type

    def read(self, pattern_type: str) -> tuple[list[str], list[str]]:
        data = self.gql.execute(
            "{ SIA { security { signature_pattern(pattern_type: %s) "
            "{ deny_list allow_list } } } }" % self._checked(pattern_type)
        )
        lists = _nested(data, "SIA", "security", "signature_pattern") or {}
        return list(lists.get("deny_list") or []), list(lists.get("allow_list") or [])

    def _write(self, pattern_type: str, deny: list[str], allow: list[str]) -> None:
        self.gql.execute(
            "mutation { SIA { security { signature_pattern(pattern_type: %s, "
            "pattern_data: {deny_list: %s, allow_list: %s}) { deny_list allow_list } } } }"
            % (self._checked(pattern_type), _as_graphql_literal(deny), _as_graphql_literal(allow))
        )
        got_deny, got_allow = self.read(pattern_type)
        if sorted(got_deny) != sorted(deny) or sorted(got_allow) != sorted(allow):
            raise ApiError(
                f"{pattern_type} signature lists read back as deny={got_deny} "
                f"allow={got_allow}, expected deny={deny} allow={allow}"
            )

    def add_deny(self, pattern_type: str, value: str) -> None:
        deny, allow = self.read(pattern_type)
        if value in deny:
            return
        self._write(pattern_type, deny + [value], allow)
        log.info("Added %s to the %s deny list (kept %s)", value, pattern_type, deny)

    def remove_deny(self, pattern_type: str, value: str) -> None:
        deny, allow = self.read(pattern_type)
        if value not in deny:
            return
        self._write(pattern_type, [entry for entry in deny if entry != value], allow)
        log.info("Removed %s from the %s deny list", value, pattern_type)

    @contextmanager
    def temporary_deny(self, pattern_type: str, value: str) -> Iterator[PolicyHandle]:
        """본문이 도는 동안 `value`를 deny 목록에 두고, 빠져나갈 때 뺀다.

        호출하는 쪽이 BAT 전용 값(testdata.SIGNATURE_TARGET_HOST)을 넘기므로,
        원래 있던 값이어도 뺀다.
        """
        self.add_deny(pattern_type, value)
        handle = PolicyHandle(value, f"{pattern_type} deny {value}", "swg", "graphql")
        with _cleanup_guard(lambda _: self.remove_deny(pattern_type, value), handle, "signature entry"):
            yield handle
