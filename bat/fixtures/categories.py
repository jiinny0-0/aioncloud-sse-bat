"""커스텀 HTTP 카테고리와 user rule 팩토리.

커스텀 카테고리는 빈 통이고, 거기 속하는 URL은 user rule로 따로 선언한다.
그다음 SWG 정책이 HTTP_CATEGORY로 매칭하므로, 카테고리 케이스는 세 가지가
동시에 모두 살아 있어야 한다.
"""
from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Any, Iterator

from bat.clients.errors import ApiError
from bat.clients.rest import RestClient, pick_id
from bat.fixtures.policies import PolicyHandle, _cleanup_guard

log = logging.getLogger(__name__)

CUSTOM_CATEGORY_PATH = "/sia/v1/web/http_category/custom"
USER_RULE_PATH = "/sia/v1/web/http_category/user_rule"
CATEGORY_LIST_PATH = "/sia/v1/web/http_category/list"


class CustomCategoryFactory:
    def __init__(self, rest: RestClient) -> None:
        self.rest = rest

    def create(self, name: str, description: str = "") -> PolicyHandle:
        body = {"name": name, "description": description or f"BAT custom category {name}"}
        payload = self.rest.post(CUSTOM_CATEGORY_PATH, json=body)
        category_id = pick_id(payload, "id", "category_id")
        if not category_id:
            category_id = self._find_id_by_name(name)
        if not category_id:
            raise ApiError(f"Created custom category {name} but could not resolve its id")
        log.info("Created custom category %s (id=%s)", name, category_id)
        return PolicyHandle(category_id, name, "swg", "rest", body)

    def _find_id_by_name(self, name: str) -> str | None:
        payload = self.rest.get(CUSTOM_CATEGORY_PATH, params={"offset": 1, "limit": 200})
        for row in payload.get("items") or []:
            if isinstance(row, dict) and row.get("name") == name:
                return str(row.get("id") or "")
        return None

    def delete(self, handle: PolicyHandle) -> None:
        self.rest.delete(
            CUSTOM_CATEGORY_PATH, json={"category_ids": [int(handle.policy_id)]}
        )

    @contextmanager
    def temporary(self, *args: Any, **kwargs: Any) -> Iterator[PolicyHandle]:
        handle = self.create(*args, **kwargs)
        with _cleanup_guard(self.delete, handle, "custom category"):
            yield handle

    def find_default_category(self, name_contains: str) -> dict | None:
        """기본 제공 카테고리를 이름(부분 일치)으로 찾는다.

        이름은 현지화돼 있으므로, 호출하는 쪽은 테넌트의 언어 설정에 나타나는
        문자열을 넘겨야 한다.
        """
        payload = self.rest.get(CATEGORY_LIST_PATH)
        buckets = payload if isinstance(payload, dict) else {}
        for key in ("default", "defined", "items"):
            for row in buckets.get(key) or []:
                if isinstance(row, dict) and name_contains.lower() in str(row.get("name", "")).lower():
                    return row
        return None


class UserRuleFactory:
    """어떤 URL이 카테고리에 속하는지 선언한다."""

    def __init__(self, rest: RestClient) -> None:
        self.rest = rest

    @staticmethod
    def rule(value: str, rule_type: str = "host", condition: str = "apply") -> dict:
        return {"type": rule_type, "condition": condition, "value": value}

    def create(self, category_id: str | int, rules: list[dict], description: str = "") -> PolicyHandle:
        body = {
            "category_id": int(category_id),
            "rules": rules,
            "description": description or "BAT category user rule",
        }
        payload = self.rest.post(USER_RULE_PATH, json=body)
        rule_id = pick_id(payload, "id", "rule_id")
        if not rule_id:
            listing = self.rest.get(USER_RULE_PATH, params={"offset": 1, "limit": 200})
            for row in listing.get("items") or []:
                if isinstance(row, dict) and row.get("category_id") == int(category_id):
                    rule_id = str(row.get("id") or "")
                    break
        if not rule_id:
            raise ApiError(f"Created user rule for category {category_id} but found no id")
        log.info("Created category user rule (id=%s) for category %s", rule_id, category_id)
        return PolicyHandle(rule_id, f"user-rule-{category_id}", "swg", "rest", body)

    def delete(self, handle: PolicyHandle) -> None:
        self.rest.delete(USER_RULE_PATH, json={"rule_ids": [int(handle.policy_id)]})

    @contextmanager
    def temporary(self, *args: Any, **kwargs: Any) -> Iterator[PolicyHandle]:
        handle = self.create(*args, **kwargs)
        with _cleanup_guard(self.delete, handle, "category user rule"):
            yield handle
