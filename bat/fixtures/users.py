"""사용자·사용자 그룹 팩토리.

정책은 사용자 단위로 스코프되므로, 스코핑을 증명하려는 케이스는 대상 사용자를
직접 소유해야 한다. 이 사용자는 BAT 접두사를 달고 케이스마다 만들고 지우므로,
실패한 실행이 진짜처럼 보이는 계정을 남길 수 없다.
"""
from __future__ import annotations

import logging
import secrets
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator

from bat.clients.errors import ApiError
from bat.clients.rest import RestClient, pick_id
from bat.fixtures.policies import _cleanup_guard

log = logging.getLogger(__name__)

USER_PATH = "/sia/v1/user"
USER_GROUP_PATH = "/sia/v1/user/group"


@dataclass
class UserHandle:
    user_id: str
    login_id: str
    name: str
    policy_id: str = ""  # _cleanup_guard가 다른 리소스처럼 로그에 남길 수 있게

    def __post_init__(self) -> None:
        self.policy_id = self.user_id


def _password() -> str:
    """케이스 하나용 계정에 쓰고 버리는 비밀번호. 로그나 리포트에 절대 남기지 않는다."""
    return f"Bat!{secrets.token_urlsafe(12)}9aA"


class UserFactory:
    def __init__(self, rest: RestClient) -> None:
        self.rest = rest

    def create(
        self,
        login_id: str,
        *,
        first_name: str = "BAT",
        last_name: str = "Tester",
        role: str = "USER",
        user_groups: list[int] | None = None,
        description: str = "",
    ) -> UserHandle:
        body: dict[str, Any] = {
            "login_id": login_id,
            "first_name": first_name,
            "last_name": last_name,
            "password": _password(),
            "role": role,
            "description": description or "created by BAT, safe to delete",
        }
        if user_groups:
            body["user_groups"] = user_groups

        try:
            payload = self.rest.post(USER_PATH, json=body)
        except ApiError as exc:
            if exc.status_code == 500:
                raise ApiError(
                    f"POST {USER_PATH} returned 500 for login_id={login_id!r}. "
                    f"The request matches the documented schema, so this is either a "
                    f"server-side defect worth reporting or a field the spec omits. "
                    f"Compare with a user created in the console: "
                    f"'bat inspect' has no user view yet, so read one from "
                    f"GET /sia/v1/user/all.",
                    status_code=500,
                    body=exc.body,
                ) from exc
            raise

        user_id = pick_id(payload, "user_id", "id")
        if not user_id:
            user_id = self.find_id_by_login(login_id)
        if not user_id:
            raise ApiError(f"Created user {login_id} but could not resolve its id")

        log.info("Created user %s (id=%s)", login_id, user_id)
        return UserHandle(user_id=str(user_id), login_id=login_id, name=f"{first_name} {last_name}")

    def find_id_by_login(self, login_id: str) -> str | None:
        payload = self.rest.get(f"{USER_PATH}/all", params={"offset": 1, "limit": 500})
        for row in _rows(payload):
            if str(row.get("login_id", "")).lower() == login_id.lower():
                return str(row.get("id") or row.get("user_id") or "")
        return None

    def find_by_id(self, user_id: str | int) -> dict | None:
        try:
            return self.rest.get(f"{USER_PATH}/{user_id}")
        except ApiError:
            return None

    def delete(self, handle: UserHandle) -> None:
        self.rest.delete(f"{USER_PATH}/{handle.user_id}")

    @contextmanager
    def temporary(self, *args: Any, **kwargs: Any) -> Iterator[UserHandle]:
        handle = self.create(*args, **kwargs)
        with _cleanup_guard(self.delete, handle, "user"):
            yield handle


class UserGroupFactory:
    def __init__(self, rest: RestClient) -> None:
        self.rest = rest

    def create(self, name: str, users: list[int] | None = None, description: str = ""):
        body: dict[str, Any] = {
            "name": name,
            "description": description or "created by BAT, safe to delete",
        }
        if users:
            body["users"] = users

        payload = self.rest.post(USER_GROUP_PATH, json=body)
        group_id = pick_id(payload, "group_id", "id")
        if not group_id:
            listing = self.rest.get(f"{USER_GROUP_PATH}/list", params={"offset": 1, "limit": 500})
            for row in _rows(listing):
                if row.get("name") == name:
                    group_id = str(row.get("id") or "")
                    break
        if not group_id:
            raise ApiError(f"Created user group {name} but could not resolve its id")

        log.info("Created user group %s (id=%s)", name, group_id)
        return UserHandle(user_id=str(group_id), login_id=name, name=name)

    def set_members(self, group_id: str | int, user_ids: list[int]) -> None:
        self.rest.patch(f"{USER_GROUP_PATH}/{group_id}/user", json={"users": user_ids})

    def delete(self, handle: UserHandle) -> None:
        self.rest.delete(USER_GROUP_PATH, json={"ids": [int(handle.user_id)]})

    @contextmanager
    def temporary(self, *args: Any, **kwargs: Any) -> Iterator[UserHandle]:
        handle = self.create(*args, **kwargs)
        with _cleanup_guard(self.delete, handle, "user group"):
            yield handle


def _rows(payload: Any) -> list[dict]:
    if isinstance(payload, dict):
        for key in ("users", "items", "list", "data", "groups"):
            value = payload.get(key)
            if isinstance(value, list):
                return [row for row in value if isinstance(row, dict)]
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    return []
