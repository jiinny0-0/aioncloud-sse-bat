"""커넥터 인증 로그(SIA.log.auth_log).

행에 device_id와 src_ip가 있어서, 인증 이벤트가 어느 단말에서 나왔는지 가릴 수
있다.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from bat.clients.errors import ApiError
from bat.clients.graphql import GraphQLClient
from bat.events.poller import poll_until
from bat.models import SecurityEvent

log = logging.getLogger(__name__)

# introspection이 차단돼 있어서, 쿼리는 이 후보들로 시작해 서버가 거부하는 필드를
# 뺀다. 받아들여진 필드 집합은 실행 동안 캐시한다.
CANDIDATE_FIELDS = [
    "id",
    "time",
    "user_id",
    "user_name",
    "login_id",
    "client_ip",
    "src_ip",
    "auth_result",
    "result",
    "device_id",
    "device_type",
    "platform",
    "os",
    "browser",
    "user_agent",
]

_ACCEPTED_FIELDS: list[str] | None = None
_MISSING_FIELD_RE = re.compile(r'Cannot query field "([^"]+)" on type "authLogList"')


def _build_query(fields: list[str]) -> str:
    selection = "\n      ".join(fields)
    return f"""
query BatAuthLog(
  $begin_time: DateTime!, $end_time: DateTime!, $offset: Int!, $limit: Int!,
  $user_ids: [Int], $src_ip: String, $device_id: String
) {{
  SIA {{ log {{ auth_log(
    begin_time: $begin_time, end_time: $end_time, offset: $offset, limit: $limit,
    user_ids: $user_ids, src_ip: $src_ip, device_id: $device_id
  ) {{
    log_count
    log_list {{
      {selection}
    }}
  }} }} }}
}}
"""


PAGE_LIMIT = 100
DEFAULT_LOOKBACK_MIN = 10


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class AuthLogReader:
    def __init__(self, gql: GraphQLClient) -> None:
        self.gql = gql

    def _execute(self, variables: dict[str, Any]) -> dict[str, Any]:
        """서버가 받아들일 때까지 필드 목록을 줄여 가며 쿼리를 실행한다."""
        global _ACCEPTED_FIELDS

        fields = list(_ACCEPTED_FIELDS or CANDIDATE_FIELDS)
        for _ in range(len(CANDIDATE_FIELDS)):
            try:
                data = self.gql.execute(_build_query(fields), variables)
            except ApiError as exc:
                rejected = set(_MISSING_FIELD_RE.findall(str(exc)))
                remaining = [name for name in fields if name not in rejected]
                if not rejected or not remaining or remaining == fields:
                    raise
                log.info("auth_log does not expose %s; retrying without", sorted(rejected))
                fields = remaining
                continue

            if _ACCEPTED_FIELDS != fields:
                _ACCEPTED_FIELDS = fields
                log.info("auth_log fields in use: %s", fields)
            return data

        raise ApiError("Could not find a workable field set for auth_log")

    def events(
        self,
        *,
        lookback_min: int = DEFAULT_LOOKBACK_MIN,
        device_id: str = "",
        src_ip: str = "",
        user_ids: list[int] | None = None,
    ) -> list[SecurityEvent]:
        now = datetime.now(timezone.utc)
        variables: dict[str, Any] = {
            "begin_time": _iso(now - timedelta(minutes=lookback_min)),
            "end_time": _iso(now + timedelta(minutes=1)),
            "offset": 0,
            "limit": PAGE_LIMIT,
        }
        if device_id:
            variables["device_id"] = device_id
        if src_ip:
            variables["src_ip"] = src_ip
        if user_ids:
            variables["user_ids"] = user_ids

        data = self._execute(variables)
        node = ((data.get("SIA") or {}).get("log") or {}).get("auth_log") or {}
        rows = node.get("log_list") or []
        return [
            SecurityEvent(
                event_id=str(row.get("id") or row.get("log_id") or ""),
                source="auth-log",
                raw=row,
            )
            for row in rows
            if isinstance(row, dict)
        ]

    def wait_for(
        self,
        match: Callable[[SecurityEvent], bool],
        *,
        timeout_sec: float = 30.0,
        description: str = "auth event",
        **query_kwargs: Any,
    ) -> SecurityEvent:
        def probe() -> SecurityEvent | None:
            for event in self.events(**query_kwargs):
                if match(event):
                    return event
            return None

        return poll_until(probe, timeout_sec=timeout_sec, description=description)


def matches_login(login_id: str) -> Callable[[SecurityEvent], bool]:
    def predicate(event: SecurityEvent) -> bool:
        value = event.get("login_id", "user_name", "user")
        return bool(value) and login_id.lower() in str(value).lower()

    return predicate


def matches_result(expected: str) -> Callable[[SecurityEvent], bool]:
    """expected는 보통 'success' 또는 'fail'이다."""

    def predicate(event: SecurityEvent) -> bool:
        value = event.get("auth_result", "result", "result_flag")
        return bool(value) and expected.lower() in str(value).lower()

    return predicate
