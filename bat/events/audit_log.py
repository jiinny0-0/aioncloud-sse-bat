"""관리자 조작 감사 로그(SIA.log.audit_log).

커넥터 인증 로그(auth_log.py 참조)가 아니다. 행은 콘솔·API 조작을 기록하고,
`content`에 생성되거나 삭제된 리소스가 JSON으로 들어 있다. 행의 `policy_id`는
건드린 리소스의 id가 아니라 같은 종류의 모든 조작이 공유하는 기능 태그라서,
어느 리소스의 행인지는 `content` 안의 리소스 이름으로 가린다.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Callable

from bat.clients.graphql import GraphQLClient
from bat.events.poller import poll_until
from bat.models import SecurityEvent

log = logging.getLogger(__name__)

QUERY = """
query BatAuditLog($begin_time: DateTime!, $end_time: DateTime!) {
  SIA { log { audit_log(begin_time: $begin_time, end_time: $end_time) {
    log_list { id time email content policy_id behavior_id }
  } } }
}
"""

DEFAULT_LOOKBACK_MIN = 10


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class AuditLogReader:
    def __init__(self, gql: GraphQLClient) -> None:
        self.gql = gql

    def events(self, *, lookback_min: int = DEFAULT_LOOKBACK_MIN) -> list[SecurityEvent]:
        now = datetime.now(timezone.utc)
        variables = {
            "begin_time": _iso(now - timedelta(minutes=lookback_min)),
            "end_time": _iso(now + timedelta(minutes=1)),
        }
        data = self.gql.execute(QUERY, variables)
        node = ((data.get("SIA") or {}).get("log") or {}).get("audit_log") or {}
        rows = node.get("log_list") or []
        return [
            SecurityEvent(event_id=str(row.get("id") or ""), source="audit-log", raw=row)
            for row in rows
            if isinstance(row, dict)
        ]

    def wait_for(
        self,
        match: Callable[[SecurityEvent], bool],
        *,
        timeout_sec: float = 30.0,
        description: str = "audit log entry",
        **query_kwargs,
    ) -> SecurityEvent:
        def probe() -> SecurityEvent | None:
            for event in self.events(**query_kwargs):
                if match(event):
                    return event
            return None

        return poll_until(probe, timeout_sec=timeout_sec, description=description)


def matches_resource_name(name: str) -> Callable[[SecurityEvent], bool]:
    """`content`에 정확히 `"name":"<name>"` 쌍이 든 행과 매칭한다.

    단순 부분 문자열로는 이 이름 뒤에 뭔가를 덧붙인 형제 리소스(예: `-probe` 접미사)도
    매칭된다. content가 유효한 JSON이 아닌 행도 매칭되도록 정규식을 쓴다.
    """
    pattern = re.compile(r'"name"\s*:\s*"' + re.escape(name) + '"')

    def predicate(event: SecurityEvent) -> bool:
        return bool(pattern.search(str(event.get("content") or "")))

    return predicate
