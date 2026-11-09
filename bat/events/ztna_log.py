"""ZTNA 접근 로그(SIA.log.service_security_log).

행마다 매칭된 접근제어와 접근정책의 id·이름, 목적지(`dst_ip`는 "<ip>:<port>"),
단말(device_id), 동작(AP_LOGGING / AP_BLOCK)이 있다. 접근정책이 연결되지 않은
접근제어는 행을 남기지 않는 것으로 보인다.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from bat.clients.graphql import GraphQLClient
from bat.events.poller import poll_until
from bat.models import SecurityEvent

QUERY = """
query BatZtnaServiceLog($begin_time: DateTime!, $end_time: DateTime!) {
  SIA { log { service_security_log(begin_time: $begin_time, end_time: $end_time) {
    log_list {
      id time action src_ip dst_ip user_name device_id app_protocol
      access_control_id access_control_name access_policy_id access_policy_name
    }
  } } }
}
"""


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ZtnaLogReader:
    def __init__(self, gql: GraphQLClient) -> None:
        self.gql = gql

    def events(self, *, since: datetime) -> list[SecurityEvent]:
        """since(1분 여유를 둠)부터 지금까지의 행."""
        now = datetime.now(timezone.utc)
        variables: dict[str, Any] = {
            "begin_time": _iso(since - timedelta(minutes=1)),
            "end_time": _iso(now + timedelta(minutes=1)),
        }
        data = self.gql.execute(QUERY, variables)
        node = ((data.get("SIA") or {}).get("log") or {}).get("service_security_log") or {}
        return [
            SecurityEvent(event_id=str(row.get("id") or ""), source="ztna-log", raw=row)
            for row in node.get("log_list") or []
            if isinstance(row, dict)
        ]

    def wait_for(
        self,
        match: Callable[[SecurityEvent], bool],
        *,
        since: datetime,
        timeout_sec: float = 60.0,
        description: str = "ZTNA access log row",
    ) -> SecurityEvent:
        def probe() -> SecurityEvent | None:
            return next((event for event in self.events(since=since) if match(event)), None)

        return poll_until(probe, timeout_sec=timeout_sec, description=description)


def matches_access(
    *,
    access_control: str,
    action: str,
    destination: str,
    access_policy: str = "",
    device_id: str = "",
) -> Callable[[SecurityEvent], bool]:
    """그 접근제어(이름 정확히 일치)와 동작, 목적지("<ip>:<port>")의 행. destination이 비면 목적지는 보지 않는다."""

    def predicate(event: SecurityEvent) -> bool:
        raw = event.raw
        if raw.get("access_control_name") != access_control or raw.get("action") != action:
            return False
        if access_policy and raw.get("access_policy_name") != access_policy:
            return False
        if destination and str(raw.get("dst_ip") or "") != destination:
            return False
        if device_id and str(raw.get("device_id") or "").upper() != device_id.upper():
            return False
        return True

    return predicate
