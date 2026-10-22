"""DNS Firewall과 Application Firewall 보안 로그.

GraphQL SIA.log.dns_security_log / firewall_security_log에서 읽는다. 이 이벤트는
REST 웹 보안 로그에 없다. 행은 `log_list` 아래에 있다.
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

# 두 로그 필드의 합집합이다. dst_ip/dst_country_code는 firewall_security_log에만,
# record_type/categories는 dns_security_log에만 있다. 모르는 필드는 _execute에서
# 로그마다 필드를 줄여 나가며 뺀다.
CANDIDATE_FIELDS = [
    "id", "action", "policy_id", "policy_name", "time", "user_id", "user_name",
    "src_ip", "src_country_code", "dst_ip", "dst_country_code", "device_id",
    "record_type", "categories",
]
NESTED_FIELDS = {"categories": "id name"}

_MISSING_FIELD_RE = re.compile(r'Cannot query field "([^"]+)" on type')
_NEEDS_SELECTION_RE = re.compile(r'Field "([^"]+)" of type "[^"]+" must have a sub selection')

_ACCEPTED_FIELDS: dict[str, dict[str, str]] = {}

DEFAULT_LOOKBACK_MIN = 10


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _render(selection: dict[str, str]) -> str:
    return " ".join(
        name if not sub else f"{name} {{ {sub} }}" for name, sub in selection.items()
    )


def _build_query(log_field: str, selection: dict[str, str]) -> str:
    return f"""
query BatNetworkLog($begin_time: DateTime!, $end_time: DateTime!) {{
  SIA {{ log {{ {log_field}(begin_time: $begin_time, end_time: $end_time) {{
    log_list {{ {_render(selection)} }}
  }} }} }}
}}
"""


class NetworkLogReader:
    def __init__(self, gql: GraphQLClient) -> None:
        self.gql = gql

    def _execute(self, log_field: str, variables: dict[str, Any]) -> dict[str, Any]:
        selection: dict[str, str] = dict(
            _ACCEPTED_FIELDS.get(log_field) or {name: "" for name in CANDIDATE_FIELDS}
        )
        for _ in range(2 * len(CANDIDATE_FIELDS)):
            if not selection:
                raise ApiError(f"No usable fields remain for {log_field}")
            try:
                data = self.gql.execute(_build_query(log_field, selection), variables)
            except ApiError as exc:
                message = str(exc)
                unknown = set(_MISSING_FIELD_RE.findall(message))
                needs_selection = set(_NEEDS_SELECTION_RE.findall(message))
                changed = False
                for name in unknown:
                    if name in selection:
                        del selection[name]
                        changed = True
                for name in needs_selection:
                    if selection.get(name) == "":
                        selection[name] = NESTED_FIELDS.get(name, "id name")
                        changed = True
                    elif name in selection:
                        del selection[name]
                        changed = True
                if not changed:
                    raise
                log.info("%s selection adjusted to: %s", log_field, _render(selection))
                continue

            _ACCEPTED_FIELDS[log_field] = selection
            return data

        raise ApiError(f"Could not find a workable field set for {log_field}")

    def _events(self, log_field: str, source: str, lookback_min: int) -> list[SecurityEvent]:
        now = datetime.now(timezone.utc)
        variables = {
            "begin_time": _iso(now - timedelta(minutes=lookback_min)),
            "end_time": _iso(now + timedelta(minutes=1)),
        }
        data = self._execute(log_field, variables)
        node = ((data.get("SIA") or {}).get("log") or {}).get(log_field) or {}
        rows = node.get("log_list") or []
        return [
            SecurityEvent(event_id=str(row.get("id") or ""), source=source, raw=row)
            for row in rows
            if isinstance(row, dict)
        ]

    def dns_events(self, lookback_min: int = DEFAULT_LOOKBACK_MIN) -> list[SecurityEvent]:
        return self._events("dns_security_log", "dns-security-log", lookback_min)

    def firewall_events(self, lookback_min: int = DEFAULT_LOOKBACK_MIN) -> list[SecurityEvent]:
        return self._events("firewall_security_log", "firewall-security-log", lookback_min)

    def wait_for_dns_event(
        self,
        match: Callable[[SecurityEvent], bool],
        *,
        timeout_sec: float = 30.0,
        description: str = "dns security event",
        lookback_min: int = DEFAULT_LOOKBACK_MIN,
    ) -> SecurityEvent:
        def probe() -> SecurityEvent | None:
            for event in self.dns_events(lookback_min):
                if match(event):
                    return event
            return None

        return poll_until(probe, timeout_sec=timeout_sec, description=description)

    def wait_for_firewall_event(
        self,
        match: Callable[[SecurityEvent], bool],
        *,
        timeout_sec: float = 30.0,
        description: str = "firewall security event",
        lookback_min: int = DEFAULT_LOOKBACK_MIN,
    ) -> SecurityEvent:
        def probe() -> SecurityEvent | None:
            for event in self.firewall_events(lookback_min):
                if match(event):
                    return event
            return None

        return poll_until(probe, timeout_sec=timeout_sec, description=description)


def matches_policy(policy_name: str) -> Callable[[SecurityEvent], bool]:
    """policy_name이 정확히 일치하는 행과 매칭한다.

    부분 문자열로는 같은 케이스 이름을 딴 형제 정책까지 매칭된다.
    """

    def predicate(event: SecurityEvent) -> bool:
        value = event.get("policy_name")
        return value is not None and str(value).strip() == policy_name

    return predicate
