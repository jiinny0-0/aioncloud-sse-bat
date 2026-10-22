"""In-App Control과 SaaS Access가 함께 쓰는 CASB 보안 로그(SIA.log.casb_security_log).

필드 이름이 네트워크 로그와 다르다. `policy_id`/`policy_name`이 없고, 정책 이름은
`rule_name`에 있으며, 매칭된 앱은 `in_app_service { id name }`에 있다
(`in_app_name`/`in_app_func`는 비어 있다). 스키마에 카탈로그 목록이 없어서 이 행들이
앱-id 매핑의 유일한 출처다(testdata.CASB_SAAS_APPS 참조). `saas_desc_id: 1`은 특정
앱이 아니라 "전체 앱" 센티널이다.
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

CANDIDATE_FIELDS = [
    "id", "action", "rule_name", "time", "user_id", "user_name",
    "src_ip", "device_id", "request_uri", "in_app_service", "in_app_name",
    "in_app_func",
]
NESTED_FIELDS = {
    "in_app_service": "id name",
    "in_app_name": "id name",
    "in_app_func": "id name",
}

_MISSING_FIELD_RE = re.compile(r'Cannot query field "([^"]+)" on type')
_NEEDS_SELECTION_RE = re.compile(r'Field "([^"]+)" of type "[^"]+" must have a sub selection')

_ACCEPTED_FIELDS: dict[str, str] | None = None

DEFAULT_LOOKBACK_MIN = 10


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _render(selection: dict[str, str]) -> str:
    return " ".join(
        name if not sub else f"{name} {{ {sub} }}" for name, sub in selection.items()
    )


def _build_query(selection: dict[str, str]) -> str:
    return f"""
query BatCasbLog($begin_time: DateTime!, $end_time: DateTime!) {{
  SIA {{ log {{ casb_security_log(begin_time: $begin_time, end_time: $end_time) {{
    log_list {{ {_render(selection)} }}
  }} }} }}
}}
"""


class CasbLogReader:
    def __init__(self, gql: GraphQLClient) -> None:
        self.gql = gql

    def _execute(self, variables: dict[str, Any]) -> dict[str, Any]:
        global _ACCEPTED_FIELDS
        selection: dict[str, str] = dict(
            _ACCEPTED_FIELDS if _ACCEPTED_FIELDS is not None
            else {name: "" for name in CANDIDATE_FIELDS}
        )
        for _ in range(2 * len(CANDIDATE_FIELDS)):
            if not selection:
                raise ApiError("No usable fields remain for casb_security_log")
            try:
                data = self.gql.execute(_build_query(selection), variables)
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
                log.info("casb_security_log selection adjusted to: %s", _render(selection))
                continue

            _ACCEPTED_FIELDS = selection
            return data

        raise ApiError("Could not find a workable field set for casb_security_log")

    def events(self, lookback_min: int = DEFAULT_LOOKBACK_MIN) -> list[SecurityEvent]:
        now = datetime.now(timezone.utc)
        variables = {
            "begin_time": _iso(now - timedelta(minutes=lookback_min)),
            "end_time": _iso(now + timedelta(minutes=1)),
        }
        data = self._execute(variables)
        node = ((data.get("SIA") or {}).get("log") or {}).get("casb_security_log") or {}
        rows = node.get("log_list") or []
        return [
            SecurityEvent(event_id=str(row.get("id") or ""), source="casb-security-log", raw=row)
            for row in rows
            if isinstance(row, dict)
        ]

    def wait_for_event(
        self,
        match: Callable[[SecurityEvent], bool],
        *,
        timeout_sec: float = 30.0,
        description: str = "casb security event",
        lookback_min: int = DEFAULT_LOOKBACK_MIN,
    ) -> SecurityEvent:
        def probe() -> SecurityEvent | None:
            for event in self.events(lookback_min):
                if match(event):
                    return event
            return None

        return poll_until(probe, timeout_sec=timeout_sec, description=description)


def matches_rule(rule_name: str) -> Callable[[SecurityEvent], bool]:
    """rule_name이 정확히 일치하는 행과 매칭한다(rule_name은 정책 이름이다. 이 로그에는 policy_id가 없다)."""

    def predicate(event: SecurityEvent) -> bool:
        value = event.get("rule_name")
        return value is not None and str(value).strip() == rule_name

    return predicate


def in_app_service_name(event: SecurityEvent) -> str:
    service = event.get("in_app_service") or {}
    return str(service.get("name") or "") if isinstance(service, dict) else ""


def in_app_service_id(event: SecurityEvent) -> int | None:
    service = event.get("in_app_service") or {}
    value = service.get("id") if isinstance(service, dict) else None
    return int(value) if value is not None else None
