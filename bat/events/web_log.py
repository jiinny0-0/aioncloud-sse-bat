"""웹 보안 로그 조회(SWG, DLP, CASB, GenAI 트래픽).

GraphQL SIA.log.web_security_log에서 읽는다. 이 로그는 REST
/sia/v1/log/security/web 엔드포인트와 같은 데이터·필드 이름을 담고 있다.
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

DEFAULT_LOOKBACK_MIN = 10

# 하위 선택(sub-selection)이 필요한 필드는 `categories`뿐이다.
CANDIDATE_FIELDS = [
    "id", "action", "policy_id", "policy_name", "time", "user_id", "user_name",
    "device_id", "src_ip", "src_country_code", "full_uri", "reason", "categories",
    "detect_count", "file_name", "file_action", "file_hash", "transaction_id",
    "dst_ip", "dst_country_code", "browser",
]
NESTED_FIELDS = {"categories": "id name"}

_MISSING_FIELD_RE = re.compile(r'Cannot query field "([^"]+)" on type')
_NEEDS_SELECTION_RE = re.compile(r'Field "([^"]+)" of type "[^"]+" must have a sub selection')

_ACCEPTED_FIELDS: dict[str, str] | None = None


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _render(selection: dict[str, str]) -> str:
    return " ".join(
        name if not sub else f"{name} {{ {sub} }}" for name, sub in selection.items()
    )


def _rows(data: dict[str, Any], field: str) -> list[dict]:
    node = ((data.get("SIA") or {}).get("log") or {}).get(field) or {}
    return [row for row in (node.get("log_list") or []) if isinstance(row, dict)]


class WebLogReader:
    def __init__(self, console: GraphQLClient) -> None:
        self.console = console

    def _selection(self) -> dict[str, str]:
        """서버가 받아들이는 필드 선택을 반환한다. 프로세스 전체에서 캐시한다."""
        global _ACCEPTED_FIELDS
        if _ACCEPTED_FIELDS is not None:
            return dict(_ACCEPTED_FIELDS)

        selection: dict[str, str] = {name: "" for name in CANDIDATE_FIELDS}
        now = datetime.now(timezone.utc)
        variables = {
            "b": _iso(now - timedelta(minutes=DEFAULT_LOOKBACK_MIN)),
            "e": _iso(now + timedelta(minutes=1)),
        }
        for _ in range(2 * len(CANDIDATE_FIELDS)):
            if not selection:
                raise ApiError("No usable fields remain for web_security_log")
            query = f"""
            query($b: DateTime!, $e: DateTime!) {{
              SIA {{ log {{ web_security_log(begin_time: $b, end_time: $e) {{
                log_list {{ {_render(selection)} }}
              }} }} }}
            }}
            """
            try:
                self.console.execute(query, variables)
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
                log.info("web_security_log selection adjusted to: %s", _render(selection))
                continue

            _ACCEPTED_FIELDS = dict(selection)
            return dict(selection)

        raise ApiError("Could not find a workable field set for web_security_log")

    def security_events(self, lookback_min: int = DEFAULT_LOOKBACK_MIN) -> list[SecurityEvent]:
        selection = self._selection()
        now = datetime.now(timezone.utc)
        variables = {
            "b": _iso(now - timedelta(minutes=lookback_min)),
            "e": _iso(now + timedelta(minutes=1)),
        }
        query = f"""
        query($b: DateTime!, $e: DateTime!) {{
          SIA {{ log {{ web_security_log(begin_time: $b, end_time: $e) {{
            log_list {{ {_render(selection)} }}
          }} }} }}
        }}
        """
        data = self.console.execute(query, variables)
        return [
            SecurityEvent(event_id=str(row.get("id") or ""), source="security-log", raw=row)
            for row in _rows(data, "web_security_log")
        ]

    def event_detail(self, event_id: str) -> dict:
        selection = self._selection()
        query = f"""
        query($id: Int!) {{
          SIA {{ log {{ web_security_log_by_id(id: $id) {{
            log_list {{ {_render(selection)} }}
          }} }} }}
        }}
        """
        data = self.console.execute(query, {"id": int(event_id)})
        rows = _rows(data, "web_security_log_by_id")
        return rows[0] if rows else {}

    def wait_for_security_event(
        self,
        match: Callable[[SecurityEvent], bool],
        *,
        timeout_sec: float = 30.0,
        description: str = "security event",
        lookback_min: int = DEFAULT_LOOKBACK_MIN,
    ) -> SecurityEvent:
        def probe() -> SecurityEvent | None:
            for event in self.security_events(lookback_min):
                if match(event):
                    return event
            return None

        return poll_until(probe, timeout_sec=timeout_sec, description=description)

    def no_security_event(
        self,
        match: Callable[[SecurityEvent], bool],
        *,
        settle_sec: float = 8.0,
        lookback_min: int = DEFAULT_LOOKBACK_MIN,
    ) -> bool:
        """로그 기록 지연만큼 기다린 뒤 매칭되는 이벤트가 없으면 True를 반환한다."""
        import time

        time.sleep(settle_sec)
        return not any(match(event) for event in self.security_events(lookback_min))


def matches_policy(
    policy_name: str, policy_id: str | int | None = None
) -> Callable[[SecurityEvent], bool]:
    """policy_name이 정확히 일치하는 행과 매칭하고, policy_id가 주어지면 그것도 맞춘다.

    부분 문자열이 아니라 정확히 일치시킨다. probe 정책은 케이스 이름을 그대로 따서
    짓기 때문에(예: `-idprobe` 접미사) 부분 문자열로는 그 이벤트까지 매칭된다.
    로그의 `policy_id`는 생성한 정책의 id다.
    """

    def predicate(event: SecurityEvent) -> bool:
        value = event.get("policy_name")
        if value is None or str(value).strip() != policy_name:
            return False
        return policy_id is None or str(event.get("policy_id")) == str(policy_id)

    return predicate


def matches_policy_id(policy_id: str | int) -> Callable[[SecurityEvent], bool]:
    """이름 매칭보다 강하다. id는 실행 간에 겹칠 수 없다."""

    def predicate(event: SecurityEvent) -> bool:
        value = event.get("policy_id")
        return value is not None and str(value) == str(policy_id)

    return predicate


def matches_target(target: str) -> Callable[[SecurityEvent], bool]:
    """요청한 리소스와 매칭한다.

    레코드는 요청을 full_uri로 보여 주므로, 호스트만 주어지면 별도의 호스트 필드가
    아니라 full_uri의 부분 문자열로 확인한다.
    """
    needle = target.lower().removeprefix("https://").removeprefix("http://").rstrip("/")

    def predicate(event: SecurityEvent) -> bool:
        value = event.get("full_uri")
        return bool(value) and needle in str(value).lower()

    return predicate


def matches_action(action: str) -> Callable[[SecurityEvent], bool]:
    """action은 BLOCK / LOGGING / REWRITE 같은 값이다."""

    def predicate(event: SecurityEvent) -> bool:
        value = event.get("action")
        return bool(value) and action.upper() == str(value).upper()

    return predicate


def matches_user(user_name: str) -> Callable[[SecurityEvent], bool]:
    def predicate(event: SecurityEvent) -> bool:
        value = event.get("user_name")
        return bool(value) and user_name.lower() in str(value).lower()

    return predicate


def matches_device(device_id: str) -> Callable[[SecurityEvent], bool]:
    """이벤트가 어느 단말에서 나왔는지 가린다."""

    def predicate(event: SecurityEvent) -> bool:
        value = event.get("device_id")
        return bool(value) and str(value) == device_id

    return predicate


def all_of(*predicates: Callable[[SecurityEvent], bool]) -> Callable[[SecurityEvent], bool]:
    def predicate(event: SecurityEvent) -> bool:
        return all(check(event) for check in predicates)

    return predicate


# 모든 보안 이벤트에 있어야 하는 식별 필드와, 그에 대응하는 레코드 필드 이름이다.
IDENTITY_FIELDS = {
    "user": "user_name",
    "user_id": "user_id",
    "device": "device_id",
    "policy": "policy_name",
    "policy_id": "policy_id",
    "action": "action",
    "target": "full_uri",
    "time": "time",
}

# 진단용 추가 필드다. reason은 정책이 왜 매칭됐는지 알려 주고, file_*는 전송된
# 파일을 설명하며, transaction_id는 요청을 그 요청의 다른 로그 항목과 잇는다.
DETAIL_FIELDS = (
    "reason",
    "categories",
    "detect_count",
    "file_name",
    "file_action",
    "file_hash",
    "transaction_id",
    "src_ip",
    "dst_ip",
    "browser",
)


def details_of(event: SecurityEvent) -> dict[str, object]:
    return {name: event.get(name) for name in DETAIL_FIELDS if event.get(name) is not None}


def identity_of(event: SecurityEvent) -> dict[str, object]:
    return {label: event.get(field) for label, field in IDENTITY_FIELDS.items()}
