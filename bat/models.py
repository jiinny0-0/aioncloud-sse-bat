"""모든 BAT 케이스가 함께 쓰는 결과·메타데이터 모델."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Status(str, Enum):
    """의미는 bat/verdict.py에 정의돼 있고, 상태를 정하는 곳도 거기뿐이다."""

    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"
    UNVERIFIED = "UNVERIFIED"


class Step(str, Enum):
    SETUP = "setup"
    ACTION = "action"
    USER_RESULT = "user_visible_result"
    EVENT = "event_validation"
    CLEANUP = "cleanup"


# 케이스가 필수 기준으로 지정할 수 있는 단계. 즉 보안 동작 자체다.
CRITERIA_STEPS = (Step.USER_RESULT, Step.EVENT)


class Kind(str, Enum):
    """단계 기록의 종류. 잘 됐는지와는 별개다.

    필수 기준을 채울 수 있는 것은 ASSERTION뿐이다. EVIDENCE는 관찰해서 읽는 사람을
    위해 남겨 두는 것이다(CASB가 판정 근거로 쓰지 않는 화면 결과, 식별 정보 덤프 등).
    판정은 그 `ok`를 읽지 않는다. UNAVAILABLE은 점검을 아예 수행하지 못했다는 뜻이다.
    """

    ASSERTION = "assertion"
    EVIDENCE = "evidence"
    UNAVAILABLE = "unavailable"


@dataclass
class StepRecord:
    step: Step
    ok: bool
    detail: str = ""
    duration_sec: float = 0.0
    expected: Any = None
    actual: Any = None
    kind: Kind = Kind.ASSERTION


@dataclass
class CaseResult:
    """최종 리포트의 한 행. 실패를 디버깅하는 데 필요한 근거를 함께 담는다."""

    case_id: str
    product: str
    scenario: str
    status: Status = Status.ERROR
    priority: str = "P1"
    lane: str = ""
    workspace: str = ""
    endpoint: str = ""
    user: str = ""
    policy_ids: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    event_source: str = "rest-log"
    started_at: datetime | None = None
    ended_at: datetime | None = None
    steps: list[StepRecord] = field(default_factory=list)
    error: str = ""
    failure_step: str = ""
    cleanup_warnings: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    # @pytest.mark.verifies로 지정한 필수 기준. 비어 있으면 diagnostic 케이스다.
    criteria: list[str] = field(default_factory=list)
    # @pytest.mark.diagnostic: 환경 점검. 기록한 점검이 전부 통과하면 PASS다.
    diagnostic: bool = False
    verdict_reason: str = ""

    @property
    def duration_sec(self) -> float:
        if not self.started_at or not self.ended_at:
            return 0.0
        return round((self.ended_at - self.started_at).total_seconds(), 2)

    def record(self, step: Step, ok: bool, detail: str = "", **kwargs: Any) -> StepRecord:
        entry = StepRecord(step=step, ok=ok, detail=detail, **kwargs)
        entry.kind = Kind(entry.kind)
        self.steps.append(entry)
        if not ok and entry.kind is not Kind.EVIDENCE and not self.failure_step:
            self.failure_step = step.value
        return entry

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "product": self.product,
            "scenario": self.scenario,
            "status": self.status.value,
            "priority": self.priority,
            "lane": self.lane,
            "workspace": self.workspace,
            "endpoint": self.endpoint,
            "user": self.user,
            "policy_ids": self.policy_ids,
            "event_ids": self.event_ids,
            "event_source": self.event_source,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "duration_sec": self.duration_sec,
            "failure_step": self.failure_step,
            "error": self.error,
            "cleanup_warnings": self.cleanup_warnings,
            "artifacts": self.artifacts,
            "criteria": self.criteria,
            "diagnostic": self.diagnostic,
            "verdict_reason": self.verdict_reason,
            "steps": [
                {
                    "step": s.step.value,
                    "ok": s.ok,
                    "kind": s.kind.value,
                    "detail": s.detail,
                    "duration_sec": s.duration_sec,
                    "expected": s.expected,
                    "actual": s.actual,
                }
                for s in self.steps
            ],
        }


@dataclass
class TrafficResult:
    """테스트 단말에서 보낸 실제 요청의 결과.

    `blocked`는 SSE의 차단 표시(차단 페이지, 403/451, 거부된 DNS 응답)다.
    `delivered`는 요청이 통과했다는 적극적인 근거다. 둘 다 없으면 확정적인 결과가
    돌아오지 않은 것이므로(탐색 오류, curl의 "000", DNS 타임아웃) "차단 안 됨"을
    절대 "허용됨"으로 읽으면 안 된다.

    status_code 0은 curl의 "000"이다. curl은 실행됐지만 HTTP 응답을 받지 못했다.
    None은 상태를 아예 얻지 못했다는 뜻이다.
    """

    url: str
    status_code: int | None
    blocked: bool
    via: str  # "browser" | "curl" | "dns"
    detail: str = ""
    artifact: str = ""
    isolated: bool = False
    delivered: bool = False


@dataclass
class SecurityEvent:
    """SSE 로그 API들을 정규화한 뷰."""

    event_id: str
    source: str
    raw: dict[str, Any]

    def get(self, *names: str) -> Any:
        """로그 엔드포인트마다 필드 이름이 다르므로 차례대로 시도한다."""
        for name in names:
            if name in self.raw and self.raw[name] not in (None, ""):
                return self.raw[name]
        return None
