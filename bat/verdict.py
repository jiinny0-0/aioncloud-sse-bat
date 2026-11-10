"""케이스의 상태와 실행 전체의 롤백 판정(gate)을 정하는 유일한 곳.

케이스 상태는 세 단계로 정한다.

1. classify: 케이스 본문이 어떻게 끝났는지로 정한다.
   PASS        선언한 필수 기준마다 통과한 assertion이 있고, 본문이 끝까지 돌아 완료를
               주장했다(pass_case). diagnostic 케이스(환경 점검)는 점검을 하나 이상 기록하고
               그 점검이 전부 통과하면 통과한다.
   FAIL        필요한 assertion이 실패했다(AssertionError, 또는 기준 단계에 ok=False인 기록).
               관리 API가 응답하지 않거나 5xx를 준 것(product_failure)도 여기다.
   UNVERIFIED  요구한 동작을 확인하지 못했다. 검증 수단이 없었거나, 선언한 기준이 한 번도
               평가되지 않았다.
   SKIP        일부러 실행하지 않았다.
   BAT_ERROR   제품이 아니라 BAT 도구·실행 환경 문제다. 실행 조건 미비(environment_error),
               인증·설정 오류, 테스트 코드의 예상하지 못한 예외, 완료를 주장하지 않은 본문.
2. apply_known_issue: 사용자가 버그로 보지 않기로 한 증상의 FAIL은 SKIP이다.
3. apply_gate: FAIL은 롤백할 만큼 치명적인 경우에만 남는다. gate 케이스가 아니거나,
   일부 대상만 실패했거나(MinorFailure), 사용자 결과는 맞고 이벤트만 실패했으면 WARN이다.
   그 뒤 FAIL은 한 번 더 돌려 보고(merge_retry) 재확인에서도 FAIL일 때만 최종 FAIL이다.

CRITERIA_STEPS에 든 단계만 센다. 케이스가 raise하지 않기로 한 SETUP/ACTION 실패 기록은
참고용으로만 남는다.
"""
from __future__ import annotations

import re
from enum import Enum
from typing import Any, Iterable

from bat.models import CRITERIA_STEPS, CaseResult, Kind, Status, Step

_CRITERIA_VALUES = {step.value for step in CRITERIA_STEPS}

# 결과 CSV·현황 엑셀에 붙이는 상태 설명. Status 값 자체는 언어와 관계없이 그대로다.
STATUS_MEANINGS = {
    "ko": {
        "PASS": "PASS - 기대대로 동작",
        "FAIL": "FAIL - 치명적 결함(배포 롤백 사유)",
        "WARN": "WARN - 기대와 다르게 동작, 확인 필요(롤백 대상 아님)",
        "UNVERIFIED": "UNVERIFIED - 판정 근거 부족·확인 수단 없음(확인 필요)",
        "SKIP": "SKIP - 일부러 실행·판정하지 않음(알려진 이슈 등)",
        "BAT_ERROR": "BAT_ERROR - 테스트 도구/환경 문제(제품 이슈 아님)",
        "미실행": "미실행 - 이번 실행에서 돌지 않음",
    },
    "en": {
        "PASS": "PASS - behaved as expected",
        "FAIL": "FAIL - critical defect (deployment rollback)",
        "WARN": "WARN - behaved unexpectedly, needs a look (not a rollback)",
        "UNVERIFIED": "UNVERIFIED - not enough evidence or no means to check (needs a look)",
        "SKIP": "SKIP - deliberately not run or judged (known issue etc.)",
        "BAT_ERROR": "BAT_ERROR - test tool / environment problem (not a product issue)",
        "미실행": "미실행 - not run in this run",
    },
}

# 예전 결과 파일에 남은 상태 값.
LEGACY_STATUSES = {"ERROR": Status.BAT_ERROR.value}


def current_status(value: object) -> str:
    """저장된 상태 값을 지금 이름으로(ERROR -> BAT_ERROR)."""
    text = str(value or "")
    return LEGACY_STATUSES.get(text, text)


class Raised(str, Enum):
    """테스트 러너가 본, 케이스 본문이 끝난 방식."""

    NOTHING = "nothing"
    ASSERTION = "assertion"
    SKIP = "skip"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


class MinorFailure(AssertionError):
    """기대와 다르지만 치명적이지 않은 실패. gate 케이스에서도 FAIL이 아니라 WARN이다.

    일부 대상만 실패했거나(across_targets), 저장값 일부가 다르다(expect_values). `why`가
    WARN 사유에 붙는다.
    """

    def __init__(self, message: str, why: str) -> None:
        super().__init__(message)
        self.why = why


def product_failure(exc: BaseException) -> str:
    """관리 API(콘솔/REST)가 응답하지 않거나 5xx를 줬으면 그 설명, 아니면 빈 문자열.

    연결 실패·타임아웃·5xx는 제품 장애이고, 인증(401/403)·설정·4xx는 BAT 쪽 문제로 본다.
    """
    import httpx

    from bat.clients.errors import ApiError

    if isinstance(exc, httpx.TransportError):
        return f"management API unreachable ({type(exc).__name__}: {exc})"
    if isinstance(exc, ApiError) and exc.status_code and exc.status_code >= 500:
        return f"management API failed: {exc}"
    return ""


def classify(case: CaseResult, raised: Raised, message: str = "") -> tuple[Status, str]:
    if raised is Raised.SKIP:
        return Status.SKIP, message or "skipped"
    if raised is Raised.UNAVAILABLE:
        return Status.UNVERIFIED, f"verification unavailable: {message}"
    if raised is Raised.ASSERTION:
        return Status.FAIL, message or "assertion failed"
    if raised is Raised.ERROR:
        return Status.BAT_ERROR, message or "unexpected error"

    unknown = [name for name in case.criteria if name not in _CRITERIA_VALUES]
    if unknown:
        return Status.BAT_ERROR, f"unknown criteria {unknown}; allowed: {sorted(_CRITERIA_VALUES)}"

    assertions = [
        s for s in case.steps if s.kind is Kind.ASSERTION and s.step in CRITERIA_STEPS
    ]
    failed = [s for s in assertions if not s.ok]
    if failed:
        first = failed[0]
        return Status.FAIL, f"{first.step.value} assertion recorded as failed: {first.detail}"

    unavailable = [s for s in case.steps if s.kind is Kind.UNAVAILABLE]
    if unavailable:
        first = unavailable[0]
        return Status.UNVERIFIED, f"verification unavailable at {first.step.value}: {first.detail}"

    if case.status is not Status.PASS:
        return Status.BAT_ERROR, "case did not set a status"

    if not case.criteria:
        if case.diagnostic:
            checks = [s for s in case.steps if s.kind is Kind.ASSERTION]
            if checks and all(s.ok for s in checks):
                return Status.PASS, f"diagnostic: all {len(checks)} check(s) passed"
            failed_check = next((s for s in checks if not s.ok), None)
            if failed_check:
                return Status.FAIL, f"diagnostic check failed at {failed_check.step.value}: {failed_check.detail}"
        return Status.UNVERIFIED, "diagnostic: no mandatory security-behaviour criterion declared"

    evaluated = {s.step.value for s in assertions}
    missing = [name for name in case.criteria if name not in evaluated]
    if missing:
        return Status.UNVERIFIED, f"mandatory criteria never evaluated: {missing}"

    return Status.PASS, f"all mandatory criteria passed: {list(case.criteria)}"


def apply_known_issue(status: Status, reason: str, description: str, match: str | None) -> tuple[Status, str]:
    """`@pytest.mark.known_issue(description, match=<정규식>)`가 붙은 케이스의 상태를 정한다.

    사용자가 버그로 보지 않기로 한 것은 그 증상이다. 그래서 FAIL 사유가 match와 일치할 때만
    SKIP으로 바꾸고, 다른 이유의 FAIL(그리고 match가 없는 마커)은 FAIL로 둔다. PASS하면
    결함이 재현되지 않은 것이라 마커를 뗄지 보라고 사유에 남긴다.
    """
    if status is Status.FAIL:
        if match and re.search(match, reason, re.DOTALL):
            return Status.SKIP, f"known issue ({description}): {reason}"
        why = "has no match pattern" if not match else f"pattern {match!r} does not match this failure"
        return Status.FAIL, f"{reason} [known_issue ({description}) {why}, so this stays a failure]"
    if status is Status.PASS:
        return Status.PASS, f"{reason} — known_issue ({description}) did not reproduce: 해제 검토 필요"
    return status, reason


def _only_the_event_failed(case: CaseResult) -> bool:
    """사용자 결과(차단/허용)는 기대대로였고 실패한 기준은 이벤트뿐인가."""
    assertions = [s for s in case.steps if s.kind is Kind.ASSERTION and s.step in CRITERIA_STEPS]
    failed = [s for s in assertions if not s.ok]
    user_ok = [s for s in assertions if s.step is Step.USER_RESULT and s.ok]
    return bool(failed) and bool(user_ok) and all(s.step is Step.EVENT for s in failed)


def apply_gate(case: CaseResult, status: Status, reason: str, *, minor: str = "") -> tuple[Status, str]:
    """FAIL을 롤백할 만큼 치명적인 경우에만 남기고 나머지는 WARN으로 내린다.

    gate 케이스가 아니면 WARN. gate 케이스여도 일부만 실패했거나(minor) 이벤트만 실패했으면
    WARN이다. FAIL이 아닌 상태는 그대로다.
    """
    if status is not Status.FAIL:
        return status, reason
    if not case.gate:
        return Status.WARN, f"{reason} [WARN: not a gate case]"
    if minor:
        return Status.WARN, f"{reason} [WARN: {minor}]"
    if _only_the_event_failed(case):
        return Status.WARN, f"{reason} [WARN: the user-visible result held, only the event check failed]"
    return Status.FAIL, reason


def merge_retry(first: dict[str, Any], status: Status, reason: str) -> tuple[Status, str]:
    """1차 FAIL 케이스를 다시 돌린 결과(status, reason)로 최종 상태를 정한다.

    재확인도 FAIL이면 FAIL, PASS면 불안정으로 WARN, WARN이면 WARN이다. 재확인이 판정을 못
    냈으면(UNVERIFIED/BAT_ERROR/SKIP) 1차 FAIL을 뒤집을 근거가 없어 FAIL로 둔다.
    """
    head = f"1차 FAIL ({str(first.get('verdict_reason') or '-')[:300]})"
    if status is Status.FAIL:
        return Status.FAIL, f"{head}, 재확인 FAIL: {reason}"
    if status is Status.PASS:
        return Status.WARN, f"1차 FAIL, 재확인 PASS: 불안정 — {head}"
    if status is Status.WARN:
        return Status.WARN, f"{head}, 재확인 WARN: {reason}"
    return Status.FAIL, f"{head}, 재확인에서 판정 못 함({status.value}: {reason})"


class Gate(str, Enum):
    OK = "OK"
    REVIEW = "REVIEW"
    ROLLBACK = "ROLLBACK"


# bat run 종료 코드. 실행 자체가 실패한 경우(설정 오류, preflight, pytest 중단)는 따로다.
GATE_EXIT_CODES = {Gate.OK: 0, Gate.REVIEW: 1, Gate.ROLLBACK: 2}


def _line(case: dict[str, Any]) -> str:
    reason = " ".join(str(case.get("verdict_reason") or case.get("error") or "-").split())
    return f"{case.get('status')} {case.get('case_id')} - {reason[:300]}"


def run_gate(cases: Iterable[dict[str, Any]], notes: Iterable[str] = ()) -> tuple[Gate, list[str]]:
    """실행 전체의 롤백 판정.

    ROLLBACK  최종 FAIL이 하나라도 있다(서버 다운 포함).
    REVIEW    FAIL은 없지만 WARN·UNVERIFIED가 있거나, gate 케이스가 BAT_ERROR로 확인되지
              못했거나, notes(예: 정리되지 않은 리소스)가 있다.
    OK        그 밖(SKIP만 있어도 OK).
    """
    cases = [{**c, "status": current_status(c.get("status"))} for c in cases]
    failed = [c for c in cases if c["status"] == Status.FAIL.value]
    if failed:
        return Gate.ROLLBACK, [_line(c) for c in failed]
    review = [
        c for c in cases
        if c["status"] in (Status.WARN.value, Status.UNVERIFIED.value)
        or (c["status"] == Status.BAT_ERROR.value and c.get("gate"))
    ]
    reasons = [_line(c) + (" (gate case not confirmed)" if c.get("gate") and c["status"] != Status.WARN.value else "")
               for c in review] + [str(n) for n in notes]
    if reasons:
        return Gate.REVIEW, reasons
    return Gate.OK, []
