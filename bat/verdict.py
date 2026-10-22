"""케이스의 상태를 정하는 유일한 곳.

PASS        케이스가 선언한 필수 기준마다 통과한 assertion이 있고, 본문이 끝까지
            돌아 완료를 주장했다(pass_case).
FAIL        필요한 assertion이 실패했다. AssertionError가 났거나, 아무것도 raise되지
            않았어도 기준 단계에 ok=False인 assertion이 기록됐다.
            diagnostic 케이스(환경 점검)는 점검을 하나 이상 기록하고 그 점검이
            전부 통과하면 통과한다.
UNVERIFIED  요구한 동작을 확인하지 못했다. 검증 수단이 없었거나, 선언한 기준이
            한 번도 평가되지 않았거나, 케이스가 기준을 선언하지 않았고 diagnostic도
            아니다.
SKIP        케이스가 명시적인 pytest.skip으로 일부러 실행하지 않았다.
ERROR       그 밖에 무언가 잘못됐다. 예상하지 못한 예외가 났거나, 본문이 완료를
            주장하지 않고 반환했다.

CRITERIA_STEPS에 든 단계만 센다. 케이스가 raise하지 않기로 한 SETUP/ACTION 실패
기록은 참고용으로만 남는다.
"""
from __future__ import annotations

from enum import Enum

from bat.models import CRITERIA_STEPS, CaseResult, Kind, Status

_CRITERIA_VALUES = {step.value for step in CRITERIA_STEPS}


class Raised(str, Enum):
    """테스트 러너가 본, 케이스 본문이 끝난 방식."""

    NOTHING = "nothing"
    ASSERTION = "assertion"
    SKIP = "skip"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


def classify(case: CaseResult, raised: Raised, message: str = "") -> tuple[Status, str]:
    if raised is Raised.SKIP:
        return Status.SKIP, message or "skipped"
    if raised is Raised.UNAVAILABLE:
        return Status.UNVERIFIED, f"verification unavailable: {message}"
    if raised is Raised.ASSERTION:
        return Status.FAIL, message or "assertion failed"
    if raised is Raised.ERROR:
        return Status.ERROR, message or "unexpected error"

    unknown = [name for name in case.criteria if name not in _CRITERIA_VALUES]
    if unknown:
        return Status.ERROR, f"unknown criteria {unknown}; allowed: {sorted(_CRITERIA_VALUES)}"

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
        return Status.ERROR, "case did not set a status"

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


def counts_against_run(case: dict) -> bool:
    """UNVERIFIED 결과 때문에 실행이 성공으로 보고되지 않아야 하는지 판단한다.

    기준이 없는 케이스가 UNVERIFIED로 끝나면 보고는 되지만 종료 코드를 정하지
    않는다. 기준을 선언하고도 그 기준을 확인하지 못한 시나리오는 종료 코드를 정한다.
    """
    return case.get("status") == Status.UNVERIFIED.value and bool(case.get("criteria"))
