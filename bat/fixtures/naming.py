"""BAT가 만드는 모든 것의 이름 규칙.

만드는 리소스에는 전부 접두사를 붙인다. (a) 실패한 실행의 잔여물을 다음 시작
때 깨끗이 정리할 수 있게 하고, (b) 아무도 테스트 정책을 실제 정책으로 착각하지
않게 하기 위해서다.
"""
from __future__ import annotations

import re

PREFIX = "BAT"
SEPARATOR = "-"
_NAME_RE = re.compile(rf"^{PREFIX}{SEPARATOR}[A-Z]+{SEPARATOR}\d{{3}}{SEPARATOR}")


def resource_name(case_id: str, run_id: str, suffix: str = "") -> str:
    """BAT-SWG-001-20260915-101500-ab12cd[-suffix]."""
    parts = [case_id, run_id]
    if suffix:
        parts.append(suffix)
    return SEPARATOR.join(parts)


def user_login_id(case_id: str, run_id: str, index: int = 1) -> str:
    return f"{case_id}.{run_id}.u{index}@bat.local".lower()


def is_bat_resource(name: str) -> bool:
    return bool(name) and bool(_NAME_RE.match(name.strip()))


def belongs_to_run(name: str, run_id: str) -> bool:
    return is_bat_resource(name) and run_id in name


def case_id_of(name: str) -> str:
    if not is_bat_resource(name):
        return ""
    return SEPARATOR.join(name.split(SEPARATOR)[:3])
