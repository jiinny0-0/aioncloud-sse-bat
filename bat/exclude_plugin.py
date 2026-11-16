"""all 실행에서 제외 목록(BAT_EXCLUDE)에 있는 제품/케이스를 수집 단계에서 빼는 pytest 플러그인.

bat run이 제외 목록이 있을 때만 `-p bat.exclude_plugin`으로 불러온다.
- 제품 이름(예: dlp)  → 그 제품의 테스트 전체 제외
- 케이스 ID(예: BAT-SWG-001) → 그 케이스만 제외
제외된 테스트는 실행하지 않고 deselected로만 표시된다 (PASS/FAIL/SKIP 집계에 들어가지 않음).
"""

import os

import pytest


def _excluded() -> tuple[set[str], set[str]]:
    products: set[str] = set()
    cases: set[str] = set()
    for token in os.getenv("BAT_EXCLUDE", "").split(","):
        value = token.strip()
        if not value:
            continue
        if value.upper().startswith("BAT-"):
            cases.add(value.upper())
        else:
            products.add(value.lower())
    return products, cases


def _product_of(item) -> set[str]:
    """product 마커와 tests/<제품> 폴더 이름 둘 다 확인한다."""
    names: set[str] = set()
    marker = item.get_closest_marker("product")
    if marker and marker.args:
        names.add(str(marker.args[0]).lower())
    parts = [part.lower() for part in item.path.parts]
    if "tests" in parts:
        index = len(parts) - 1 - parts[::-1].index("tests")
        if index + 1 < len(parts) - 1:  # 파일 이름이 아니라 폴더일 때만
            names.add(parts[index + 1])
    return names


@pytest.hookimpl(tryfirst=True)  # conftest의 워커 그룹 지정, 실행 계획 기록보다 먼저 제외
def pytest_collection_modifyitems(config, items):
    products, cases = _excluded()
    if not products and not cases:
        return
    keep, drop = [], []
    for item in items:
        marker = item.get_closest_marker("case")
        case_id = str(marker.args[0]).upper() if marker and marker.args else ""
        if case_id in cases or _product_of(item) & products:
            drop.append(item)
        else:
            keep.append(item)
    if drop:
        config.hook.pytest_deselected(items=drop)
        items[:] = keep
