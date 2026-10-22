"""실행별 결과 엑셀: reports/result/<YYYYMMDD>-<stage>-bat-test-result.xlsx.

케이스마다 한 행이고, 그 실행 스테이지의 최신 상태를 담는다. 설명 열은 케이스
현황표(status_book)에서 손으로 관리하는 열에서 가져온다.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

from bat.report import status_book
from bat.settings import REPORTS_DIR

RESULT_DIR = REPORTS_DIR / "result"
SHEET = "Result"
COLUMNS = [
    ("product", "Product", 10),
    ("status", "Status", 12),
    ("scenario", "Scenario", 45),
    ("test_steps", "Test Steps", 50),
    ("test_parameters", "Test Parameters", 32),
    ("test_data", "Test Data", 32),
    ("expected_results", "Expected Results", 40),
    ("actual_result", "Actual Result", 40),
]
WRAP = {"scenario", "test_steps", "test_parameters", "test_data", "expected_results", "actual_result"}
# 현황표에 통과하지 못한 결과의 한국어 설명이 없을 때 쓴다.
DEFAULT_ACTUAL = {
    "FAIL": "기대 결과와 다르게 동작함",
    "UNVERIFIED": "확인할 수단이 없어 판정하지 못함",
    "SKIP": "대상 기능이 탐지하지 않아 판정에서 제외함",
    "ERROR": "실행 환경 오류로 판정하지 못함",
    status_book.NOT_RUN: "미실행",
}
HANGUL = re.compile(r"[가-힣]")


def result_path(stage: str, run_id: str, directory: Path = RESULT_DIR) -> Path:
    """<YYYYMMDD>-<stage>-bat-test-result.xlsx. 날짜는 실행 id에서 딴다."""
    return directory / f"{run_id[:8]}-{stage}-bat-test-result.xlsx"


def actual_result(status: str, row: dict[str, Any]) -> str:
    """짧은 한국어 결과. PASS면 기대 결과를, 아니면 현황표의 한국어 메모를 쓴다."""
    if status == "PASS":
        return str(row.get("expected_results") or "기대 결과대로 동작함")
    note = str(row.get("actual_results") or "").strip()
    if status in ("FAIL", "UNVERIFIED", "SKIP") and HANGUL.search(note):
        return note
    return DEFAULT_ACTUAL.get(status, status)


def build_rows(stage: str, tracker_rows: list[dict[str, Any]], cases: list[dict[str, str]]) -> list[dict[str, Any]]:
    by_id = {r["case_id"]: r for r in tracker_rows}
    rows = []
    for case in sorted(cases, key=lambda c: c["case_id"]):
        row = by_id.get(case["case_id"], {})
        status = str(row.get(status_book.status_key(stage)) or status_book.NOT_RUN)
        rows.append({
            "product": case["product"],
            "status": status,
            "scenario": case["scenario"],
            **{key: row.get(key, "") for key in ("test_steps", "test_parameters", "test_data", "expected_results")},
            "actual_result": actual_result(status, row),
        })
    return rows


def write(rows: list[dict[str, Any]], path: Path) -> Path:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill

    font = status_book.FONT_NAME
    wb = Workbook()
    ws = wb.active
    ws.title = SHEET
    for col, (_, label, width) in enumerate(COLUMNS, start=1):
        cell = ws.cell(row=1, column=col, value=label)
        cell.font = Font(name=font, bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor="4472C4")
        cell.alignment = Alignment(horizontal="center", vertical="center")
        ws.column_dimensions[cell.column_letter].width = width
    for r_idx, row in enumerate(rows, start=2):
        for c_idx, (key, _, _) in enumerate(COLUMNS, start=1):
            cell = ws.cell(row=r_idx, column=c_idx, value=row.get(key, ""))
            cell.font = Font(name=font)
            cell.alignment = Alignment(vertical="top", wrap_text=key in WRAP)
            if key == "status":
                status_book._paint(cell, str(row.get(key, "")))
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:{ws.cell(row=len(rows) + 1, column=len(COLUMNS)).coordinate}"

    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        wb.save(path)
        return path
    except PermissionError:
        fallback = path.with_stem(path.stem + "-locked")
        wb.save(fallback)
        print(f"{path} is open in Excel; wrote {fallback} instead.", file=sys.stderr)
        return fallback


def write_for_run(profile: str, run_id: str, directory: Path = REPORTS_DIR,
                  tests_dir: Path = status_book.TESTS_DIR) -> Path:
    """`run_id` 스테이지의 결과 엑셀. 현황표의 현재 내용으로 만든다."""
    stage = status_book.stage_of(profile)
    tracker_rows, _ = status_book.read_book(status_book.book_path(directory))
    rows = build_rows(stage, tracker_rows, status_book.catalog(tests_dir))
    return write(rows, result_path(stage, run_id, directory / "result"))
