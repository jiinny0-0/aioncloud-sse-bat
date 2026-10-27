"""케이스 현황표: reports/bat-test-status.xlsx.

케이스마다 한 행이다. 왼쪽 열은 손으로 관리하고, 스테이지마다 `bat run`이 채우는
`<stage> Status`와 `<stage> Last Run` 열이 따로 있다. write_rows()는 항상 행 목록으로
엑셀 전체를 다시 만들므로, 수식과 서식이 데이터와 어긋날 수 없다.
"""
from __future__ import annotations

import ast
import json
import logging
import sys
from pathlib import Path
from typing import Any

from bat.settings import REPORTS_DIR, ROOT

log = logging.getLogger(__name__)

TESTS_DIR = ROOT / "tests"
BOOK_NAME = "bat-test-status.xlsx"
# 예전 리포트에는 qa의 옛 이름인 "swg"가 들어 있을 수 있다.
STAGE_ALIASES = {"swg": "qa", "lguplus": "lg"}
DEFAULT_STAGES = ("qa", "lg", "lg-preprod", "real")

# 빈 번호를 없애려고 다시 매긴 케이스 id. 오래된 것부터: (기준 시각, {옛 id: 새 id}).
# 기준 시각 전에 시작한 저장된 실행은 그 전의 id를 갖고 있다. None은 케이스가 더는
# 없는 id를 버린다. 그래서 옛 결과가 지금 그 번호를 가진 케이스에 붙는 일이 없다.
# 단계마다 차례로 적용하므로, 두 기준 시각보다 오래된 실행에는 둘 다 적용된다.
RENUMBERINGS: list[tuple[str, dict[str, str | None]]] = [
    # ZTNA: 002/008/009/014/015는 삭제되거나 합쳐졌다.
    ("2026-10-15T12:00:00", {
        "BAT-ZTNA-002": None, "BAT-ZTNA-005": "BAT-ZTNA-002", "BAT-ZTNA-006": "BAT-ZTNA-003",
        "BAT-ZTNA-007": "BAT-ZTNA-004", "BAT-ZTNA-008": None, "BAT-ZTNA-009": None,
        "BAT-ZTNA-010": "BAT-ZTNA-005", "BAT-ZTNA-011": "BAT-ZTNA-006", "BAT-ZTNA-012": "BAT-ZTNA-007",
        "BAT-ZTNA-013": "BAT-ZTNA-008", "BAT-ZTNA-014": None, "BAT-ZTNA-015": None,
    }),
    # RBI: 002~004는 쓰인 적이 없다.
    ("2026-10-15T14:50:00", {"BAT-RBI-005": "BAT-RBI-002"}),
    # 약어 변경(2026-10-28): BAS -> BASIC, GAI -> GEN. 기한은 옛 코드가 아직 돌 수 있는 기간을 넉넉히 잡았다.
    ("2026-11-15T00:00:00", {
        **{f"BAT-BAS-00{n}": f"BAT-BASIC-00{n}" for n in range(1, 7)},
        "BAT-GAI-001": "BAT-GEN-001",
    }),
]


def current_id(case_id: str, started_at: str) -> str | None:
    """저장된 결과가 지금 기준으로 속하는 id(None: 그 케이스가 더는 없음)."""
    for cutoff, mapping in RENUMBERINGS:
        if case_id is None:
            break
        if started_at and started_at < cutoff:
            case_id = mapping.get(case_id, case_id)
    return case_id


FONT_NAME = "Arial"
BASE_HEADERS = [
    "case_id", "product", "priority", "status", "scenario",
    "test_steps", "test_parameters", "test_data", "expected_results", "actual_results",
    "note",
]
BASE_LABELS = {
    "case_id": "Case ID", "product": "Product", "priority": "Priority",
    "status": "Status", "scenario": "Scenario",
    "test_steps": "Test Steps", "test_parameters": "Test Parameters",
    "test_data": "Test Data", "expected_results": "Expected Results",
    "actual_results": "Actual Results", "note": "Note",
}
# 여러 줄 자유 텍스트에는 wrap_text와 더 넓은 열을 준다.
WRAP_FIELDS = {"scenario", "test_steps", "test_parameters", "test_data",
               "expected_results", "actual_results", "note"}
# bat/verdict.py가 주는 상태에, (그 스테이지에서) 한 번도 안 돈 케이스용 미실행을 더했다.
# FAIL이 먼저다. 이 파일을 여는 사람은 통과한 것보다 깨진 것을 먼저 보고 싶어 한다.
STATUS_ORDER = {"FAIL": 0, "ERROR": 1, "UNVERIFIED": 2, "미실행": 3, "SKIP": 4, "PASS": 5}
STATUSES = ["PASS", "FAIL", "UNVERIFIED", "ERROR", "SKIP", "미실행"]
NOT_RUN = "미실행"
STATUS_COLORS = {  # 채우기, 글꼴
    "PASS": ("C6EFCE", "006100"),
    "FAIL": ("FFC7CE", "9C0006"),
    "UNVERIFIED": ("DDEBF7", "1F4E78"),
    "ERROR": ("F4B084", "833C0B"),
    "SKIP": ("FFEB9C", "9C6500"),
    "미실행": ("D9D9D9", "404040"),
}
SCOPE_NOTES = {
    "crud": "기본 실행 제외(crud: 저장·조회만 보는 케이스)",
    "manual": "기본 실행 제외(manual)",
    "diagnostic": "환경 점검 케이스(점검이 모두 통과하면 PASS)",
}


def stage_of(profile: str) -> str:
    return STAGE_ALIASES.get(profile, profile)


def book_path(directory: Path = REPORTS_DIR) -> Path:
    return directory / BOOK_NAME


def status_key(stage: str) -> str:
    return f"{stage}_status"


def run_key(stage: str) -> str:
    return f"{stage}_last_run"


def headers_for(stages: list[str]) -> list[str]:
    return BASE_HEADERS + [k for s in stages for k in (status_key(s), run_key(s))]


def label_of(key: str) -> str:
    if key in BASE_LABELS:
        return BASE_LABELS[key]
    if key.endswith("_last_run"):
        return f"{key[: -len('_last_run')]} Last Run"
    return f"{key[: -len('_status')]} Status"


# -- 카탈로그: tests/에 선언된 케이스 --------------------------------------

def _mark(node: ast.expr) -> tuple[str, list[Any]] | None:
    """`pytest.mark.x(...)` 또는 `pytest.mark.x` -> ("x", [상수 인자])."""
    call = node if isinstance(node, ast.Call) else None
    target = call.func if call else node
    if not (isinstance(target, ast.Attribute) and isinstance(target.value, ast.Attribute)
            and target.value.attr == "mark"):
        return None
    args = [a.value for a in (call.args if call else []) if isinstance(a, ast.Constant)]
    return target.attr, args


def _module_marks(tree: ast.Module) -> dict[str, list[Any]]:
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "pytestmark" for t in node.targets):
            values = node.value.elts if isinstance(node.value, (ast.List, ast.Tuple)) else [node.value]
            return dict(m for m in map(_mark, values) if m)
    return {}


def catalog(tests_dir: Path = TESTS_DIR) -> list[dict[str, str]]:
    """tests/에 있는 parked가 아닌 모든 케이스. 제품, 우선순위, 시나리오(docstring 첫 줄), 범위를 함께 준다."""
    return [c for c in _all_cases(tests_dir) if not c["parked"]]


def parked_ids(tests_dir: Path = TESTS_DIR) -> set[str]:
    return {c["case_id"] for c in _all_cases(tests_dir) if c["parked"]}


def _all_cases(tests_dir: Path) -> list[dict[str, Any]]:
    cases = []
    for path in sorted(tests_dir.rglob("test_*.py")):
        if path.name == "test_selfcheck.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        module = _module_marks(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            marks = dict(m for m in map(_mark, node.decorator_list) if m)
            if not marks.get("case"):
                continue
            doc = (ast.get_docstring(node) or "").strip()
            cases.append({
                "case_id": str(marks["case"][0]),
                "product": str((marks.get("product") or module.get("product") or [""])[0]),
                "priority": str((marks.get("priority") or ["P1"])[0]),
                "scenario": doc.splitlines()[0] if doc else node.name,
                "scope": next((s for s in SCOPE_NOTES if s in marks), ""),
                "parked": "parked" in marks or "parked" in module,
            })
    return cases


# -- 엑셀 입출력 ---------------------------------------------------------------

def read_book(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """현황 시트에서 읽은 (rows, stages). 시트가 없으면 ([], 기본 스테이지)."""
    from openpyxl import load_workbook

    if not path.exists():
        return [], list(DEFAULT_STAGES)
    wb = load_workbook(path, data_only=True)
    if "현황" not in wb.sheetnames:
        return [], list(DEFAULT_STAGES)
    ws = wb["현황"]
    labels = [str(c.value or "") for c in ws[1]]
    by_label = {v: k for k, v in BASE_LABELS.items()}
    keys, stages = [], list(DEFAULT_STAGES)
    for label in labels:
        if label in by_label:
            keys.append(by_label[label])
        elif label.endswith(" Status"):
            stage = label[: -len(" Status")]
            stages += [] if stage in stages else [stage]
            keys.append(status_key(stage))
        elif label.endswith(" Last Run"):
            keys.append(run_key(label[: -len(" Last Run")]))
        else:
            keys.append(None)
    headers = headers_for(stages)
    # 시트를 쓴 뒤에 추가된 스테이지는 아직 열이 없다. 그 스테이지에서는 모든
    # 케이스가 미실행이다.
    absent = {status_key(s): NOT_RUN for s in stages if status_key(s) not in keys}
    rows = []
    for values in ws.iter_rows(min_row=2, values_only=True):
        row = {k: (v if v is not None else "") for k, v in zip(keys, values) if k}
        if row.get("case_id"):
            rows.append({h: row.get(h, absent.get(h, "")) for h in headers})
    return rows, stages


def _has_columns_for(path: Path, stages: list[str]) -> bool:
    from openpyxl import load_workbook

    wb = load_workbook(path, read_only=True)
    try:
        if "현황" not in wb.sheetnames:
            return False
        labels = {str(c.value or "") for c in next(wb["현황"].iter_rows(max_row=1))}
    finally:
        wb.close()
    return all(f"{s} Status" in labels for s in stages)


def read_rows(path: Path) -> list[dict[str, Any]]:
    return read_book(path)[0]


def _paint(cell, status: str) -> None:
    from openpyxl.styles import Font, PatternFill

    if status in STATUS_COLORS:
        fill, font = STATUS_COLORS[status]
        cell.fill = PatternFill("solid", fgColor=fill)
        cell.font = Font(name=FONT_NAME, color=font)


def _build_cases_sheet(wb, rows: list[dict], stages: list[str]) -> None:
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.worksheet.datavalidation import DataValidation
    from openpyxl.worksheet.table import Table, TableStyleInfo

    headers = headers_for(stages)
    ws = wb.active
    ws.title = "현황"
    for col, key in enumerate(headers, start=1):
        cell = ws.cell(row=1, column=col, value=label_of(key))
        cell.font = Font(name=FONT_NAME, bold=True, color="FFFFFF")
        # 스테이지 열은 한 덩어리로 읽히도록 머리글 색을 따로 준다.
        cell.fill = PatternFill("solid", fgColor="4472C4" if key in BASE_LABELS else "2F5597")
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)

    status_keys = {"status"} | {status_key(s) for s in stages}
    for r_idx, row in enumerate(rows, start=2):
        for c_idx, key in enumerate(headers, start=1):
            cell = ws.cell(row=r_idx, column=c_idx, value=row.get(key, ""))
            cell.font = Font(name=FONT_NAME)
            cell.alignment = Alignment(vertical="top", wrap_text=key in WRAP_FIELDS)
            if key in status_keys:
                _paint(cell, row.get(key, ""))

    last_row = len(rows) + 1
    widths = {"case_id": 20, "product": 10, "priority": 9, "status": 10,
              "scenario": 45, "test_steps": 45, "test_parameters": 30, "test_data": 30,
              "expected_results": 35, "actual_results": 35, "note": 35}
    for col, key in enumerate(headers, start=1):
        width = widths.get(key, 12 if key.endswith("_status") else 24)
        ws.column_dimensions[ws.cell(row=1, column=col).column_letter].width = width
    ws.freeze_panes = "B2"
    ws.row_dimensions[1].height = 30

    # 진짜 Excel 표로 만들면 열마다 정렬·필터 드롭다운이 생긴다.
    table = Table(displayName="CaseStatus", ref=f"A1:{ws.cell(row=last_row, column=len(headers)).coordinate}")
    table.tableStyleInfo = TableStyleInfo(name="TableStyleMedium2", showRowStripes=True, showFirstColumn=False)
    ws.add_table(table)

    validation = DataValidation(type="list", formula1=f'"{",".join(STATUSES)}"', allow_blank=True)
    ws.add_data_validation(validation)
    for key in status_keys:
        letter = ws.cell(row=1, column=headers.index(key) + 1).column_letter
        validation.add(f"{letter}2:{letter}{max(last_row, 500)}")


def _build_summary_sheet(wb, rows: list[dict], stages: list[str]) -> None:
    from openpyxl.chart import BarChart, PieChart, Reference
    from openpyxl.styles import Font

    headers = headers_for(stages)
    cases = wb["현황"]

    def col(key: str) -> str:
        return cases.cell(row=1, column=headers.index(key) + 1).column_letter

    ws = wb.create_sheet("요약")
    products = sorted({row["product"] for row in rows if row.get("product")})
    ws.cell(row=1, column=1, value="BAT 케이스 현황 요약").font = Font(name=FONT_NAME, bold=True, size=14)
    ws.cell(row=2, column=1, value="'현황' 시트가 바뀌면 여기 숫자도 자동으로 재계산됩니다. "
            "Status는 손으로 관리하는 열, 스테이지 열은 bat run이 채우는 열입니다.").font = Font(
        name=FONT_NAME, italic=True, size=9, color="808080"
    )

    # Status x (Status, 각 스테이지).
    header_row = 4
    columns = [("Status", "status")] + [(f"{s} Status", status_key(s)) for s in stages]
    ws.cell(row=header_row, column=1, value="Status").font = Font(name=FONT_NAME, bold=True)
    for j, (label, _) in enumerate(columns, start=2):
        ws.cell(row=header_row, column=j, value=label).font = Font(name=FONT_NAME, bold=True)
    first = header_row + 1
    total_row = first + len(STATUSES)
    for i, status in enumerate(STATUSES):
        r = first + i
        ws.cell(row=r, column=1, value=status).font = Font(name=FONT_NAME)
        for j, (_, key) in enumerate(columns, start=2):
            c = col(key)
            ws.cell(row=r, column=j, value=f'=COUNTIF(현황!{c}:{c},"{status}")').font = Font(name=FONT_NAME)
    ws.cell(row=total_row, column=1, value="Total").font = Font(name=FONT_NAME, bold=True)
    for j in range(2, 2 + len(columns)):
        letter = ws.cell(row=1, column=j).column_letter
        ws.cell(row=total_row, column=j, value=f"=SUM({letter}{first}:{letter}{total_row - 1})").font = Font(
            name=FONT_NAME, bold=True
        )

    bar = BarChart()
    bar.type, bar.grouping, bar.overlap = "col", "stacked", 100
    bar.title = "스테이지별 Status 분포"
    bar.height, bar.width = 9, 16
    for i in range(len(STATUSES)):
        r = first + i
        series = Reference(ws, min_col=1, max_col=1 + len(columns), min_row=r)
        bar.add_data(series, from_rows=True, titles_from_data=True)
    bar.set_categories(Reference(ws, min_col=2, max_col=1 + len(columns), min_row=header_row))
    ws.add_chart(bar, f"{ws.cell(row=1, column=3 + len(columns)).column_letter}4")

    pie = PieChart()
    pie.title = "Status 분포(손 관리 Status 열)"
    pie.height, pie.width = 8, 10
    pie.add_data(Reference(ws, min_col=2, min_row=header_row, max_row=total_row - 1), titles_from_data=True)
    pie.set_categories(Reference(ws, min_col=1, min_row=first, max_row=total_row - 1))
    ws.add_chart(pie, f"{ws.cell(row=1, column=3 + len(columns)).column_letter}24")

    pb_header = total_row + 3
    ws.cell(row=pb_header, column=1, value="Product (Status 열 기준)").font = Font(name=FONT_NAME, bold=True)
    ws.cell(row=pb_header, column=2, value="Total").font = Font(name=FONT_NAME, bold=True)
    for j, status in enumerate(STATUSES):
        ws.cell(row=pb_header, column=3 + j, value=status).font = Font(name=FONT_NAME, bold=True)
    pc, sc = col("product"), col("status")
    for i, product in enumerate(products):
        r = pb_header + 1 + i
        ws.cell(row=r, column=1, value=product).font = Font(name=FONT_NAME)
        ws.cell(row=r, column=2, value=f'=COUNTIF(현황!{pc}:{pc},"{product}")')
        for j, status in enumerate(STATUSES):
            ws.cell(row=r, column=3 + j, value=f'=COUNTIFS(현황!{pc}:{pc},"{product}",현황!{sc}:{sc},"{status}")')
    ws.column_dimensions["A"].width = 24
    for j in range(2, 3 + len(STATUSES)):
        ws.column_dimensions[ws.cell(row=1, column=j).column_letter].width = 11


def write_rows(rows: list[dict[str, Any]], path: Path, stages: list[str] | None = None) -> Path:
    """`rows`로 엑셀 전체를 다시 만든다.

    쓴 경로를 돌려준다. 보통 `path`이고, `path`가 Excel에 열려 있으면 같은 위치의
    `*-locked.xlsx`다(Windows는 열린 엑셀 파일에 배타적 잠금을 건다).
    """
    from openpyxl import Workbook

    stages = list(stages or DEFAULT_STAGES)
    rows = sorted(rows, key=lambda r: (STATUS_ORDER.get(r.get("status", ""), 9), r.get("case_id", "")))
    wb = Workbook()
    _build_cases_sheet(wb, rows, stages)
    _build_summary_sheet(wb, rows, stages)
    wb.calculation.fullCalcOnLoad = True
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        wb.save(path)
        return path
    except PermissionError:
        fallback = path.with_stem(path.stem + "-locked")
        wb.save(fallback)
        print(f"{path} is open in Excel; wrote {fallback} instead. Close it and run "
              f"'bat status sync' (or move the file into place).", file=sys.stderr)
        return fallback


# -- 갱신 --------------------------------------------------------------------

def _new_row(entry: dict[str, str], stages: list[str]) -> dict[str, Any]:
    row = {h: "" for h in headers_for(stages)}
    row.update({k: entry[k] for k in ("case_id", "product", "priority", "scenario")})
    row["status"] = NOT_RUN
    row["note"] = SCOPE_NOTES.get(entry.get("scope", ""), "")
    for stage in stages:
        row[status_key(stage)] = NOT_RUN
    return row


def _merge_catalog(rows: list[dict[str, Any]], stages: list[str], cases: list[dict[str, str]],
                   descriptions: dict[str, dict[str, str]] | None = None) -> list[str]:
    """`rows`에 없는 카탈로그 케이스를 추가하고 빈칸을 채운다. 추가한 id를 돌려준다.

    descriptions(tests/case_descriptions.yaml)에 있는 설명은 현황표의 설명 열을 덮어쓴다.
    """
    by_id = {r["case_id"]: r for r in rows}
    added = []
    for entry in cases:
        row = by_id.get(entry["case_id"])
        if row is None:
            rows.append(_new_row(entry, stages))
            added.append(entry["case_id"])
            continue
        for key in ("product", "priority", "scenario"):
            if not row.get(key):
                row[key] = entry[key]
        for stage in stages:
            if not row.get(status_key(stage)):
                row[status_key(stage)] = NOT_RUN
    for row in rows:
        description = (descriptions or {}).get(row["case_id"], {})
        for key in ("test_steps", "test_parameters", "test_data", "expected_results"):
            if description.get(key):
                row[key] = description[key]
        if description.get("actual_result"):
            row["actual_results"] = description["actual_result"]
    return added


def _descriptions(tests_dir: Path) -> dict[str, dict[str, str]]:
    from bat.report.result_book import load_descriptions

    return load_descriptions(tests_dir / "case_descriptions.yaml")


def sync_catalog(directory: Path = REPORTS_DIR, tests_dir: Path = TESTS_DIR) -> list[str]:
    """현황표에 tests/의 모든 케이스가 오르게 한다. 추가한 id를 돌려준다."""
    path = book_path(directory)
    rows, stages = read_book(path)
    before = [dict(r) for r in rows]
    parked = parked_ids(tests_dir)
    rows[:] = [r for r in rows if r["case_id"] not in parked]
    added = _merge_catalog(rows, stages, catalog(tests_dir), _descriptions(tests_dir))
    if added or rows != before or not path.exists() or not _has_columns_for(path, stages):
        write_rows(rows, path, stages)
    return added


def _apply_result(row: dict[str, Any], stage: str, case: dict[str, Any], run_id: str) -> None:
    row[status_key(stage)] = case.get("status") or ""
    row[run_key(stage)] = run_id
    for key in ("product", "priority", "scenario"):
        if not row.get(key) and case.get(key):
            row[key] = case[key]


def record_run(profile: str, run_id: str, directory: Path = REPORTS_DIR,
               tests_dir: Path = TESTS_DIR) -> Path | None:
    """실행 하나의 결과를 그 스테이지 열에 쓴다(새 케이스가 있으면 먼저 추가한다)."""
    from bat.report.collector import load_cases

    cases = []
    for run_dir in directory.glob(f"*/{run_id}"):
        for case in load_cases(run_dir):
            case_id = current_id(case["case_id"], str(case.get("started_at") or ""))
            if case_id:
                cases.append({**case, "case_id": case_id})
    parked = parked_ids(tests_dir)
    cases = [c for c in cases if c["case_id"] not in parked]  # 예: --tag parked 실행
    sync_catalog(directory, tests_dir)
    if not cases:
        return None
    stage = stage_of(profile)
    path = book_path(directory)
    rows, stages = read_book(path)
    if stage not in stages:
        stages.append(stage)
        for row in rows:
            row.setdefault(status_key(stage), NOT_RUN)
            row.setdefault(run_key(stage), "")
    by_id = {r["case_id"]: r for r in rows}
    for case in cases:
        row = by_id.get(case["case_id"])
        if row is None:  # 돌긴 했지만 tests/에 없다(예: 그 뒤 이름이 바뀜)
            row = {h: "" for h in headers_for(stages)}
            row.update(case_id=case["case_id"], status=NOT_RUN)
            rows.append(row)
            by_id[row["case_id"]] = row
        _apply_result(row, stage, case, run_id)
    return write_rows(rows, path, stages)


def latest_results(stage: str, directory: Path = REPORTS_DIR) -> dict[str, tuple[str, dict]]:
    """{case_id: (run_id, case)} — 저장된 실행 전체에서 본, 케이스별 `stage`의 가장 최근 결과."""
    latest: dict[str, tuple[str, str, dict]] = {}
    for path in directory.glob("*/*/run-report.json"):
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            log.warning("Skipping unreadable report %s: %s", path, exc)
            continue
        if stage_of(str(report.get("profile") or "")) != stage_of(stage):
            continue
        run_started = str(report.get("started_at") or "")
        for case in report.get("cases") or []:
            case_id = current_id(case["case_id"], run_started)
            if case_id is None:
                continue
            started = str(case.get("started_at") or run_started)
            seen = latest.get(case_id)
            if seen is None or started > seen[0]:
                latest[case_id] = (started, str(report.get("run_id") or path.parent.name), case)
    return {cid: (run_id, case) for cid, (_, run_id, case) in latest.items()}


def rebuild_stage_columns(directory: Path = REPORTS_DIR, tests_dir: Path = TESTS_DIR) -> Path:
    """저장된 실행 리포트로 모든 스테이지 열을 다시 채운다. 손으로 관리하는 열은 그대로 둔다."""
    path = book_path(directory)
    rows, stages = read_book(path)
    _merge_catalog(rows, stages, catalog(tests_dir), _descriptions(tests_dir))
    by_id = {r["case_id"]: r for r in rows}
    for stage in stages:
        for row in rows:
            row[status_key(stage)], row[run_key(stage)] = NOT_RUN, ""
        for case_id, (run_id, case) in latest_results(stage, directory).items():
            if case_id in by_id:
                _apply_result(by_id[case_id], stage, case, run_id)
    return write_rows(rows, path, stages)


def upsert_case(case_id: str, directory: Path = REPORTS_DIR, **fields: Any) -> Path:
    """케이스 하나를 손으로 고친다(행이 없으면 추가한다)."""
    path = book_path(directory)
    rows, stages = read_book(path)
    row = next((r for r in rows if r["case_id"] == case_id), None)
    if row is None:
        row = {h: "" for h in headers_for(stages)}
        row["case_id"] = case_id
        rows.append(row)
    row.update(fields)
    return write_rows(rows, path, stages)
