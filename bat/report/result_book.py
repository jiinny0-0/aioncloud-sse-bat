"""실행별 결과 CSV: reports/result/<YYYYMMDD>-<HHMM>-<stage>-bat-test-result.csv.

실행 하나에 파일 하나다. 케이스마다 한 행이고, 그 실행에서 돈 케이스는 그 결과를,
돌지 않은 케이스는 미실행을 담는다. 설명 열은 tests/case_descriptions.yaml에서 가져온다.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from bat.report import status_book
from bat.settings import REPORTS_DIR

RESULT_DIR = REPORTS_DIR / "result"
DESCRIPTIONS = status_book.TESTS_DIR / "case_descriptions.yaml"
DESCRIPTION_FIELDS = ("test_steps", "test_parameters", "test_data", "expected_results")
COLUMNS = [
    ("product", "Product"),
    ("status", "Status"),
    ("scenario", "Scenario"),
    ("test_steps", "Test Steps"),
    ("test_parameters", "Test Parameters"),
    ("test_data", "Test Data"),
    ("expected_results", "Expected Results"),
    ("actual_result", "Actual Result"),
]
# case_descriptions.yaml에 actual_result가 없을 때 쓴다.
DEFAULT_ACTUAL = {
    "FAIL": "기대 결과와 다르게 동작함",
    "UNVERIFIED": "확인할 수단이 없어 판정하지 못함",
    "SKIP": "대상 기능이 탐지하지 않아 판정에서 제외함",
    "ERROR": "실행 환경 오류로 판정하지 못함",
    status_book.NOT_RUN: "미실행",
}


def load_descriptions(path: Path = DESCRIPTIONS) -> dict[str, dict[str, str]]:
    """{case_id: {test_steps, test_parameters, test_data, expected_results, actual_result}}."""
    import yaml

    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {str(k): {f: str(v) for f, v in (fields or {}).items()} for k, fields in data.items()}


def result_path(stage: str, run_id: str, directory: Path = RESULT_DIR) -> Path:
    """<YYYYMMDD>-<HHMM>-<stage>-bat-test-result.csv. 날짜와 시각은 실행 id(YYYYMMDD-HHMMSS-…)에서 딴다."""
    return directory / f"{run_id[:8]}-{run_id[9:13]}-{stage}-bat-test-result.csv"


def run_statuses(run_id: str, directory: Path = REPORTS_DIR) -> dict[str, str]:
    """{case_id: status} — 그 실행에서 돈 케이스만. 번호가 바뀐 케이스는 지금 번호로 맞춘다."""
    from bat.report.collector import load_cases

    statuses: dict[str, str] = {}
    for run_dir in directory.glob(f"*/{run_id}"):
        for case in load_cases(run_dir):
            case_id = status_book.current_id(case["case_id"], str(case.get("started_at") or ""))
            if case_id:
                statuses[case_id] = str(case.get("status") or "")
    return statuses


def latest_run_id(profile: str, directory: Path = REPORTS_DIR) -> str | None:
    """그 스테이지에서 가장 최근에 시작한 실행의 id."""
    import json

    stage = status_book.stage_of(profile)
    best: tuple[str, str] | None = None
    for path in directory.glob("*/*/run-report.json"):
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if status_book.stage_of(str(report.get("profile") or "")) != stage:
            continue
        key = (str(report.get("started_at") or ""), str(report.get("run_id") or path.parent.name))
        best = key if best is None or key > best else best
    return best[1] if best else None


def actual_result(status: str, description: dict[str, str]) -> str:
    """짧은 한국어 결과. PASS면 기대 결과를, 아니면 그 케이스의 actual_result를 쓴다."""
    if status == "PASS":
        return description.get("expected_results") or "기대 결과대로 동작함"
    note = description.get("actual_result", "").strip()
    if status in ("FAIL", "UNVERIFIED", "SKIP") and note:
        return note
    return DEFAULT_ACTUAL.get(status, status)


def build_rows(statuses: dict[str, str], cases: list[dict[str, str]],
               descriptions: dict[str, dict[str, str]]) -> list[dict[str, Any]]:
    """상태는 statuses(이번 실행)에서, 없으면 미실행. 설명은 descriptions에서 가져온다."""
    rows = []
    for case in sorted(cases, key=lambda c: c["case_id"]):
        status = statuses.get(case["case_id"]) or status_book.NOT_RUN
        description = descriptions.get(case["case_id"], {})
        rows.append({
            "product": case["product"],
            "status": status,
            "scenario": case["scenario"],
            **{key: description.get(key, "") for key in DESCRIPTION_FIELDS},
            "actual_result": actual_result(status, description),
        })
    return rows


def write(rows: list[dict[str, Any]], path: Path) -> Path:
    """CSV로 쓴다. UTF-8 BOM을 붙여 엑셀에서 열어도 한글이 깨지지 않는다."""
    import csv

    def dump(target: Path) -> None:
        with target.open("w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([label for _, label in COLUMNS])
            for row in rows:
                writer.writerow([row.get(key, "") for key, _ in COLUMNS])

    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        dump(path)
        return path
    except PermissionError:
        fallback = path.with_stem(path.stem + "-locked")
        dump(fallback)
        print(f"{path} is open in another program; wrote {fallback} instead.", file=sys.stderr)
        return fallback


def write_for_run(profile: str, run_id: str, directory: Path = REPORTS_DIR,
                  tests_dir: Path = status_book.TESTS_DIR) -> Path:
    """실행 하나의 결과 CSV. 돈 케이스는 그 결과, 나머지는 미실행이다."""
    stage = status_book.stage_of(profile)
    rows = build_rows(run_statuses(run_id, directory), status_book.catalog(tests_dir),
                      load_descriptions(tests_dir / DESCRIPTIONS.name))
    return write(rows, result_path(stage, run_id, directory / "result"))
