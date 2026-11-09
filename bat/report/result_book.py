"""실행별 결과 CSV: reports/result/<YYYYMMDD>-<HHMM>-<stage>-bat-test-result.csv.

실행 하나에 파일 하나다. 케이스마다 한 행이고, 그 실행에서 돈 케이스는 그 결과를,
돌지 않은 케이스는 미실행을 담는다. 설명 열은 tests/case_descriptions.yaml에서 가져온다.

언어는 BAT_REPORT_LANG(ko/en, 기본 ko)로 고른다. 바뀌는 것은 Scenario와 설명 열,
Actual Result의 문장뿐이다. 열 이름과 Status 값(PASS/FAIL/.../미실행)은 언어와 관계없이
같다. 결과 파일을 읽는 쪽(봇, 집계 스크립트)이 그 값으로 행을 거르기 때문이다.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from bat.report import status_book
from bat.settings import REPORTS_DIR

RESULT_DIR = REPORTS_DIR / "result"
DESCRIPTIONS = status_book.TESTS_DIR / "case_descriptions.yaml"
DESCRIPTION_FIELDS = ("test_steps", "test_parameters", "test_data", "expected_results")
LANG_ENV = "BAT_REPORT_LANG"
DEFAULT_LANG = "ko"
# 한국어가 원문이고, 다른 언어는 케이스 항목 아래 같은 이름의 블록(en:)에 둔다.
LANGS = ("ko", "en")
# 번역 블록에 둘 수 있는 키. scenario는 한국어에선 테스트 docstring 첫 줄이다.
TRANSLATED_FIELDS = ("scenario", *DESCRIPTION_FIELDS, "actual_result")
COLUMNS = [
    ("case_id", "Case ID"),
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
    "ko": {
        "FAIL": "기대 결과와 다르게 동작함",
        "UNVERIFIED": "확인할 수단이 없어 판정하지 못함",
        "SKIP": "대상 기능이 탐지하지 않아 판정에서 제외함",
        "ERROR": "실행 환경 오류로 판정하지 못함",
        status_book.NOT_RUN: "미실행",
    },
    "en": {
        "FAIL": "Behaved differently from the expected result",
        "UNVERIFIED": "Not judged: there was no means to verify the result",
        "SKIP": "Excluded from the verdict: the target feature did not detect it",
        "ERROR": "Not judged because of an execution environment error",
        status_book.NOT_RUN: "Not run",
    },
}
# PASS인데 expected_results가 비어 있을 때.
DEFAULT_PASS = {"ko": "기대 결과대로 동작함", "en": "Behaved as expected"}


def report_lang(value: str | None = None) -> str:
    """결과 CSV의 언어. value가 없으면 BAT_REPORT_LANG, 모르는 값이면 ko."""
    lang = (value if value is not None else os.getenv(LANG_ENV, "")).strip().lower()
    return lang if lang in LANGS else DEFAULT_LANG


def _load_raw(path: Path) -> dict[str, dict[str, Any]]:
    import yaml

    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {str(k): dict(fields or {}) for k, fields in data.items()}


def _korean(fields: dict[str, Any]) -> dict[str, str]:
    """케이스 항목에서 번역 블록(en: 등)을 뺀 한국어 원문."""
    return {f: str(v) for f, v in fields.items() if f not in LANGS}


def _translation(fields: dict[str, Any], lang: str) -> dict[str, str]:
    block = fields.get(lang) if lang != DEFAULT_LANG else None
    return {f: str(v) for f, v in (block or {}).items() if str(v or "").strip()}


def load_descriptions(path: Path = DESCRIPTIONS, lang: str = DEFAULT_LANG) -> dict[str, dict[str, str]]:
    """{case_id: {test_steps, test_parameters, test_data, expected_results, actual_result[, scenario]}}.

    ko면 원문 그대로다. 다른 언어면 그 언어 블록의 값을 쓰고, 블록에 없는 키는 한국어
    원문으로 대체한다(무엇이 대체됐는지는 untranslated()). scenario는 번역 블록에만 있다.
    """
    lang = report_lang(lang)
    descriptions = {}
    for case_id, fields in _load_raw(path).items():
        description = _korean(fields)
        description.update(_translation(fields, lang))
        descriptions[case_id] = description
    return descriptions


def untranslated(lang: str, case_ids: list[str] | None = None,
                 path: Path = DESCRIPTIONS) -> dict[str, list[str]]:
    """{case_id: [번역이 없어 한국어로 대체되는 키]}. ko거나 빠진 것이 없으면 빈 dict.

    scenario는 한국어 원문이 docstring이라 번역 블록에 항상 있어야 한다. case_ids가
    있으면 그 케이스만 보고, YAML에 항목이 없는 케이스는 scenario가 빠진 것으로 센다.
    """
    lang = report_lang(lang)
    if lang == DEFAULT_LANG:
        return {}
    raw = _load_raw(path)
    missing = {}
    for case_id in (case_ids if case_ids is not None else list(raw)):
        fields = raw.get(case_id, {})
        translated = _translation(fields, lang)
        needed = ["scenario"] + [f for f, v in _korean(fields).items()
                                 if f in TRANSLATED_FIELDS and v.strip()]
        keys = [f for f in needed if f not in translated]
        if keys:
            missing[case_id] = keys
    return missing


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


def actual_result(status: str, description: dict[str, str], lang: str = DEFAULT_LANG) -> str:
    """짧은 결과 문장. PASS면 기대 결과를, 아니면 그 케이스의 actual_result를 쓴다."""
    lang = report_lang(lang)
    if status == "PASS":
        return description.get("expected_results") or DEFAULT_PASS[lang]
    note = description.get("actual_result", "").strip()
    if status in ("FAIL", "UNVERIFIED", "SKIP") and note:
        return note
    return DEFAULT_ACTUAL[lang].get(status, status)


def build_rows(statuses: dict[str, str], cases: list[dict[str, str]],
               descriptions: dict[str, dict[str, str]], lang: str = DEFAULT_LANG) -> list[dict[str, Any]]:
    """상태는 statuses(이번 실행)에서, 없으면 미실행. 설명은 descriptions에서 가져온다.

    Status 값은 lang과 관계없이 그대로다(미실행 포함). scenario는 descriptions에 있으면
    (번역) 그것을, 없으면 카탈로그(docstring 첫 줄)를 쓴다.
    """
    rows = []
    for case in sorted(cases, key=lambda c: c["case_id"]):
        status = statuses.get(case["case_id"]) or status_book.NOT_RUN
        description = descriptions.get(case["case_id"], {})
        rows.append({
            "case_id": case["case_id"],
            "product": case["product"],
            "status": status,
            "scenario": description.get("scenario") or case["scenario"],
            **{key: description.get(key, "") for key in DESCRIPTION_FIELDS},
            "actual_result": actual_result(status, description, lang),
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
                  tests_dir: Path = status_book.TESTS_DIR, lang: str | None = None) -> Path:
    """실행 하나의 결과 CSV. 돈 케이스는 그 결과, 나머지는 미실행이다.

    lang이 없으면 BAT_REPORT_LANG을 따른다. 번역이 빠진 칸은 한국어로 채우고 경고만 남긴다.
    """
    lang = report_lang(lang)
    stage = status_book.stage_of(profile)
    cases = status_book.catalog(tests_dir)
    path = tests_dir / DESCRIPTIONS.name
    missing = untranslated(lang, [c["case_id"] for c in cases], path)
    if missing:
        listed = ", ".join(f"{case_id} ({', '.join(keys)})" for case_id, keys in sorted(missing.items()))
        print(f"Result book  : no {lang} text for {len(missing)} case(s), used Korean: {listed}",
              file=sys.stderr)
    rows = build_rows(run_statuses(run_id, directory), cases, load_descriptions(path, lang), lang)
    return write(rows, result_path(stage, run_id, directory / "result"))
