"""실행 단위 결과 수집과 리포트 렌더링."""
from __future__ import annotations

import json
import logging
import os
import threading
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from bat.models import CaseResult, Status
from bat.report.redact import redact
from bat.verdict import counts_against_run

log = logging.getLogger(__name__)

PRODUCT_ORDER = ["ztna", "edr", "fwaas", "rbi", "swg", "casb", "genai", "dlp", "cross"]


def load_cases(report_dir: Path) -> list[dict[str, Any]]:
    """실행 하나의 리포트 디렉터리 아래에 있는 모든 케이스 파일.

    xdist 워커마다 자기 몫만 가진 collector가 따로 있으므로, 실행 리포트는 케이스별
    파일을 읽어 실행 전체를 덮는다.
    """
    cases = []
    for path in sorted(report_dir.glob("*/result.json")):
        try:
            cases.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError) as exc:
            log.warning("Skipping unreadable case file %s: %s", path, exc)
    return cases


class ResultCollector:
    """스레드 안전한 케이스 결과 저장소.

    케이스는 끝나는 즉시 디스크에 쓴다. 그래서 실행이 죽거나 취소돼도 쓸 수 있는
    근거가 남는다.
    """

    def __init__(self, report_dir: Path, run_id: str, profile: str) -> None:
        self.report_dir = report_dir
        self.run_id = run_id
        self.profile = profile
        self.started_at = datetime.now()
        self._results: list[CaseResult] = []
        self._lock = threading.Lock()
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def add(self, result: CaseResult) -> None:
        with self._lock:
            self._results.append(result)
        self._write_case(result)

    @property
    def results(self) -> list[CaseResult]:
        with self._lock:
            return list(self._results)

    def _write_case(self, result: CaseResult) -> None:
        case_dir = self.report_dir / result.case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        payload = redact(result.to_dict())
        # 다른 xdist 워커가 같은 순간에 실행 리포트를 만들려고 모든 케이스 파일을
        # 읽고 있을 수 있으므로 원자적으로 쓴다.
        target = case_dir / "result.json"
        tmp = case_dir / f"result.json.{os.getpid()}.tmp"
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, target)

    # -- 요약 -------------------------------------------------------

    def _all_cases(self) -> list[dict[str, Any]]:
        return load_cases(self.report_dir)

    @staticmethod
    def totals_of(cases: list[dict[str, Any]]) -> Counter:
        return Counter(case["status"] for case in cases)

    @staticmethod
    def by_product_of(cases: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
        counts: dict[str, Counter] = defaultdict(Counter)
        for case in cases:
            counts[case["product"]]["total"] += 1
            counts[case["product"]][case["status"]] += 1
        ordered = sorted(counts, key=lambda p: (PRODUCT_ORDER.index(p) if p in PRODUCT_ORDER else 99, p))
        return {
            product: {
                "passed": counts[product][Status.PASS.value],
                "unverified": counts[product][Status.UNVERIFIED.value],
                "total": counts[product]["total"],
            }
            for product in ordered
        }

    def totals(self) -> Counter:
        return self.totals_of(self._all_cases())

    def write_run_report(self, extra: dict[str, Any] | None = None) -> Path:
        ended_at = datetime.now()
        duration = ended_at - self.started_at
        cases = self._all_cases()
        totals = self.totals_of(cases)

        meta = {
            "run_id": self.run_id,
            "profile": self.profile,
            "started_at": self.started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "duration_sec": round(duration.total_seconds(), 1),
            "totals": dict(totals),
            "by_product": self.by_product_of(cases),
            "cases": [redact(case) for case in cases],
        }
        if extra:
            meta.update(redact(extra))

        json_path = self.report_dir / "run-report.json"
        json_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
        (self.report_dir / "human-summary.md").write_text(
            self._render_markdown(meta), encoding="utf-8"
        )
        log.info("Report written to %s", self.report_dir)
        return json_path

    def _render_markdown(self, meta: dict[str, Any]) -> str:
        totals = meta["totals"]
        duration_sec = meta["duration_sec"]
        minutes, seconds = divmod(int(duration_sec), 60)

        lines = [
            "# AIONCLOUD SSE BAT RESULT",
            "",
            f"Run      : {meta['run_id']}",
            f"Profile  : {meta['profile']}",
            f"Total    : {sum(totals.values())}",
            f"Passed   : {totals.get('PASS', 0)}",
            f"Failed   : {totals.get('FAIL', 0)}",
            f"Unverified: {totals.get('UNVERIFIED', 0)}",
            f"Skipped  : {totals.get('SKIP', 0)}",
            f"Errors   : {totals.get('ERROR', 0)}",
            f"Duration : {minutes}m {seconds:02d}s",
            "",
            "## By product",
            "",
        ]
        for product, counts in meta["by_product"].items():
            line = f"{product.upper():<9}: {counts['passed']}/{counts['total']} passed"
            if counts.get("unverified"):
                line += f", {counts['unverified']} unverified"
            lines.append(line)

        failures = [
            case
            for case in meta["cases"]
            if case["status"] in ("FAIL", "ERROR")
        ]
        if failures:
            lines += ["", "## Failures", ""]
            for case in failures:
                lines += [
                    f"### {case['case_id']} — {case['scenario']}",
                    "",
                    f"- Status       : {case['status']}",
                    f"- Failure step : {case['failure_step'] or '-'}",
                    f"- Lane         : {case['lane']} / endpoint {case['endpoint'] or '-'}",
                    f"- Workspace    : {case['workspace']}",
                    f"- Policy ids   : {', '.join(case['policy_ids']) or '-'}",
                    f"- Event ids    : {', '.join(case['event_ids']) or '-'}",
                    f"- Error        : {case['error'] or '-'}",
                ]
                for step in case["steps"]:
                    if not step["ok"]:
                        lines.append(
                            f"- {step['step']}: expected={step['expected']!r} "
                            f"actual={step['actual']!r} — {step['detail']}"
                        )
                if case["artifacts"]:
                    lines.append(f"- Artifacts    : {', '.join(case['artifacts'])}")
                lines.append("")

        unverified = [case for case in meta["cases"] if case["status"] == "UNVERIFIED"]
        if unverified:
            lines += ["## Unverified (not a pass)", ""]
            for case in unverified:
                label = "scenario" if counts_against_run(case) else "diagnostic"
                lines.append(
                    f"- {case['case_id']} [{label}] — {case.get('verdict_reason') or '-'}"
                )
            lines.append("")

        leftovers = [c for c in meta["cases"] if c["cleanup_warnings"]]
        if leftovers:
            lines += ["## Cleanup warnings", ""]
            for case in leftovers:
                for warning in case["cleanup_warnings"]:
                    lines.append(f"- {case['case_id']}: {warning}")
            lines.append("")

        return "\n".join(lines) + "\n"
