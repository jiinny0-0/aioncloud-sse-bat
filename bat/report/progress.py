"""실행의 실시간 진행 상황: reports/run-progress.md와 `bat progress`.

실행이 디스크에 남기는 파일로 만들므로 xdist 워커끼리 공유하는 것이 없다.
plan.json(이번 실행이 돌 케이스), <case>/result.json(끝난 케이스마다 하나),
.running-<worker>(각 워커가 지금 도는 케이스).
"""
from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from bat.settings import REPORTS_DIR

PLAN_NAME = "plan.json"
PROGRESS_NAME = "run-progress.md"
STATUSES = ("PASS", "FAIL", "UNVERIFIED", "SKIP", "ERROR")


def write_plan(report_dir: Path, run_id: str, profile: str, case_ids: list[str], workers: int) -> Path:
    report_dir.mkdir(parents=True, exist_ok=True)
    plan = {"run_id": run_id, "profile": profile, "started_at": datetime.now().isoformat(timespec="seconds"),
            "workers": max(1, workers), "case_ids": sorted(set(case_ids))}
    return _atomic_write(report_dir / PLAN_NAME, json.dumps(plan, ensure_ascii=False, indent=1))


def mark_running(report_dir: Path, case_id: str | None, worker: str = "") -> None:
    """이 워커가 실행 중인 케이스를 기록한다(None이면 지운다)."""
    path = report_dir / f".running-{worker or os.environ.get('PYTEST_XDIST_WORKER', 'main')}"
    if case_id:
        _atomic_write(path, case_id)
    elif path.exists():
        path.unlink(missing_ok=True)


def snapshot(report_dir: Path, *, now: datetime | None = None,
             estimates: dict[str, float] | None = None) -> dict[str, Any]:
    """진행 파일에 들어가는 숫자들."""
    plan = json.loads((report_dir / PLAN_NAME).read_text(encoding="utf-8"))
    results = {}
    for path in report_dir.glob("*/result.json"):
        try:
            case = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue  # 지금 교체되는 중이다. 다음 갱신 때 센다
        results[case.get("case_id")] = case
    planned = plan["case_ids"]
    done = [cid for cid in planned if cid in results]
    counts = Counter(results[cid].get("status") for cid in done)
    running = sorted({p.read_text(encoding="utf-8").strip() for p in report_dir.glob(".running-*")} - set(done))
    now = now or datetime.now()
    started = datetime.fromisoformat(plan["started_at"])
    if estimates is None:
        from bat.cli import ESTIMATED_SECONDS as estimates  # noqa: N811 - 표 하나에 이름 둘
    left = [cid for cid in planned if cid not in results]
    return {
        "run_id": plan["run_id"], "profile": plan["profile"], "started_at": started,
        "total": len(planned), "done": len(done), "counts": counts, "running": running,
        "elapsed_min": (now - started).total_seconds() / 60,
        "remaining_min": sum(estimates.get(cid, 30) for cid in left) / 60 / plan["workers"],
        "failed": [cid for cid in done if results[cid].get("status") in ("FAIL", "ERROR")],
    }


def render(report_dir: Path, *, finished: bool = False, now: datetime | None = None,
           estimates: dict[str, float] | None = None) -> str:
    s = snapshot(report_dir, now=now, estimates=estimates)
    # 세션은 run-report.json을 마지막에 쓴다. 일찍 멈춘 실행에도 이 파일이 있다.
    finished = finished or ((report_dir / "run-report.json").exists() and not s["running"])
    pct = 100 * s["done"] // s["total"] if s["total"] else 100
    state = "끝남" if finished or (s["total"] and s["done"] == s["total"]) else f"예상 남은 시간 ~{s['remaining_min']:.0f}분"
    lines = [
        f"Run {s['run_id']} ({s['profile']}) — {s['done']}/{s['total']} ({pct}%), "
        f"시작 {s['started_at']:%H:%M}, 경과 {s['elapsed_min']:.0f}분, {state}",
        " / ".join(f"{st} {s['counts'].get(st, 0)}" for st in STATUSES),
    ]
    if s["running"] and not finished:
        lines.append(f"현재: {', '.join(s['running'])}")
    lines.append(f"FAIL/ERROR: {', '.join(s['failed']) or '-'}")
    return "\n".join(lines) + "\n"


def update(report_dir: Path, *, finished: bool = False, out: Path | None = None) -> Path | None:
    """reports/run-progress.md를 다시 쓴다. 예외를 내지 않는다. 진행 표시가 실행을 깨면 안 된다."""
    try:
        return _atomic_write(out or REPORTS_DIR / PROGRESS_NAME, render(report_dir, finished=finished))
    except Exception:  # noqa: BLE001
        return None


def latest_run_dir(reports_dir: Path = REPORTS_DIR) -> Path | None:
    plans = sorted(reports_dir.glob(f"*/*/{PLAN_NAME}"), key=lambda p: p.stat().st_mtime)
    return plans[-1].parent if plans else None


def _atomic_write(path: Path, text: str) -> Path:
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)
    return path
