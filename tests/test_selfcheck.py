"""프레임워크 자체 점검.

SSE 환경을 전혀 건드리지 않으므로 어디서든 돌릴 수 있고, BAT를 테넌트에 붙이기 전에
설치가 정상인지 확인하는 가장 빠른 방법이다.
"""
from __future__ import annotations

import ast
import contextlib
import importlib
import inspect
import json
import pathlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from types import SimpleNamespace

import httpx
import pytest

from bat.clients.errors import ApiError, AuthError, SelfBlockedError
from bat.events.poller import PollTimeout, poll_until
from bat.fixtures.naming import belongs_to_run, case_id_of, is_bat_resource, resource_name
from bat.fixtures.policies import UNRAISED_CLEANUP_FAILURES, CleanupWarning, _cleanup_guard
from bat.models import CaseResult, Kind, SecurityEvent, Status, Step, TrafficResult
from bat.report.collector import ResultCollector
from bat.report.redact import MASK, redact
from bat.verdict import Raised, classify, counts_against_run

RUN_ID = "20260915-101500-ab12cd"
TESTS_DIR = pathlib.Path(__file__).parent


def test_resource_names_are_identifiable():
    name = resource_name("BAT-SWG-001", RUN_ID)
    assert is_bat_resource(name)
    assert belongs_to_run(name, RUN_ID)
    assert case_id_of(name) == "BAT-SWG-001"


def test_production_names_are_never_swept():
    """잔여물 sweep은 접두사로 삭제하므로 이 가드가 중요하다."""
    for name in ("prod-web-policy", "BATCH-1", "batch-swg-001", ""):
        assert not is_bat_resource(name)


def test_secrets_never_reach_a_report():
    payload = {
        "Authorization": "Bearer eyJhbGciOiJI.payloadpart.signaturepart",
        "password": "whatever",
        "note": "MonsterKey mon-e67946fd-f077-46f1-9ae9-81c79579ad54",
        "policy": "BAT-SWG-001",
    }
    cleaned = redact(payload)
    assert cleaned["password"] == MASK
    assert MASK in cleaned["Authorization"]
    assert MASK in cleaned["note"]
    assert cleaned["policy"] == "BAT-SWG-001", "non-secret values must survive"


def test_poller_returns_as_soon_as_the_probe_succeeds():
    attempts = {"n": 0}

    def probe():
        attempts["n"] += 1
        return "ok" if attempts["n"] >= 2 else None

    assert poll_until(probe, timeout_sec=10, description="probe") == "ok"
    assert attempts["n"] == 2


def test_poller_gives_up_with_a_useful_message():
    with pytest.raises(PollTimeout) as excinfo:
        poll_until(lambda: None, timeout_sec=1, description="never happens")
    assert "never happens" in str(excinfo.value)


# -- 결과 분류 (bat/verdict.py) ------------------------------


def _case(*criteria: Step, claimed: bool = True) -> CaseResult:
    case = CaseResult(
        case_id="BAT-SELF-001",
        product="swg",
        scenario="selfcheck",
        criteria=[step.value for step in criteria],
    )
    if claimed:
        case.status = Status.PASS
    return case


def test_every_mandatory_criterion_passing_is_pass():
    case = _case(Step.USER_RESULT, Step.EVENT)
    case.record(Step.SETUP, ok=True, detail="policy created")
    case.record(Step.USER_RESULT, ok=True, detail="block page")
    case.record(Step.EVENT, ok=True, detail="event found")
    status, _ = classify(case, Raised.NOTHING)
    assert status is Status.PASS


def test_a_failed_mandatory_assertion_is_fail():
    case = _case(Step.USER_RESULT)
    case.record(Step.USER_RESULT, ok=False, detail="page rendered")
    assert classify(case, Raised.ASSERTION, "expected block page")[0] is Status.FAIL


def test_a_failed_assertion_that_nothing_raised_is_still_fail():
    """정리 오류가 AssertionError를 대체한 뒤에도 실패한 기록은 여전히 케이스를 실패시킨다."""
    case = _case(Step.USER_RESULT, Step.EVENT)
    case.record(Step.USER_RESULT, ok=False, detail="page rendered")
    case.cleanup_warnings.append("DELETE /sia/v1/web/policy -> HTTP 400")
    status, reason = classify(case, Raised.NOTHING)
    assert status is Status.FAIL
    assert "page rendered" in reason


def test_unavailable_verification_is_unverified():
    case = _case(Step.EVENT)
    assert classify(case, Raised.UNAVAILABLE, "log API returned 500")[0] is Status.UNVERIFIED
    recorded = _case(Step.EVENT)
    recorded.record(Step.EVENT, ok=False, detail="log API returned 500", kind=Kind.UNAVAILABLE)
    assert classify(recorded, Raised.NOTHING)[0] is Status.UNVERIFIED


def test_unverified_helper_records_and_raises():
    from tests.support import VerificationUnavailable, unverified

    case = _case(Step.EVENT)
    with pytest.raises(VerificationUnavailable):
        unverified(case, Step.EVENT, "no event source reachable")
    assert case.steps[-1].kind is Kind.UNAVAILABLE
    assert case.failure_step == Step.EVENT.value


def test_an_intentional_skip_is_skip():
    assert classify(_case(Step.EVENT), Raised.SKIP, "no live proxy")[0] is Status.SKIP


def test_an_unexpected_exception_is_error():
    status, reason = classify(_case(Step.EVENT), Raised.ERROR, "ApiError: HTTP 500")
    assert status is Status.ERROR
    assert "500" in reason


def test_a_body_that_never_claims_completion_is_error():
    case = _case(Step.EVENT, claimed=False)
    case.record(Step.EVENT, ok=True)
    assert classify(case, Raised.NOTHING) == (Status.ERROR, "case did not set a status")


def test_crud_success_without_a_criterion_is_not_pass():
    case = _case()
    case.record(Step.SETUP, ok=True, detail="policy created")
    case.record(Step.ACTION, ok=True, detail="policy read back")
    case.record(Step.USER_RESULT, ok=True, detail="listed")
    status, reason = classify(case, Raised.NOTHING)
    assert status is Status.UNVERIFIED
    assert "diagnostic" in reason


def test_a_diagnostic_whose_checks_all_pass_is_pass():
    case = _case()
    case.diagnostic = True
    case.record(Step.ACTION, ok=True, detail="token accepted")
    assert classify(case, Raised.NOTHING)[0] is Status.PASS

    case.record(Step.ACTION, ok=True, detail="seen", kind=Kind.EVIDENCE)
    case.record(Step.USER_RESULT, ok=False, detail="API intercepted")
    assert classify(case, Raised.NOTHING)[0] is Status.FAIL

    empty = _case()
    empty.diagnostic = True
    empty.record(Step.ACTION, ok=True, detail="only evidence", kind=Kind.EVIDENCE)
    assert classify(empty, Raised.NOTHING)[0] is Status.UNVERIFIED


def test_evidence_alone_does_not_satisfy_a_criterion():
    case = _case(Step.USER_RESULT, Step.EVENT)
    case.record(Step.USER_RESULT, ok=True, detail="recorded, not asserted", kind=Kind.EVIDENCE)
    case.record(Step.EVENT, ok=True, detail="event found")
    status, reason = classify(case, Raised.NOTHING)
    assert status is Status.UNVERIFIED
    assert "user_visible_result" in reason


def test_failed_evidence_neither_fails_the_case_nor_marks_a_failure_step():
    case = _case(Step.EVENT)
    case.record(Step.EVENT, ok=False, detail="identity missing device_id", kind=Kind.EVIDENCE)
    case.record(Step.EVENT, ok=True, detail="event found")
    assert case.failure_step == ""
    assert classify(case, Raised.NOTHING)[0] is Status.PASS


def test_unknown_criterion_is_an_error_not_a_pass():
    case = _case()
    case.criteria = ["setup"]
    case.record(Step.SETUP, ok=True)
    assert classify(case, Raised.NOTHING)[0] is Status.ERROR


@pytest.mark.parametrize(
    "exc, expected",
    [
        (AssertionError("x"), Raised.ASSERTION),
        (pytest.fail.Exception("x"), Raised.ASSERTION),
        (pytest.skip.Exception("x"), Raised.SKIP),
        (RuntimeError("x"), Raised.ERROR),
    ],
)
def test_how_a_body_ended_maps_to_the_right_kind(exc, expected):
    from tests.conftest import _how_it_ended

    try:
        raise exc
    except BaseException:
        info = pytest.ExceptionInfo.from_current()
    assert _how_it_ended(SimpleNamespace(excinfo=info))[0] is expected


def test_verification_unavailable_is_told_apart_from_a_skip():
    from tests.conftest import _how_it_ended
    from tests.support import VerificationUnavailable

    try:
        raise VerificationUnavailable("dependency down")
    except BaseException:
        info = pytest.ExceptionInfo.from_current()
    assert _how_it_ended(SimpleNamespace(excinfo=info))[0] is Raised.UNAVAILABLE
    assert _how_it_ended(SimpleNamespace(excinfo=None))[0] is Raised.NOTHING


# -- 리포트와 CLI ---------------------------------------------------


def _finished(case_id: str, status: Status, criteria: list[str], reason: str) -> CaseResult:
    case = CaseResult(case_id=case_id, product="swg", scenario=case_id, criteria=criteria)
    case.status, case.verdict_reason = status, reason
    return case


def test_run_report_covers_every_worker_and_shows_unverified(tmp_path):
    """한 디렉터리에 둔 collector 두 개가 xdist 워커 두 개를 대신한다."""
    first = ResultCollector(report_dir=tmp_path, run_id=RUN_ID, profile="qa")
    second = ResultCollector(report_dir=tmp_path, run_id=RUN_ID, profile="qa")
    first.add(_finished("BAT-SWG-001", Status.PASS, ["user_visible_result"], "ok"))
    second.add(_finished("BAT-SWG-002", Status.UNVERIFIED, ["event_validation"], "criteria never evaluated"))
    second.add(_finished("BAT-BASIC-001", Status.UNVERIFIED, [], "diagnostic: no criterion"))
    second.write_run_report()

    report = json.loads((tmp_path / "run-report.json").read_text(encoding="utf-8"))
    assert report["totals"] == {"PASS": 1, "UNVERIFIED": 2}
    assert report["by_product"]["swg"] == {"passed": 1, "unverified": 2, "total": 3}
    summary = (tmp_path / "human-summary.md").read_text(encoding="utf-8")
    assert "Unverified: 2" in summary
    assert "BAT-SWG-002 [scenario] — criteria never evaluated" in summary
    assert "BAT-BASIC-001 [diagnostic]" in summary


@pytest.mark.parametrize(
    "statuses, pytest_code, expected",
    [
        ([("PASS", ["event_validation"])], 0, 0),
        ([("PASS", ["event_validation"]), ("UNVERIFIED", [])], 0, 0),
        ([("PASS", ["event_validation"]), ("UNVERIFIED", ["event_validation"])], 0, 6),
        ([("UNVERIFIED", ["event_validation"]), ("FAIL", ["event_validation"])], 1, 1),
        ([("SKIP", ["event_validation"])], 0, 0),
    ],
)
def test_cli_exit_code_follows_the_bat_verdict(tmp_path, monkeypatch, capsys, statuses, pytest_code, expected):
    import bat.settings
    from bat.cli import bat_exit_code

    run_dir = tmp_path / "2026-10-13" / RUN_ID
    collector = ResultCollector(report_dir=run_dir, run_id=RUN_ID, profile="qa")
    for index, (status, criteria) in enumerate(statuses):
        collector.add(_finished(f"BAT-SWG-{index:03d}", Status(status), criteria, "reason"))
    monkeypatch.setattr(bat.settings, "REPORTS_DIR", tmp_path)

    assert bat_exit_code(pytest_code, RUN_ID) == expected
    assert "BAT verdict" in capsys.readouterr().out


def test_unverified_counts_against_a_run_only_for_scenarios():
    assert counts_against_run({"status": "UNVERIFIED", "criteria": ["event_validation"]})
    assert not counts_against_run({"status": "UNVERIFIED", "criteria": []})
    assert not counts_against_run({"status": "PASS", "criteria": ["event_validation"]})


# -- 정리와 마스킹은 이 변경 뒤에도 유지돼야 한다 -------------------------


def test_new_report_fields_are_still_redacted(tmp_path):
    collector = ResultCollector(report_dir=tmp_path, run_id=RUN_ID, profile="qa")
    case = _finished(
        "BAT-SWG-001", Status.UNVERIFIED, ["event_validation"],
        "verification unavailable: Authorization: Bearer eyJhbGciOiJI.payloadpart.signaturepart",
    )
    case.record(Step.EVENT, ok=False, detail="token=Bearer abcdefghijklmnop", kind=Kind.UNAVAILABLE)
    collector.add(case)
    collector.write_run_report()
    for path in (tmp_path / "BAT-SWG-001" / "result.json", tmp_path / "run-report.json"):
        text = path.read_text(encoding="utf-8")
        assert "eyJhbGciOiJI.payloadpart" not in text
        assert "abcdefghijklmnop" not in text
        assert MASK in text


def test_cleanup_runs_on_failure_and_never_masks_it():
    deleted = []

    def failing_delete(handle):
        deleted.append(handle)
        raise RuntimeError("DELETE -> HTTP 400")

    first, second = SimpleNamespace(name="policy-1"), SimpleNamespace(name="policy-2")
    with pytest.raises(AssertionError):
        with _cleanup_guard(failing_delete, first, "web policy"):
            raise AssertionError("expected block page")
    assert deleted == [first], "cleanup must still run when the body failed"

    with pytest.raises(CleanupWarning):
        with _cleanup_guard(failing_delete, second, "web policy"):
            pass
    assert deleted == [first, second]


def test_a_cleanup_failure_behind_a_failed_body_still_reaches_the_report():
    """실패한 본문 뒤의 정리 실패는 cleanup_warnings에 들어가고, 여전히 실패가 우선한다."""
    from tests.conftest import _take_unraised_cleanup_failures

    def failing_delete(handle):
        raise RuntimeError("getaddrinfo failed")

    UNRAISED_CLEANUP_FAILURES.clear()
    with pytest.raises(AssertionError, match="block page"):
        with _cleanup_guard(failing_delete, SimpleNamespace(name="BAT-CASB-004-x"), "casb saas access policy"):
            raise AssertionError("expected block page")
    with pytest.raises(AssertionError):  # 성공한 정리는 아무것도 추가하지 않는다
        with _cleanup_guard(lambda handle: None, SimpleNamespace(name="BAT-CASB-004-y"), "web policy"):
            raise AssertionError("expected block page")

    case = _finished("BAT-CASB-004", Status.FAIL, ["user_visible_result"], "did not hold")
    _take_unraised_cleanup_failures(case)
    assert case.cleanup_warnings == ["casb saas access policy BAT-CASB-004-x: getaddrinfo failed"]
    assert case.status is Status.FAIL, "the verdict is untouched"
    assert not UNRAISED_CLEANUP_FAILURES, "the next case starts with nothing it did not leave"


# -- 스위트 자체에 대한 정적 가드 -------------------------------------

# 기준 선언 점검에서 뺄 제품 폴더(지금은 없음).
UNDECLARED_ALLOWED_DIRS: set[str] = set()


def _case_functions():
    for path in sorted(TESTS_DIR.rglob("test_*.py")):
        if path.parent.name in UNDECLARED_ALLOWED_DIRS:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef):
                continue
            markers = {}
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                markers[getattr(target, "attr", "")] = decorator
            if "case" in markers:
                yield path, node, markers


def test_every_case_declares_criteria_or_says_why_not():
    undeclared, bad = [], []
    for path, node, markers in _case_functions():
        exempt = {"crud", "diagnostic", "manual"} & set(markers)
        if "verifies" not in markers:
            if not exempt:
                undeclared.append(f"{path.name}::{node.name}")
            continue
        args = [getattr(arg, "attr", repr(arg)) for arg in markers["verifies"].args]
        if not args or any(arg not in ("USER_RESULT", "EVENT") for arg in args):
            bad.append(f"{path.name}::{node.name} {args}")
    assert not undeclared, f"add @pytest.mark.verifies or crud/diagnostic: {undeclared}"
    assert not bad, f"verifies takes Step.USER_RESULT / Step.EVENT only: {bad}"


def test_constant_ok_records_state_what_they_are():
    """상수로 쓴 `ok=True`는 바로 위에서 확인한 경우가 아니면 관찰이다.
    어느 쪽이든 kind=로 그 사실을 밝혀야 한다."""
    offenders = []
    for path in sorted(TESTS_DIR.rglob("*.py")):
        if path.name == "test_selfcheck.py":  # 일부러 합성 기록을 만든다
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "record"):
                continue
            if not node.args or getattr(node.args[0], "attr", "") not in ("USER_RESULT", "EVENT"):
                continue
            ok = next((k.value for k in node.keywords if k.arg == "ok"), None)
            has_kind = any(k.arg == "kind" for k in node.keywords)
            if isinstance(ok, ast.Constant) and ok.value is True and not has_kind:
                offenders.append(f"{path.name}:{node.lineno}")
    assert not offenders, f"constant ok=True without kind=: {offenders}"


def test_cleanup_handlers_never_claim_completion_themselves():
    """pass_case를 부르는 `except CleanupWarning` 핸들러는, 바로 그 예외 때문에 남은 검증을
    건너뛴 케이스를 PASS로 만든다."""
    offenders = []
    for path in sorted(TESTS_DIR.rglob("test_*.py")):
        if path.parent.name in UNDECLARED_ALLOWED_DIRS or path.name == "test_selfcheck.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for handler in ast.walk(tree):
            if not (isinstance(handler, ast.ExceptHandler) and getattr(handler.type, "id", "") == "CleanupWarning"):
                continue
            called = {
                getattr(node.func, "id", "")
                for node in ast.walk(handler)
                if isinstance(node, ast.Call)
            }
            if "pass_case" in called or "cleanup_failed" not in called:
                offenders.append(f"{path.name}:{handler.lineno}")
    assert not offenders, f"handle CleanupWarning with cleanup_failed(case, warning): {offenders}"


def test_no_policy_name_is_matched_as_a_substring():
    """정책 이름은 절대 부분 문자열로 매칭하지 않는다. probe의 이름에 그 케이스의 이름이 들어 있다."""
    pattern = re.compile(r'\bin str\(\s*\w+\.get\(\s*"(policy_name|rule_name|content)"')
    roots = [TESTS_DIR, TESTS_DIR.parent / "bat" / "events"]
    offenders = [
        f"{path.relative_to(TESTS_DIR.parent)}:{number}"
        for root in roots
        for path in sorted(root.rglob("*.py"))
        if path.parent.name not in UNDECLARED_ALLOWED_DIRS and path.name != "test_selfcheck.py"
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if pattern.search(line)
    ]
    assert not offenders, f"match with web_log/network_log/casb_log/audit_log matchers: {offenders}"


# -- 이벤트 매칭: 정확한 이름 (bat/events/*) ------------------------------


def _event(**raw) -> SecurityEvent:
    return SecurityEvent(event_id=str(raw.get("id", "1")), source="test", raw=raw)


def test_a_probe_named_after_the_case_is_not_the_case_policy():
    from bat.events import audit_log, casb_log, network_log, web_log

    own = resource_name("BAT-SWG-011", RUN_ID)
    probe = resource_name("BAT-SWG-011", RUN_ID, "idprobe")

    assert web_log.matches_policy(own)(_event(policy_name=own))
    assert not web_log.matches_policy(own)(_event(policy_name=probe))
    assert web_log.matches_policy(own, 502)(_event(policy_name=own, policy_id=502))
    assert web_log.matches_policy(own, "502")(_event(policy_name=own, policy_id=502))
    assert not web_log.matches_policy(own, 502)(_event(policy_name=own, policy_id=501))
    assert not web_log.matches_policy(own)(_event(policy_id=502))

    assert network_log.matches_policy(own)(_event(policy_name=own))
    assert not network_log.matches_policy(own)(_event(policy_name=probe))
    assert casb_log.matches_rule(own)(_event(rule_name=own))
    assert not casb_log.matches_rule(own)(_event(rule_name=probe))

    row = {"next": [{"id": 502, "name": own, "enable": True}]}
    probe_row = {"next": [{"id": 501, "name": probe, "enable": True}]}
    assert audit_log.matches_resource_name(own)(_event(content=json.dumps(row)))
    assert audit_log.matches_resource_name(own)(_event(content=json.dumps(row, separators=(",", ":"))))
    assert not audit_log.matches_resource_name(own)(_event(content=json.dumps(probe_row)))


RUN_CONTEXT = SimpleNamespace(run_id=RUN_ID, policy_propagation_timeout_sec=1, event_poll_timeout_sec=1,
                              started_at=datetime(2026, 9, 15, 10, 15),
                              profile=SimpleNamespace(connector_process="AIConnector for Client"))


@pytest.fixture
def instant_polling(monkeypatch):
    """폴링은 sleep 대신 가짜 시계를 앞으로 돌린다. tests.support도 같은 시계로 시간을
    잰다(CASB 점검은 정책 변경 시각부터 요청 시간을 잰다). fixture가 이 시계를 돌려주므로
    fake가 시간을 흘려보낼 수 있다."""
    import bat.events.poller as poller
    import tests.support as support

    clock = SimpleNamespace(now=0.0)
    fake_time = SimpleNamespace(
        monotonic=lambda: clock.now,
        sleep=lambda seconds: setattr(clock, "now", clock.now + seconds),
    )
    monkeypatch.setattr(poller, "time", fake_time)
    monkeypatch.setattr(support, "time", fake_time)
    return clock


def _run_case_body(module: str, function: str, case_id: str, **fixtures):
    """실제 케이스 본문을 fake에 대고 실행하고, conftest와 같은 방식으로 분류한다."""
    from tests.conftest import _how_it_ended

    body = getattr(importlib.import_module(module), function)
    verifies = next(m for m in body.pytestmark if m.name == "verifies")
    case = CaseResult(
        case_id=case_id, product="selfcheck", scenario=function,
        criteria=[step.value for step in verifies.args],
    )
    available = {"case": case, "run_context": RUN_CONTEXT, **fixtures}
    try:
        body(**{name: available[name] for name in inspect.signature(body).parameters})
    except BaseException:  # noqa: BLE001 - conftest처럼 아래에서 분류한다
        raised, message = _how_it_ended(SimpleNamespace(excinfo=pytest.ExceptionInfo.from_current()))
    else:
        raised, message = Raised.NOTHING, ""
    status, reason = classify(case, raised, message)
    return status, reason, case


def _leftover_readers(monkeypatch, **kinds):
    """bat.leftovers.readers를 종류별 행(또는 읽기 실패)으로 바꾼다."""
    import bat.leftovers as leftovers

    def reader(rows):
        if isinstance(rows, Exception):
            def fail():
                raise rows
            return fail
        return lambda: ([{"id": n, **row} for n, row in enumerate(rows)], True)

    monkeypatch.setattr(leftovers, "readers", lambda rest, gql: [(kind, reader(rows)) for kind, rows in kinds.items()])


def test_the_leftover_check_ignores_policies_of_its_own_run(monkeypatch):
    """다른 실행의 리소스만 잔여물이다. 이번 실행의 리소스는 다른 워커가 아직 쓰고 있을 수 있다.
    웹 정책뿐 아니라 모든 정책 종류를 보고, GenAI처럼 description에 이름을 담는 정책도 센다."""
    from tests.basic.test_basic import test_no_leftovers_from_previous_runs as body
    from tests.support import VerificationUnavailable

    def run(**kinds):
        _leftover_readers(monkeypatch, **kinds)
        case = CaseResult(case_id="BAT-BASIC-005", product="basic", scenario="leftovers")
        body(case=case, rest=None, console=None, run_context=RUN_CONTEXT)
        return case

    case = run(web=[{"name": f"BAT-DLP-003-{RUN_ID}"}, {"name": "tt"}], dns=[{"name": "user rule"}])
    assert case.steps[0].ok

    with pytest.raises(AssertionError, match="BAT-DLP-006-20261012-163648-87bb50"):
        run(web=[{"name": f"BAT-DLP-003-{RUN_ID}"}], dns=[{"name": "BAT-DLP-006-20261012-163648-87bb50-dlp"}])
    with pytest.raises(AssertionError, match="BAT-GEN-001-20261012-163648-87bb50"):
        run(genai=[{"name": "", "description": "BAT generated GenAI policy BAT-GEN-001-20261012-163648-87bb50"}])
    # 남은 것은 없지만 못 읽은 목록이 있으면 확인하지 못한 것이다.
    with pytest.raises(VerificationUnavailable, match="not confirmed"):
        run(web=[], ztna=RuntimeError("Duplicate login"))


def test_the_run_end_check_counts_only_this_runs_resources(monkeypatch):
    """실행 종료 검사는 이번 실행(run_id)의 리소스만 세고, 읽지 못한 목록은 따로 알린다."""
    import bat.leftovers as leftovers

    _leftover_readers(
        monkeypatch,
        web=[{"name": f"BAT-SWG-001-{RUN_ID}"}, {"name": "BAT-SWG-001-20261012-163648-87bb50"}, {"name": "tt"}],
        genai=[{"name": "", "description": f"BAT generated GenAI policy BAT-GEN-001-{RUN_ID}"}],
        rbi=RuntimeError("Unauthorized Roles"),
    )
    found, unread = leftovers.scan(None, None, lambda name: leftovers.belongs_to_run(name, RUN_ID))
    assert found == [f"web id=0 BAT-SWG-001-{RUN_ID}", f"genai id=0 BAT-GEN-001-{RUN_ID}"]
    assert unread and unread[0].startswith("rbi: RuntimeError")


def _first(rows, match, description, timeout_sec):
    for row in rows:
        if match(row):
            return row
    raise PollTimeout(description, timeout_sec, 1)


FAKE_SOURCE_IP = "203.0.113.7"  # TEST-NET-3: 케이스들이 대조로 쓰는 192.0.2.0/24 밖이다
FAKE_HOST_COUNTRY = {"httpbin.org": "US", "example.com": "US", "www.korea.kr": "KR"}


class _FakeWebTenant:
    """웹 정책 API, 브라우저, 보안로그, 감사로그를 한 객체에 담았다.
    SWG 케이스 본문을 처음부터 끝까지 돌리기에 충분하다.

    방문할 때마다 rule이 요청에 맞는 활성 정책마다 이벤트를 하나씩 남긴다. 평가는 제품이
    원래 해야 하는 방식을 따른다. HTTP_HOST는 호스트로, SOURCE_IP/SOURCE_IP_GEO는 이
    가짜 러너(203.0.113.7, KR)로, DESTINATION_IP_GEO는 호스트의 국가로 본다. `ignores`는
    제품이 subject를 건너뛰게 한다(그러면 정책이 모든 요청에 매칭된다. 음성 대조가 잡으려는
    결함이 이것이다). `never`는 subject가 아무것에도 매칭되지 않게 한다."""

    def __init__(self, *, ignores=(), never=(), silent_hosts=(), undelivered_hosts=(),
                 host_country=None, rejects=(), priorities_descend=False):
        self.ignores, self.never = set(ignores), set(never)
        self.silent_hosts, self.undelivered_hosts = set(silent_hosts), set(undelivered_hosts)
        self.host_country = {**FAKE_HOST_COUNTRY, **(host_country or {})}
        self.rejects, self.priorities_descend = set(rejects), priorities_descend
        self.active: dict[str, SimpleNamespace] = {}
        self.events: list[SecurityEvent] = []
        self.audit: list[SecurityEvent] = []
        self._ids = iter(range(500, 600))

    @contextlib.contextmanager
    def temporary(self, name, rules, *, action_type="BLOCK", **_):
        from bat.clients.errors import ApiError

        if any(value in self.rejects for rule in rules for value in rule["value"]):
            raise ApiError("POST /sia/v1/web/policy -> 400 invalid parameter", status_code=400)
        policy_id = next(self._ids)
        handle = SimpleNamespace(policy_id=str(policy_id), name=name, action=str(action_type), rules=rules)
        self.active[name] = handle
        priority = 1000 - policy_id if self.priorities_descend else policy_id
        content = json.dumps({"next": [{"id": policy_id, "name": name, "priority": priority}]})
        self.audit.insert(0, _event(id=f"a{policy_id}", content=content))
        try:
            yield handle
        finally:
            del self.active[name]

    def _fires(self, handle, host) -> bool:
        from bat.fixtures.enums import Subject

        for rule in handle.rules:
            subject, values = rule["subject"], rule["value"]
            if subject in self.never:
                return False
            if subject in self.ignores:
                continue
            matched = {
                Subject.HTTP_HOST: host in values,
                Subject.SOURCE_IP: f"{FAKE_SOURCE_IP}/32" in values,
                Subject.SOURCE_IP_GEO: "KR" in values,
                Subject.DESTINATION_IP_GEO: self.host_country.get(host) in values,
                Subject.HTTP_CATEGORY: True,
            }.get(subject, False)
            if not matched:
                return False
        return True

    def visit(self, url, case_id=""):
        from urllib.parse import urlparse

        host = urlparse(url).hostname
        if host in self.undelivered_hosts:
            return TrafficResult(url=url, status_code=None, blocked=False, via="browser",
                                 detail="net::ERR_CONNECTION_RESET")
        for handle in list(self.active.values()):
            if host not in self.silent_hosts and self._fires(handle, host):
                self.events.insert(0, _event(
                    id=len(self.events) + 1, policy_name=handle.name,
                    policy_id=int(handle.policy_id), action=handle.action, full_uri=url,
                    src_ip=f"{FAKE_SOURCE_IP}:50000", src_country_code="KR",
                    dst_country_code=self.host_country.get(host),
                    categories=[{"id": 7, "name": "Technology"}],
                ))
        return TrafficResult(url=url, status_code=200, blocked=False, via="browser",
                             detail="page rendered (HTTP 200)", delivered=True)

    def security_events(self, lookback_min=10):
        return list(self.events)

    def no_security_event(self, match, *, settle_sec=8.0, **_):
        return not any(match(event) for event in self.events)

    def wait_for_security_event(self, match, *, timeout_sec=30.0, description="", **_):
        return _first(self.events, match, description, timeout_sec)

    def wait_for(self, match, *, timeout_sec=30.0, description="", **_):  # audit_log
        return _first(self.audit, match, description, timeout_sec)


PROBED_SWG_CASES = [
    ("tests.swg.test_swg_category", "test_builtin_category_matches_traffic", "BAT-SWG-003"),
    ("tests.swg.test_swg_conditions", "test_source_ip_block", "BAT-SWG-011"),
    ("tests.swg.test_swg_conditions", "test_source_ip_geo_block", "BAT-SWG-012"),
    ("tests.swg.test_swg_conditions", "test_destination_ip_geo_block", "BAT-SWG-013"),
]


def _web_fixtures(tenant):
    return dict(web_policies=tenant, browser_session=tenant, web_log=tenant, audit_log=tenant)


@pytest.mark.parametrize("module, function, case_id", PROBED_SWG_CASES)
def test_the_probe_event_no_longer_passes_for_the_condition_under_test(module, function, case_id, instant_polling):
    """절대 매칭되지 않는 조건은 그 probe 정책이 이벤트를 남겨도 케이스를 실패시킨다."""
    tenant = _FakeWebTenant(never={"HTTP_CATEGORY", "SOURCE_IP", "SOURCE_IP_GEO", "DESTINATION_IP_GEO"})
    status, reason, case = _run_case_body(module, function, case_id, **_web_fixtures(tenant))
    assert status is Status.FAIL, reason
    assert not case.event_ids, "no event may be attributed to the policy under test"


@pytest.mark.parametrize("module, function, case_id", PROBED_SWG_CASES)
def test_the_condition_under_test_passes_on_its_own_event(module, function, case_id, instant_polling):
    tenant = _FakeWebTenant()
    status, reason, case = _run_case_body(module, function, case_id, **_web_fixtures(tenant))
    assert status is Status.PASS, reason
    own = resource_name(case_id, RUN_ID)
    judged = [s.actual for s in case.steps if isinstance(s.actual, dict) and "policy_id" in s.actual]
    # 대상 여러 개를 도는 케이스는 정책 이름 끝에 대상 이름이 붙는다. probe 정책만 아니면 된다.
    assert judged and all(
        actual["policy"] == own or (actual["policy"].startswith(own + "-") and "probe" not in actual["policy"])
        for actual in judged
    )


# -- SWG-011/012/013의 음성 대조 ------------------------------------

CONDITION_CASES = [
    ("test_source_ip_block", "BAT-SWG-011", "SOURCE_IP"),
    ("test_source_ip_geo_block", "BAT-SWG-012", "SOURCE_IP_GEO"),
    ("test_destination_ip_geo_block", "BAT-SWG-013", "DESTINATION_IP_GEO"),
]


def _run_condition_case(function, case_id, tenant):
    return _run_case_body(
        "tests.swg.test_swg_conditions", function, case_id, **_web_fixtures(tenant)
    )


def _negative_records(case):
    return [s for s in case.steps if "negative control" in s.detail]


@pytest.mark.parametrize("function, case_id, subject", CONDITION_CASES)
def test_negative_control_passes_when_the_condition_is_applied(function, case_id, subject, instant_polling):
    status, reason, case = _run_condition_case(function, case_id, _FakeWebTenant())
    assert status is Status.PASS, reason
    negative = [s for s in _negative_records(case) if s.step is Step.EVENT]
    assert [(s.ok, s.kind) for s in negative] == [(True, Kind.ASSERTION)]
    assert any("-reach" in name for name in negative[0].actual["policies that logged it"])


@pytest.mark.parametrize("function, case_id, subject", CONDITION_CASES)
def test_an_ignored_condition_fails_the_negative_control(function, case_id, subject, instant_polling):
    """결함: 제품이 조건을 건너뛰어 정책이 모든 요청에 매칭된다. 양성 대조만으로는
    이 경우에도 통과한다."""
    status, reason, case = _run_condition_case(function, case_id, _FakeWebTenant(ignores={subject}))
    assert status is Status.FAIL, reason
    assert "not being applied" in reason


@pytest.mark.parametrize("function, case_id, subject", CONDITION_CASES)
def test_a_request_the_reach_probe_never_saw_is_unverified(function, case_id, subject, instant_polling):
    """요청이 아예 평가·기록되지 않았다면, 테스트 대상 정책에 기록이 없다는 것은
    아무것도 증명하지 못한다."""
    tenant = _FakeWebTenant(silent_hosts={"example.com", "www.korea.kr"})
    status, reason, case = _run_condition_case(function, case_id, tenant)
    assert status is Status.UNVERIFIED, reason
    assert "never appeared under the reach probe" in reason


@pytest.mark.parametrize("function, case_id, subject", CONDITION_CASES)
def test_an_undelivered_negative_request_is_unverified(function, case_id, subject, instant_polling):
    tenant = _FakeWebTenant(undelivered_hosts={"example.com", "www.korea.kr"})
    status, reason, case = _run_condition_case(function, case_id, tenant)
    assert status is Status.UNVERIFIED, reason
    assert "was not delivered" in reason


@pytest.mark.parametrize("function, case_id, subject", CONDITION_CASES)
def test_an_unprovable_evaluation_order_is_unverified(function, case_id, subject, instant_polling):
    """reach probe가 먼저 평가될 수 있다면, 첫 매칭에서 멈추는 정책이 테스트 대상
    정책을 가릴 수 있다."""
    status, reason, case = _run_condition_case(function, case_id, _FakeWebTenant(priorities_descend=True))
    assert status is Status.UNVERIFIED, reason
    assert "evaluated before the reach probe" in reason


def test_a_rejected_control_value_is_unverified(instant_polling):
    status, reason, case = _run_condition_case(
        "test_source_ip_geo_block", "BAT-SWG-012", _FakeWebTenant(rejects={"AQ"})
    )
    assert status is Status.UNVERIFIED, reason
    assert "was rejected" in reason


def test_a_destination_in_the_same_country_is_no_negative_control(instant_polling):
    tenant = _FakeWebTenant(host_country={"www.korea.kr": "US"})
    status, reason, case = _run_condition_case(
        "test_destination_ip_geo_block", "BAT-SWG-013", tenant
    )
    assert status is Status.UNVERIFIED, reason
    assert "not a destination outside US" in reason


def test_unrelated_traffic_to_the_policy_country_does_not_count_against_it(instant_polling):
    """SWG-013의 정책은 다른 US 트래픽을 기록하는 게 정상이다. 그 정책에 불리하게
    칠 수 있는 건 음성 요청 자신의 행뿐이다."""
    tenant = _FakeWebTenant()
    original = tenant.visit

    def visit_plus_background(url, case_id=""):
        result = original(url, case_id)
        original("https://httpbin.org/anything", case_id)  # 관계없는 US 요청
        return result

    tenant.visit = visit_plus_background
    status, reason, case = _run_condition_case("test_destination_ip_geo_block", "BAT-SWG-013", tenant)
    assert status is Status.PASS, reason


# -- 허용 판정에는 적극적 증거가 필요하다 (bat/traffic/*) -------------------


NSLOOKUP_RESOLVED = (
    "Server:  UnKnown\nAddress:  127.0.2.1\n\nName:    example.com\n"
    "Addresses:  172.66.147.243\n\t  104.20.23.154\n"
)
NSLOOKUP_REFUSED = (
    "*** UnKnown can't find example.com: Non-existent domain\n"
    "Server:  UnKnown\nAddress:  127.0.2.1\n"
)
NSLOOKUP_TIMED_OUT = (
    "DNS request timed out.\n    timeout was 2 seconds.\n"
    "Server:  UnKnown\nAddress:  8.8.8.8\n\n*** Request to UnKnown timed-out\n"
)
NSLOOKUP_NO_ADDRESS = "Server:  UnKnown\nAddress:  127.0.2.1\n\nName:    httpbin.org\n"


class _Endpoint:
    def __init__(self, *outputs: str):
        self.outputs = list(outputs)

    def run(self, command, timeout_sec=None):
        output = self.outputs.pop(0) if len(self.outputs) > 1 else self.outputs[0]
        return SimpleNamespace(stdout=output, stderr="")


@pytest.mark.parametrize(
    "stdout, blocked, delivered",
    [
        ('"200"', False, True),
        ('"404"', False, True),
        ('"403"', True, False),
        ('"451"', True, False),
        ('"000"', False, False),
        ('"502"', False, False),
        ("", False, False),
    ],
)
def test_curl_tells_a_block_a_delivery_and_no_answer_apart(stdout, blocked, delivered):
    from bat.traffic.http import curl_status

    result = curl_status(_Endpoint(stdout), "https://example.com/")
    assert (result.blocked, result.delivered) == (blocked, delivered)


@pytest.mark.parametrize(
    "stdout, blocked, delivered",
    [
        (NSLOOKUP_RESOLVED, False, True),
        (NSLOOKUP_REFUSED, True, False),
        (NSLOOKUP_TIMED_OUT, False, False),
        (NSLOOKUP_NO_ADDRESS, False, False),
    ],
)
def test_nslookup_needs_an_address_to_count_as_resolved(stdout, blocked, delivered):
    from bat.traffic.http import dns_lookup

    result = dns_lookup(_Endpoint(stdout), "example.com")
    assert (result.blocked, result.delivered) == (blocked, delivered)


class _Page:
    def __init__(self, *, status=200, error=None, marker=False, final_url=None):
        self.status, self.error, self.marker, self.final_url = status, error, marker, final_url
        self.url = "about:blank"

    def goto(self, url, wait_until=None):
        if self.error:
            raise RuntimeError(self.error)
        self.url = self.final_url or url
        return None if self.status is None else SimpleNamespace(status=self.status)

    def wait_for_timeout(self, ms):
        pass

    def get_by_text(self, text):
        return SimpleNamespace(is_visible=lambda timeout=None: self.marker)


def _browser(page):
    from bat.traffic.browser import BrowserSession

    session = BrowserSession(profile=SimpleNamespace(block_page_marker="SSE BLOCKED"))
    session.page = lambda: contextlib.nullcontext(page)
    session.screenshot = lambda page, case_id, label="": ""
    return session


@pytest.mark.parametrize(
    "page, blocked, delivered",
    [
        (_Page(status=200), False, True),
        (_Page(status=200, marker=True), True, False),
        (_Page(error="net::ERR_CONNECTION_RESET"), False, False),
        (_Page(status=None), False, False),
        (_Page(status=502), False, False),
    ],
)
def test_a_page_counts_as_allowed_only_when_it_rendered(page, blocked, delivered):
    result = _browser(page).visit("https://example.com/")
    assert (result.blocked, result.delivered) == (blocked, delivered)


@pytest.mark.parametrize(
    "page, isolated, delivered",
    [
        (_Page(status=200), False, True),
        (_Page(status=200, final_url="https://rbi.example.net/view?url=x"), True, False),
        (_Page(error="Timeout 30000ms exceeded"), False, False),
    ],
)
def test_a_direct_render_needs_to_have_happened(page, isolated, delivered):
    result = _browser(page).visit_for_isolation("https://example.com/")
    assert (result.isolated, result.delivered) == (isolated, delivered)


def _traffic(*, blocked=False, delivered=False, isolated=False, via="curl", status=None):
    return TrafficResult(url="https://example.com/", status_code=status, blocked=blocked,
                         via=via, delivered=delivered, isolated=isolated)


def test_a_delivered_request_passes_the_allow_check():
    from tests.support import expect_delivered

    case = _case(Step.USER_RESULT)
    assert expect_delivered(case, _traffic(delivered=True, status=200), expected="ok", failure="x")
    assert classify(case, Raised.NOTHING)[0] is Status.PASS


def test_a_blocked_request_fails_the_allow_check():
    from tests.support import expect_delivered

    case = _case(Step.USER_RESULT)
    with pytest.raises(AssertionError, match="also blocked"):
        expect_delivered(case, _traffic(blocked=True, status=403), expected="ok", failure="also blocked")
    assert classify(case, Raised.ASSERTION, "also blocked")[0] is Status.FAIL

    unraised = _case(Step.USER_RESULT)
    assert not expect_delivered(
        unraised, _traffic(blocked=True, status=403), expected="ok", failure="x", fatal=False
    )
    assert classify(unraised, Raised.NOTHING)[0] is Status.FAIL


def test_still_isolated_fails_the_direct_render_check():
    from tests.support import expect_delivered

    case = _case(Step.USER_RESULT)
    with pytest.raises(AssertionError):
        expect_delivered(case, _traffic(isolated=True, via="browser"), expected="ok", failure="isolated")


@pytest.mark.parametrize(
    "traffic",
    [
        _traffic(status=0),
        _traffic(status=None),
        _traffic(via="browser"),
        _traffic(via="dns"),
    ],
    ids=["curl-000", "curl-no-status", "navigation-error", "dns-timeout"],
)
def test_no_answer_is_unverified_not_allowed_and_not_failed(traffic):
    from tests.support import expect_allowed

    case = _case(Step.USER_RESULT, Step.EVENT)
    expect_allowed(case, traffic, "https://example.com/")  # 예외가 나면 안 된다
    case.record(Step.EVENT, ok=True, detail="event found")
    status, reason = classify(case, Raised.NOTHING)
    assert status is Status.UNVERIFIED
    assert case.steps[0].kind is Kind.UNAVAILABLE


def test_a_later_failure_still_fails_after_an_inconclusive_allow_check():
    from tests.support import expect_delivered

    case = _case(Step.USER_RESULT, Step.EVENT)
    expect_delivered(case, _traffic(status=0), expected="ok", failure="x")
    case.record(Step.EVENT, ok=False, detail="no matching event")
    assert classify(case, Raised.ASSERTION, "no event")[0] is Status.FAIL


def test_the_block_check_is_unchanged():
    from tests.support import expect_block

    blocked = _case(Step.USER_RESULT)
    expect_block(blocked, _traffic(blocked=True, via="browser"), "https://example.com/")
    assert classify(blocked, Raised.NOTHING)[0] is Status.PASS

    for traffic in (_traffic(delivered=True, via="browser", status=200), _traffic(via="browser")):
        case = _case(Step.USER_RESULT)
        with pytest.raises(AssertionError):
            expect_block(case, traffic, "https://example.com/")
        assert classify(case, Raised.ASSERTION, "no block page")[0] is Status.FAIL


def test_restore_polls_wait_for_an_actual_answer(instant_polling):
    from tests.support import dns_lookup_until_allowed

    restored = dns_lookup_until_allowed(_Endpoint(NSLOOKUP_TIMED_OUT, NSLOOKUP_RESOLVED), "example.com", 20)
    assert restored.delivered
    never = dns_lookup_until_allowed(_Endpoint(NSLOOKUP_TIMED_OUT), "example.com", 20)
    assert not never.delivered and not never.blocked


# -- 정리 실패가 건너뛴 검증을 PASS로 바꾸면 안 된다 ------------------


def test_cleanup_failure_after_the_body_finished_is_only_a_warning():
    from tests.support import cleanup_failed

    case = _case(Step.EVENT)
    case.record(Step.EVENT, ok=True, detail="event found")
    cleanup_failed(case, CleanupWarning("web policy BAT-X: HTTP 500"))
    assert case.cleanup_warnings == ["web policy BAT-X: HTTP 500"]
    assert classify(case, Raised.NOTHING)[0] is Status.PASS


def test_cleanup_failure_before_the_body_finished_is_an_error():
    from tests.conftest import _how_it_ended
    from tests.support import CleanupInterrupted, cleanup_failed

    case = _case(Step.EVENT, claimed=False)
    case.record(Step.EVENT, ok=True, detail="first leg's event found")
    try:
        cleanup_failed(case, CleanupWarning("dns firewall BAT-FW-010-other: HTTP 500"))
    except CleanupInterrupted:
        info = pytest.ExceptionInfo.from_current()
    else:
        pytest.fail("cleanup_failed must raise when the body has not finished")
    status, reason = classify(case, *_how_it_ended(SimpleNamespace(excinfo=info)))
    assert status is Status.ERROR
    assert "never ran" in reason


class _FakeHostCaseTenant:
    """BAT-SWG-023용 웹 정책 API, curl 단말, 브라우저. curl은 호스트를 입력한 그대로
    보내고, 브라우저는 먼저 소문자로 바꾼다(Chromium처럼). 제품은 Host를 대소문자를
    구분해 비교하거나 구분하지 않고 비교한다."""

    def __init__(self, *, case_sensitive, curl_answers=True, browser_blocks=None):
        self.case_sensitive = case_sensitive
        self.curl_answers = curl_answers
        self.browser_blocks = browser_blocks
        self.hosts: list[str] = []
        self.name = ""
        self.events: list[SecurityEvent] = []

    @contextlib.contextmanager
    def temporary(self, name, rules, **_):
        self.hosts, self.name = [v for rule in rules for v in rule["value"]], name
        yield SimpleNamespace(policy_id="900", name=name)
        self.hosts = []

    def wait_for_security_event(self, match, *, timeout_sec=30.0, description="", **_):
        return _first(self.events, match, description, timeout_sec)

    def _blocks(self, host):
        return host in self.hosts if self.case_sensitive else host.lower() in [h.lower() for h in self.hosts]

    def run(self, command, timeout_sec=None):  # 단말의 curl
        from urllib.parse import urlparse

        url = command.rsplit(" ", 1)[-1].strip('"')
        if self._blocks(urlparse(url).hostname if not self.case_sensitive else urlparse(url).netloc):
            self.events.insert(0, _event(id=len(self.events) + 1, policy_name=self.name, policy_id=900,
                                         action="BLOCK", full_uri=url))
            return SimpleNamespace(stdout="403", stderr="")
        return SimpleNamespace(stdout="200" if self.curl_answers else "000", stderr="")

    def visit(self, url, case_id=""):
        from urllib.parse import urlparse

        host = urlparse(url).netloc.lower()
        landed = url.replace(urlparse(url).netloc, host)
        if self._blocks(host) if self.browser_blocks is None else self.browser_blocks:
            return TrafficResult(url=landed, status_code=403, blocked=True, via="browser", detail="block page")
        return TrafficResult(url=landed, status_code=200, blocked=False, via="browser", delivered=True)


def _known_issue_of(module: str, function: str):
    import importlib

    test = getattr(importlib.import_module(module), function)
    return next(m for m in getattr(test, "pytestmark", []) if m.name == "known_issue")


@pytest.mark.parametrize(
    "tenant_args, body_status, final_status",
    [
        # 대소문자 무관 매칭: curl도 막힌다.
        (dict(case_sensitive=False), Status.PASS, Status.PASS),
        # curl만 우회하고 브라우저는 막힌다: 우회가 확인된 FAIL이고, 그 증상만 known_issue로 SKIP.
        (dict(case_sensitive=True), Status.FAIL, Status.SKIP),
        # curl도 브라우저도 통과: known_issue 증상이 아니므로 FAIL 그대로.
        (dict(case_sensitive=True, browser_blocks=False), Status.FAIL, Status.FAIL),
        # curl이 응답을 받지 못함(000): 우회인지 알 수 없다.
        (dict(case_sensitive=True, curl_answers=False), Status.UNVERIFIED, Status.UNVERIFIED),
    ],
)
def test_swg_023_counts_a_bypass_only_when_curl_was_delivered(instant_polling, tenant_args, body_status, final_status):
    """BAT-SWG-023: curl이 막히면 PASS, curl이 응답을 받으면 FAIL(known_issue 증상과 일치할 때만 SKIP), 응답이 없으면 UNVERIFIED."""
    from bat.verdict import apply_known_issue

    tenant = _FakeHostCaseTenant(**tenant_args)
    status, reason, case = _run_case_body(
        "tests.swg.test_swg_http_host", "test_host_block_is_case_insensitive", "BAT-SWG-023",
        web_policies=tenant, executor=tenant, browser_session=tenant, web_log=tenant,
    )
    assert status is body_status, reason
    browser = [s for s in case.steps if s.detail.startswith("browser ")]
    assert len(browser) == 1 and browser[0].kind is Kind.EVIDENCE
    known = _known_issue_of("tests.swg.test_swg_http_host", "test_host_block_is_case_insensitive")
    final, final_reason = apply_known_issue(status, reason, known.args[0], known.kwargs.get("match"))
    assert final is final_status, final_reason


def test_known_issue_skips_only_its_own_symptom():
    """known_issue는 match와 일치하는 FAIL만 SKIP으로 바꾸고, 그 밖의 FAIL은 FAIL로 둔다. PASS면 해제 검토를 남긴다."""
    from bat.verdict import apply_known_issue

    match = r"second rule was delivered"
    skipped = apply_known_issue(Status.FAIL, "A payload matching only the second rule was delivered", "d", match)
    assert skipped[0] is Status.SKIP and skipped[1].startswith("known issue (d): ")
    status, reason = apply_known_issue(Status.FAIL, "The keyword rule did not block its own payload", "d", match)
    assert status is Status.FAIL and "does not match" in reason
    status, reason = apply_known_issue(Status.FAIL, "anything", "d", None)
    assert status is Status.FAIL and "no match pattern" in reason
    status, reason = apply_known_issue(Status.PASS, "all mandatory criteria passed", "d", match)
    assert status is Status.PASS and "해제 검토 필요" in reason
    for other in (Status.UNVERIFIED, Status.ERROR, Status.SKIP):
        assert apply_known_issue(other, "r", "d", match) == (other, "r")


def test_every_known_issue_marker_names_its_symptom():
    """known_issue 마커마다 match가 있고 그 정규식이 컴파일된다(match가 없으면 어떤 FAIL도 SKIP이 되지 않는다)."""
    import importlib
    import re

    found = []
    for path in sorted(TESTS_DIR.rglob("test_*.py")):
        if path.name == "test_selfcheck.py":
            continue
        module = importlib.import_module(".".join(path.relative_to(TESTS_DIR.parent).with_suffix("").parts))
        for name in dir(module):
            if not name.startswith("test_"):
                continue
            for mark in getattr(getattr(module, name), "pytestmark", []):
                if mark.name == "known_issue":
                    found.append(name)
                    assert mark.kwargs.get("match"), f"{name}: known_issue without match="
                    re.compile(mark.kwargs["match"])
    assert len(found) >= 4, found


def test_known_issue_patterns_match_the_failures_they_describe():
    """세 결함 케이스의 match가 그 케이스가 실제로 내는 실패 문구와 일치한다(문구를 바꾸면 여기서 드러난다)."""
    import re

    samples = {
        ("tests.cross.test_cross_swg_dlp", "test_dlp_block_survives_a_higher_priority_allow"):
            "A higher-priority ALLOW policy on httpbin.org let the DLP-flagged payload through (HTTP 200)",
        ("tests.dlp.test_dlp_detection", "test_one_policy_with_two_rules_catches_either_of_them"):
            "A payload matching only the second rule was delivered (HTTP 200); rules in one policy",
        ("tests.fwaas.test_fwaas_firewall", "test_protocol_scope_limits_what_is_blocked"):
            "A policy scoped to protocol 1 (ICMP) also cut off HTTP to 98.88.155.171, so the protocol",
    }
    for (module, function), message in samples.items():
        known = _known_issue_of(module, function)
        assert re.search(known.kwargs["match"], message), function
        # 같은 케이스의 다른 실패(사전 조건 실패, 이벤트 없음)는 일치하지 않는다.
        assert not re.search(known.kwargs["match"], "The DLP-linked policy never took effect on its own"), function
        assert not re.search(known.kwargs["match"], "No security event for BAT-X within 90s"), function


def test_eicar_counts_as_missed_only_when_delivered_intact():
    """BAT-SWG-016: 차단되지 않은 업로드는 응답을 받고 에코가 내용을 그대로 받았을 때만 놓친 것(FAIL)이다."""
    from bat.traffic.http import echoed_file_intact
    from tests.swg.test_swg_conditions import eicar_outcome

    def traffic(status):
        return TrafficResult(url="u", status_code=status, blocked=status in (403, 451), via="curl",
                             delivered=status == 200)

    assert eicar_outcome(traffic(403), None) == "blocked"
    assert eicar_outcome(traffic(200), True) == "missed"
    assert eicar_outcome(traffic(200), False) == "unknown"   # 전달 중 내용이 바뀜
    assert eicar_outcome(traffic(200), None) == "unknown"    # 에코를 읽지 못함
    assert eicar_outcome(traffic(0), None) == "unknown"      # 업로드가 응답을 받지 못함

    content = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$TEST"
    body = json.dumps({"files": {"file": content + "\r\n"}, "form": {}})
    assert echoed_file_intact(body, content) is True
    assert echoed_file_intact(json.dumps({"files": {"file": "changed"}}), content) is False
    assert echoed_file_intact("<html>block page</html>", content) is None
    assert echoed_file_intact(json.dumps({"files": {}}), content) is None


class _FakeDnsTenant:
    """BAT-FW-010용 DNS Firewall API, 단말, DNS 로그. 커넥터 사용자에게 적용되는
    BLOCK 정책이 활성인 동안에는 조회가 거부된다."""

    CONNECTOR_USER = 11

    def __init__(self, fail_delete=()):
        self.fail_delete = fail_delete
        self.active: dict[str, SimpleNamespace] = {}
        self.created: list[str] = []
        self.events: list[SecurityEvent] = []
        self._ids = iter(range(700, 800))

    @contextlib.contextmanager
    def temporary(self, name, rules, *, action_type="BLOCK", users=None, user_groups=None, **_):
        handle = SimpleNamespace(policy_id=str(next(self._ids)), name=name, action=action_type, users=users)
        self.created.append(name)
        self.active[name] = handle

        def delete(target):
            if any(target.name.endswith(suffix) for suffix in self.fail_delete):
                raise RuntimeError("delete -> HTTP 500")
            del self.active[target.name]

        with _cleanup_guard(delete, handle, "dns firewall"):
            yield handle

    def run(self, command, timeout_sec=None):  # 단말
        applying = [
            h for h in self.active.values()
            if not h.users or self.CONNECTOR_USER in h.users
        ]
        for handle in applying:
            self.events.insert(0, _event(
                id=len(self.events) + 1, policy_name=handle.name,
                user_id=self.CONNECTOR_USER, action=handle.action,
            ))
        refused = any(h.action == "BLOCK" for h in applying)
        return SimpleNamespace(stdout=NSLOOKUP_REFUSED if refused else NSLOOKUP_RESOLVED, stderr="")

    def wait_for_dns_event(self, match, *, timeout_sec=30.0, description="", **_):
        return _first(self.events, match, description, timeout_sec)

    def dns_events(self, lookback_min=10):
        return list(self.events)


def _run_fw_010(tenant):
    return _run_case_body(
        "tests.fwaas.test_fwaas_firewall", "test_dns_firewall_applies_only_to_its_users",
        "BAT-FW-010", dns_firewall=tenant, executor=tenant, network_log=tenant,
    )


@pytest.mark.parametrize("connector_user", [1, 2, 3, 11])
def test_fw_010_scopes_the_other_policy_to_someone_who_is_not_the_connector(instant_polling, connector_user):
    """"다른 사용자" 정책은 id가 무엇이든 커넥터 사용자가 아닌 사람으로 스코프된다."""
    tenant = _FakeDnsTenant()
    tenant.CONNECTOR_USER = connector_user
    status, reason, case = _run_fw_010(tenant)
    assert status is Status.PASS, reason


def test_fw_010_cannot_pass_when_the_other_user_policy_is_left_behind(instant_polling):
    """"다른 사용자" 정책 삭제가 실패하면, 앞 절반의 기록으로 PASS가 되는 게 아니라 ERROR다."""
    tenant = _FakeDnsTenant(fail_delete=("-other",))
    status, reason, case = _run_fw_010(tenant)
    assert status is Status.ERROR, reason
    assert "never ran" in reason
    assert not any(name.endswith("-mine") for name in tenant.created), "the own-user half must not have run"
    assert case.cleanup_warnings


def test_fw_010_still_passes_when_only_its_last_policy_is_left_behind(instant_polling):
    status, reason, case = _run_fw_010(_FakeDnsTenant(fail_delete=("-mine",)))
    assert status is Status.PASS, reason
    assert case.cleanup_warnings


def test_fw_010_passes_on_a_clean_run(instant_polling):
    status, reason, case = _run_fw_010(_FakeDnsTenant())
    assert status is Status.PASS, reason
    assert not case.cleanup_warnings


@dataclass(frozen=True)
class _Screens:
    """CASB BLOCK 정책이 보여 주는 화면. 요청이 정책 생성 후 `budget`초 안에 나갔는지로
    나눈다. 그 요청에는 `during`, 나머지에는 `after`를 차례로 쓰고 마지막 값을 반복한다.
    `unlogged`는 `after` 구간의 요청 가운데 자기 행을 남기지 않는 요청의 번호다(1부터)."""

    budget: float
    during: tuple = ("block",)
    after: tuple = ("block",)
    unlogged: tuple = ()


class _FakeJourneyTenant:
    """BAT-X-010/X-011, BAT-X-006, BAT-CASB-003/004용 DLP/web/CASB/GenAI API, 단말,
    브라우저, 로그.

    SaaS Access 정책이 활성인 동안 CASB 앱을 방문하면 casb_security_log가 기록하는
    방식대로 행을 남긴다. 페이지 자신의 요청(Notion이 쿼리를 유지한 채 www.notion.com으로
    301한 뒤의 요청), 페이지의 API 호출과 텔레메트리, 또는 둘 다다. BLOCK 정책 아래에서
    `casb_screen`은 사용자가 보는 화면("block" | "render" | "error")이다. 방문마다 하나씩
    쓰고 마지막 값을 반복하는 그 값들의 시퀀스, _Screens, 또는 정책 생성 후 지난 초를 받는
    함수일 수도 있다. `casb_rows`는 어느 요청이 행을 받는지("own" | "others" | "none" |
    "observed"), `casb_action`은 그 행에 적히는 값이다. LOGGING 정책은 항상 렌더링되고
    페이지 자신의 행을 남긴다.

    시간은 instant_polling이 설치하는 시계다. 방문 한 번에 `visit_sec`(시퀀스면 BLOCK
    방문마다 그만큼의 초, 마지막 값 반복), DLP 이벤트가 나타나기까지 `dlp_sec`, 웹 우선순위
    변경에 `priority_sec`이 걸리고, CASB 행은 요청 후 `row_delay_sec` 뒤에 나타난다.
    `casb_read_error`가 설정돼 있으면 casb_security_log를 읽을 때마다 그 예외를 던지고,
    브라우저 자체는 `casb_crash_on`번째 BLOCK 방문에서 고장 난다."""

    SUBREQUESTS = (
        "https://app.notion.com/api/v3/etClient",
        "https://www.notion.com/front-api/notifications/en-US",
        "https://http-inputs-notion.splunkcloud.com/services/collector/raw",
    )

    def __init__(
        self, fail_delete=(), *, casb_screen="block", casb_rows="own", casb_action="BLOCK",
        visit_sec=0.0, dlp_sec=0.0, row_delay_sec=0.0, casb_read_error=None, casb_crash_on=0,
        priority_sec=0.0,
    ):
        from bat.fixtures.testdata import CASB_SAAS_APP_NAME, CASB_SAAS_URL, POST_TARGET_URL

        self.casb_url, self.casb_app, self.post_url = CASB_SAAS_URL, CASB_SAAS_APP_NAME, POST_TARGET_URL
        self.fail_delete = fail_delete
        self.casb_screen = casb_screen
        self.casb_screens = [casb_screen] if isinstance(casb_screen, str) else list(
            casb_screen if isinstance(casb_screen, (list, tuple)) else ()
        )
        self.casb_rows, self.casb_action = casb_rows, casb_action
        self.visit_sec, self.dlp_sec, self.row_delay_sec = visit_sec, dlp_sec, row_delay_sec
        self.casb_read_error, self.casb_crash_on, self.priority_sec = casb_read_error, casb_crash_on, priority_sec
        self.casb_visits: list[tuple[str, str]] = []  # (url, 사용자가 본 화면), BLOCK 방문만
        self.active: dict[str, tuple[str, SimpleNamespace]] = {}
        self.created: list[str] = []
        self.web_events: list[SecurityEvent] = []
        self.casb_events: list[SecurityEvent] = []
        self._visible_at: dict[str, float] = {}  # casb 행 id -> 로그에 나타나는 시각
        self._windows = {"during": 0, "after": 0}
        self._ids = iter(range(900, 999))

    @staticmethod
    def _now():
        import bat.events.poller as poller

        return poller.time.monotonic()

    @staticmethod
    def _pass(seconds):
        import bat.events.poller as poller

        if seconds:
            poller.time.sleep(seconds)

    def _screen(self, blocker):
        """`blocker` 아래에서 이 방문이 보여 주는 화면과, 자기 행을 남기는지 여부."""
        spec, elapsed = self.casb_screen, self._now() - blocker.created_at
        if isinstance(spec, _Screens):
            window = "during" if elapsed <= spec.budget + 1e-6 else "after"
            self._windows[window] += 1
            n = self._windows[window]
            shown = spec.during if window == "during" else spec.after
            return shown[min(n, len(shown)) - 1], not (window == "after" and n in spec.unlogged)
        if callable(spec):
            return spec(elapsed), True
        return self.casb_screens[min(len(self.casb_visits), len(self.casb_screens) - 1)], True

    @contextlib.contextmanager
    def create(self, kind, name, action="BLOCK"):
        handle = SimpleNamespace(
            policy_id=str(next(self._ids)), name=name, action=str(action), created_at=self._now()
        )
        self.created.append(name)
        self.active[name] = (kind, handle)

        def delete(target):
            if any(target.name.endswith(suffix) for suffix in self.fail_delete):
                raise RuntimeError("delete -> HTTP 500")
            del self.active[target.name]

        with _cleanup_guard(delete, handle, kind):
            yield handle

    def _active(self, kind):
        return [handle for k, handle in self.active.values() if k == kind]

    def factory(self, kind):
        return SimpleNamespace(
            temporary=lambda name, *args, action_type="BLOCK", **kwargs: self.create(kind, name, action_type),
            set_priority=lambda pairs: self._pass(self.priority_sec),
        )

    def run(self, command, timeout_sec=None):  # 단말의 curl
        web = self._active("web") if self.post_url in command else []
        url = re.search(r'"(https?://[^"]+)"\s*$', command).group(1)
        for handle in web:
            self.web_events.insert(0, _event(
                id=len(self.web_events) + 1, policy_name=handle.name,
                policy_id=int(handle.policy_id), action="BLOCK", full_uri=url,
            ))
        return SimpleNamespace(stdout='"403"' if web else '"200"', stderr="")

    def security_events(self, lookback_min=10):  # web_log
        return list(self.web_events)

    def visit(self, url, case_id=""):
        casb = self._active("casb") if url.startswith(self.casb_url) else []
        own = url.replace("https://www.notion.so/", "https://www.notion.com/")
        blocker = next((handle for handle in casb if handle.action == "BLOCK"), None)
        screen, logged = "render", True
        if blocker and len(self.casb_visits) + 1 == self.casb_crash_on:
            raise RuntimeError("Target page, context or browser has been closed")
        if blocker:
            screen, logged = self._screen(blocker)
            self.casb_visits.append((url, screen))
        sent = self._now()
        for handle in casb:
            blocking = handle.action == "BLOCK"
            # "observed": 차단된 방문은 페이지 행을 남기고, 렌더링된 방문은
            # 페이지의 API 호출과 텔레메트리 행만 남긴다.
            observed = {"block": [own], "render": list(self.SUBREQUESTS)}.get(screen, [])
            rows = {"own": [own], "others": list(self.SUBREQUESTS), "none": [], "observed": observed}[
                self.casb_rows if blocking else "own"
            ]
            for uri in rows:
                if uri == own and not logged:
                    continue
                event = _event(
                    id=len(self.casb_events) + 1, rule_name=handle.name,
                    action=self.casb_action if blocking else handle.action,
                    in_app_service={"id": 3, "name": self.casb_app}, request_uri=uri,
                    time=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                )
                self.casb_events.insert(0, event)
                self._visible_at[event.event_id] = sent + self.row_delay_sec
        spec = self.visit_sec
        if isinstance(spec, (list, tuple)):
            spec = spec[min(max(len(self.casb_visits) - 1, 0), len(spec) - 1)]
        self._pass(spec)
        if blocker:
            if screen == "block":
                return TrafficResult(url=url, status_code=403, blocked=True, via="browser",
                                     detail="block page marker matched")
            if screen == "error":
                return TrafficResult(url=url, status_code=None, blocked=False, via="browser",
                                     detail="net::ERR_CONNECTION_RESET")
        return TrafficResult(url=url, status_code=200, blocked=False, via="browser",
                             detail="page rendered (HTTP 200)", delivered=True)

    def wait_for_security_event(self, match, *, timeout_sec=30.0, description="", **_):
        self._pass(self.dlp_sec)
        return _first(self.web_events, match, description, timeout_sec)

    def wait_for_event(self, match, *, timeout_sec=30.0, description="", **_):  # casb_log
        return _first(self.casb_events, match, description, timeout_sec)

    def events(self, lookback_min=10):  # casb_log
        if self.casb_read_error:
            raise self.casb_read_error
        now = self._now()
        return [e for e in self.casb_events if self._visible_at.get(e.event_id, 0.0) <= now]


def _journey_fixtures(tenant, monkeypatch):
    import tests.cross.test_user_journey as journey
    from bat.fixtures.policies import DlpPolicyFactory

    class FakeDlpFactory:
        keyword_rule = staticmethod(DlpPolicyFactory.keyword_rule)

        def __init__(self, rest):
            self.tenant = rest

        def temporary(self, name, rules):
            return self.tenant.create("dlp", name)

    monkeypatch.setattr(journey, "DlpPolicyFactory", FakeDlpFactory)
    from bat.fixtures.testdata import GENAI_TOPIC_ALL_RULES

    genai = SimpleNamespace(
        reference=lambda: {"id": 1},
        find_app=lambda name: {"id": 1},
        temporary=lambda name, apps, **kwargs: tenant.create("genai", name),
        find_id_by_name=lambda name: "41" if name in tenant.active else None,
        list=lambda: [
            {"id": 41, "name": name, "action_type": "BLOCK", "rules": GENAI_TOPIC_ALL_RULES,
             "gen_ai_app": [{"id": 1, "name": "ChatGPT"}]}
            for name, (kind, _) in tenant.active.items() if kind == "genai"
        ],
    )
    return dict(
        rest=tenant, web_policies=tenant.factory("web"), saas_access=tenant.factory("casb"),
        genai_policies=genai, browser_session=tenant, executor=tenant,
        web_log=tenant, casb_log=tenant,
    )


def _run_x_010(tenant, monkeypatch):
    return _run_case_body(
        "tests.cross.test_user_journey", "test_normal_workday_journey", "BAT-X-010",
        **_journey_fixtures(tenant, monkeypatch),
    )


def test_x_010_cannot_pass_when_its_dlp_leg_is_left_behind(instant_polling, monkeypatch):
    """DLP 단계만으로 USER_RESULT와 EVENT가 충족되더라도, 그 단계의 삭제가 실패하면 ERROR다."""
    tenant = _FakeJourneyTenant(fail_delete=("-dlpblock",))
    status, reason, case = _run_x_010(tenant, monkeypatch)
    assert status is Status.ERROR, reason
    assert "never ran" in reason
    assert not any(name.endswith(("-casb", "-genai")) for name in tenant.created)


def test_x_010_still_passes_when_only_its_last_leg_is_left_behind(instant_polling, monkeypatch):
    status, reason, case = _run_x_010(_FakeJourneyTenant(fail_delete=("-genai",)), monkeypatch)
    assert status is Status.PASS, reason
    assert case.cleanup_warnings


def test_x_010_passes_on_a_clean_run(instant_polling, monkeypatch):
    status, reason, case = _run_x_010(_FakeJourneyTenant(), monkeypatch)
    assert status is Status.PASS, reason
    assert not case.cleanup_warnings


# -- CASB BLOCK 단계: 차단된 페이지를 그 요청 자신의 행으로 판정한다 --------

CASB_BLOCK_LEGS = [
    ("tests.casb.test_casb_in_app", "test_saas_access_block_records_a_block_event", "BAT-CASB-004"),
    ("tests.cross.test_cross_casb_genai", "test_casb_block_survives_a_higher_priority_web_allow", "BAT-X-006"),
    ("tests.cross.test_user_journey", "test_normal_workday_journey", "BAT-X-010"),
    ("tests.cross.test_user_journey", "test_incident_lockdown_channels_stay_independent", "BAT-X-011"),
]

# 사용자가 본 화면, 행을 받은 요청, 행에 적힌 값 -> 판정
CASB_BLOCK_OUTCOMES = [
    pytest.param("block", "own", "BLOCK", Status.PASS, "all mandatory criteria passed", id="blocked-own-row"),
    pytest.param("render", "others", "BLOCK", Status.FAIL, "rendered under the BLOCK policy", id="rendered-other-rows"),
    pytest.param("render", "own", "BLOCK", Status.FAIL, "rendered under the BLOCK policy", id="rendered-own-row"),
    pytest.param("block", "others", "BLOCK", Status.UNVERIFIED, "are for other requests", id="blocked-other-rows"),
    pytest.param("block", "own", "LOGGING", Status.FAIL, "records action 'LOGGING'", id="own-row-not-block"),
    pytest.param("error", "own", "BLOCK", Status.UNVERIFIED, "inconclusive", id="no-answer"),
    pytest.param("block", "none", "BLOCK", Status.FAIL, "no security event appeared", id="no-row-at-all"),
]


@pytest.mark.parametrize("module, function, case_id", CASB_BLOCK_LEGS)
@pytest.mark.parametrize("screen, rows, action, expected, fragment", CASB_BLOCK_OUTCOMES)
def test_a_casb_block_leg_is_judged_on_the_blocked_page_and_its_own_row(
    module, function, case_id, screen, rows, action, expected, fragment, instant_polling, monkeypatch
):
    """페이지가 렌더링되면 그 API 호출과 텔레메트리의 BLOCK 행이 있어도 FAIL이다(rendered-other-rows)."""
    tenant = _FakeJourneyTenant(casb_screen=screen, casb_rows=rows, casb_action=action)
    status, reason, case = _run_case_body(module, function, case_id, **_journey_fixtures(tenant, monkeypatch))
    assert status is expected, reason
    assert fragment in reason
    judged = [s.actual["request"] for s in case.steps if isinstance(s.actual, dict) and "request" in s.actual]
    assert all("bat=" in uri for uri in judged), "a CASB row may only count for the marked request"


def test_a_casb_detection_case_is_not_failed_because_the_page_rendered(instant_polling, monkeypatch):
    """LOGGING 정책은 사용자를 통과시키므로, BAT-CASB-003은 렌더링된 페이지와 그 행으로 PASS한다."""
    status, reason, case = _run_case_body(
        "tests.casb.test_casb_in_app", "test_saas_access_detects_only_the_app_it_names", "BAT-CASB-003",
        **_journey_fixtures(_FakeJourneyTenant(), monkeypatch),
    )
    assert status is Status.PASS, reason
    screens = [s for s in case.steps if s.step is Step.USER_RESULT]
    assert screens and all(s.ok for s in screens)


# 가짜 시계에서 요청 여러 개가 들어갈 여유를 둔 전파 예산.
# 방문이 1초씩 걸리면 #1-#4는 0, 3, 6, 9초에 나가 10초 기한까지 돌아오고
# (#4는 정확히 기한에), #5는 기한에 나가며, 유지 요청 5개
# #6-#10이 11, 14, 17, 20, 23초에 뒤따른다.
SLOW_PROPAGATION = SimpleNamespace(run_id=RUN_ID, policy_propagation_timeout_sec=10, event_poll_timeout_sec=1)


def _run_casb_leg(module, function, case_id, tenant, monkeypatch):
    return _run_case_body(
        module, function, case_id, run_context=SLOW_PROPAGATION, **_journey_fixtures(tenant, monkeypatch)
    )


def _casb_screens(case, phase):
    return [s for s in case.steps if s.step is Step.USER_RESULT and f" {phase}, sent +" in s.detail]


def _judge_casb_block(tenant, clock, *, budget=10, event_timeout_sec=90, start_after=0.0, spent_reason=""):
    """가짜 테넌트에 SaaS Access BLOCK을 만들고 `start_after`초를 흘려보낸 뒤,
    expect_casb_block을 돌려 결과를 conftest와 같은 방식으로 분류한다."""
    from tests.conftest import _how_it_ended
    from tests.support import expect_casb_block, pass_case, policy_changed

    name = resource_name("BAT-CASB-004", RUN_ID)
    case = CaseResult(
        case_id="BAT-CASB-004", product="selfcheck", scenario="expect_casb_block",
        criteria=[Step.USER_RESULT.value, Step.EVENT.value],
    )
    with tenant.create("casb", name):
        changed = policy_changed(case, f"SaaS Access BLOCK {name} created")
        clock.now += start_after
        try:
            expect_casb_block(
                case, tenant, tenant, name, tenant.casb_url, changed=changed,
                propagation_timeout_sec=budget, event_timeout_sec=event_timeout_sec,
                expected_service=tenant.casb_app, failure="The SaaS Access BLOCK did not hold",
                budget_spent_reason=spent_reason,
            )
            pass_case(case)
        except BaseException:  # noqa: BLE001 - conftest처럼 아래에서 분류한다
            raised, message = _how_it_ended(SimpleNamespace(excinfo=pytest.ExceptionInfo.from_current()))
        else:
            raised, message = Raised.NOTHING, ""
    status, reason = classify(case, raised, message)
    return status, reason, case


def test_a_block_in_time_that_holds_five_times_with_its_rows_passes(instant_polling):
    tenant = _FakeJourneyTenant(
        casb_screen=_Screens(10, during=("render", "block")), casb_rows="observed", visit_sec=1.0
    )
    status, reason, case = _judge_casb_block(tenant, instant_polling)
    assert status is Status.PASS, reason
    hold = _casb_screens(case, "hold")
    assert len(hold) == 5 and all(s.kind is Kind.ASSERTION and s.ok for s in hold)
    rows = [s for s in case.steps if s.step is Step.EVENT and s.kind is Kind.ASSERTION]
    assert len(rows) == 5 and all(s.ok for s in rows) and len(case.event_ids) == 5


@pytest.mark.parametrize("during, relapsed", [
    pytest.param(("render", "block", "render"), "#3, #4, #5", id="renders-again-before-the-deadline"),
    pytest.param(("block", "block", "block", "block", "render"), "#5", id="renders-again-at-the-deadline"),
    pytest.param(("render", "render", "block"), "", id="stays-blocked-after-a-late-start"),
    pytest.param(("block",), "", id="blocked-throughout"),
])
def test_a_render_after_a_block_before_the_hold_is_a_stability_violation_that_fails(
    during, relapsed, instant_polling
):
    """이것만으로 FAIL이다. 여기서 기한 뒤 요청 5개는 전부 차단됐다."""
    tenant = _FakeJourneyTenant(casb_screen=_Screens(10, during=during), casb_rows="observed", visit_sec=1.0)
    status, reason, case = _judge_casb_block(tenant, instant_polling)
    hold = _casb_screens(case, "hold")
    assert len(hold) == 5 and all(s.kind is Kind.ASSERTION and s.ok for s in hold)
    violations = [s for s in case.steps if "propagation stability violation" in s.detail]
    if relapsed:
        assert status is Status.FAIL, reason
        assert f"propagation stability violation: {relapsed} rendered again after the block page of #" in reason
        assert violations and all(s.kind is Kind.ASSERTION and not s.ok for s in violations)
    else:
        assert status is Status.PASS, reason
        assert not violations


def test_a_block_that_only_takes_effect_after_the_budget_fails(instant_polling):
    tenant = _FakeJourneyTenant(
        casb_screen=_Screens(10, during=("render",), after=("block",)), casb_rows="observed", visit_sec=1.0
    )
    status, reason, case = _judge_casb_block(tenant, instant_polling)
    assert status is Status.FAIL, reason
    assert "did not take effect within the 10s propagation budget (no block page came back by the " \
           "deadline, and #5 sent at it still rendered)" in reason
    assert all(s.ok for s in _casb_screens(case, "hold")), "late, but blocked every time after the budget"
    delay = [s for s in case.steps if s.detail.startswith("propagation delay")]
    assert len(delay) == 1 and delay[0].kind is Kind.EVIDENCE
    assert "the first came in #6 (hold, sent +11.0s, back +12.0s)" in delay[0].detail


@pytest.mark.parametrize("position", [1, 2, 3, 4, 5])
def test_any_render_among_the_five_requests_after_the_budget_fails(position, instant_polling):
    after = tuple("render" if n == position else "block" for n in range(1, 6))
    tenant = _FakeJourneyTenant(casb_screen=_Screens(10, after=after), casb_rows="observed", visit_sec=1.0)
    status, reason, case = _judge_casb_block(tenant, instant_polling)
    assert status is Status.FAIL, reason
    assert f"1 of 5 requests after the 10s propagation budget rendered under the BLOCK policy: #{5 + position}" in reason


def test_five_blocks_with_one_request_unlogged_are_unverified(instant_polling):
    tenant = _FakeJourneyTenant(casb_screen=_Screens(10, unlogged=(3,)), casb_rows="observed", visit_sec=1.0)
    status, reason, case = _judge_casb_block(tenant, instant_polling)
    assert status is Status.UNVERIFIED, reason
    assert "are for other requests" in reason
    hold = _casb_screens(case, "hold")
    assert len(hold) == 5 and all(s.ok for s in hold)
    missing = [s for s in case.steps if s.step is Step.EVENT and s.kind is Kind.UNAVAILABLE]
    assert len(missing) == 1 and hold[2].detail.split(" (#")[0] in missing[0].detail


@pytest.mark.parametrize("read_error", [
    pytest.param(None, id="browser-error"),
    pytest.param(ApiError("GraphQL HTTP 502", status_code=502), id="log-api-error"),
    pytest.param(httpx.ConnectError("connection reset"), id="log-network-error"),
])
def test_a_network_error_does_not_soften_a_render_into_unverified(read_error, instant_polling):
    tenant = _FakeJourneyTenant(
        casb_screen=_Screens(10, after=("block", "error", "render", "block", "block")),
        casb_rows="observed", visit_sec=1.0, casb_read_error=read_error,
    )
    status, reason, case = _judge_casb_block(tenant, instant_polling)
    assert status is Status.FAIL, reason
    assert "1 of 5 requests after the 10s propagation budget rendered under the BLOCK policy: #8" in reason
    assert [s for s in case.steps if s.kind is Kind.UNAVAILABLE], "the error is still on record"


def test_an_unreadable_log_leaves_five_blocks_unverified_not_errored(instant_polling):
    tenant = _FakeJourneyTenant(
        casb_screen=_Screens(10), casb_rows="observed", visit_sec=1.0,
        casb_read_error=httpx.ConnectError("connection reset"),
    )
    status, reason, case = _judge_casb_block(tenant, instant_polling)
    assert status is Status.UNVERIFIED, reason
    assert "the CASB log could not be read (network failure, ConnectError: connection reset)" in reason


@pytest.mark.parametrize("after, expected", [
    pytest.param(("block", "render", "block"), Status.FAIL, id="after-a-render"),
    pytest.param(("block",), Status.ERROR, id="before-any-violation"),
])
def test_a_browser_failure_leaves_a_violation_already_seen_a_fail(after, expected, instant_polling):
    """브라우저가 기한 뒤 네 번째 요청(9번째 방문)에서 고장 난다."""
    tenant = _FakeJourneyTenant(
        casb_screen=_Screens(10, after=after), casb_rows="observed", visit_sec=1.0, casb_crash_on=9
    )
    status, reason, case = _judge_casb_block(tenant, instant_polling)
    assert status is expected, reason
    assert "browser has been closed" in reason
    if expected is Status.FAIL:
        assert "rendered under the BLOCK policy: #7 (then the browser failed" in reason
        assert [s for s in case.steps if s.kind is Kind.UNAVAILABLE and s.detail.startswith("only 3 of the 5")]


def test_a_row_wait_after_a_failure_is_bounded_and_does_not_undo_it(instant_polling):
    """끝내 오지 않는 행이 렌더링된 페이지를 FAIL 말고 다른 것으로 바꿀 수는 없다.
    그리고 일단 FAIL이면 그 행을 이벤트 타임아웃 끝까지 기다리지 않는다."""
    from tests.support import CASB_FAILED_ROW_WAIT_SEC

    tenant = _FakeJourneyTenant(
        casb_screen=_Screens(10, after=("render", "block")), casb_rows="observed", visit_sec=1.0,
        row_delay_sec=600,
    )
    status, reason, case = _judge_casb_block(tenant, instant_polling, event_timeout_sec=90)
    assert status is Status.FAIL, reason
    assert "rendered under the BLOCK policy: #6" in reason
    assert "no security event appeared" not in reason, "a short wait proves nothing about the log"
    ledger = next(s for s in case.steps if s.step is Step.ACTION and isinstance(s.actual, list))
    last_back = float(ledger.actual[-1]["back"].strip("+s"))  # 0.1초 단위로 반올림됨
    assert instant_polling.now - last_back <= CASB_FAILED_ROW_WAIT_SEC + 0.1
    missing = [s for s in case.steps if s.step is Step.EVENT and s.kind is Kind.UNAVAILABLE]
    assert len(missing) == 4 and all("once the check had failed" in s.detail for s in missing)


def test_rows_are_waited_for_in_full_while_the_verdict_still_depends_on_them(instant_polling):
    tenant = _FakeJourneyTenant(casb_screen=_Screens(10), casb_rows="observed", visit_sec=1.0, row_delay_sec=60)
    status, reason, case = _judge_casb_block(tenant, instant_polling, event_timeout_sec=90)
    assert status is Status.PASS, reason


@pytest.mark.parametrize("product, start_after, spent_reason, expected, fragment", [
    pytest.param(
        lambda t: "render" if t < 14 else "block", 5, "", Status.FAIL,
        "did not take effect within the 10s propagation budget", id="renders-past-the-real-budget",
    ),
    pytest.param(
        lambda t: "block" if t >= 3 else "render", 5, "", Status.PASS,
        "all mandatory criteria passed", id="blocked-in-time",
    ),
    pytest.param(
        lambda t: "block", 25, "", Status.UNVERIFIED,
        "the 10s propagation budget had run out before this check began", id="started-after-the-budget",
    ),
    pytest.param(
        lambda t: "block", 25, "judged by another case", Status.PASS,
        "all mandatory criteria passed", id="excluded-once-the-budget-is-spent",
    ),
])
def test_the_budget_counts_from_the_policy_change_not_from_the_check(
    product, start_after, spent_reason, expected, fragment, instant_polling
):
    tenant = _FakeJourneyTenant(casb_screen=product, casb_rows="observed", visit_sec=1.0)
    status, reason, case = _judge_casb_block(
        tenant, instant_polling, start_after=start_after, spent_reason=spent_reason
    )
    assert status is expected, reason
    assert fragment in reason
    timing = next(s for s in case.steps if s.detail.startswith("propagation deadline +10s from"))
    assert f"this check began at +{start_after:.1f}s and sent its first request at +{start_after:.1f}s" in timing.detail


def test_slow_requests_do_not_shrink_the_five_after_the_budget(instant_polling):
    """요청 하나가 얼마나 걸리든 예산 뒤에 요청 5개를 보낸다."""
    tenant = _FakeJourneyTenant(
        casb_screen=_Screens(10, after=("block", "block", "block", "render", "block")),
        casb_rows="observed", visit_sec=9.0,
    )
    status, reason, case = _judge_casb_block(tenant, instant_polling)
    assert len(_casb_screens(case, "hold")) == 5
    assert status is Status.FAIL, reason
    assert "1 of 5 requests after the 10s propagation budget rendered" in reason


@pytest.mark.parametrize("module, function, case_id", CASB_BLOCK_LEGS)
@pytest.mark.parametrize("screens", [
    pytest.param(_Screens(10, during=("render", "render", "render", "block"), after=("render",)),
                 id="renders-then-one-block-then-renders"),
    pytest.param(_Screens(10, during=("block",), after=("render",)), id="one-block-then-renders"),
    pytest.param(_Screens(10, after=("block", "block", "render", "block")), id="one-render-among-blocks"),
])
def test_one_block_page_among_renders_is_not_a_pass(
    module, function, case_id, screens, instant_polling, monkeypatch
):
    """렌더링된 페이지 사이에 차단 페이지가 하나 있으면 FAIL이다. 확인을 멈출 이유가 아니다."""
    tenant = _FakeJourneyTenant(casb_screen=screens, casb_rows="observed", visit_sec=1.0)
    status, reason, case = _run_casb_leg(module, function, case_id, tenant, monkeypatch)
    assert status is Status.FAIL, reason
    assert "rendered under the BLOCK policy" in reason
    let_through = [s for s in _casb_screens(case, "hold") if not s.ok]
    assert let_through and all(s.kind is Kind.ASSERTION for s in let_through)


@pytest.mark.parametrize("module, function, case_id", CASB_BLOCK_LEGS)
def test_renders_while_the_policy_propagates_are_recorded_not_failed(
    module, function, case_id, instant_polling, monkeypatch
):
    tenant = _FakeJourneyTenant(
        casb_screen=_Screens(10, during=("render", "render", "block")), casb_rows="observed", visit_sec=1.0
    )
    status, reason, case = _run_casb_leg(module, function, case_id, tenant, monkeypatch)
    assert status is Status.PASS, reason
    propagation = _casb_screens(case, "propagation")
    assert [s.actual for s in propagation[:3]] == ["page rendered", "page rendered", "block page"]
    assert all(s.kind is Kind.EVIDENCE for s in propagation)
    hold = _casb_screens(case, "hold")
    assert len(hold) == 5 and all(s.kind is Kind.ASSERTION and s.ok for s in hold)


@pytest.mark.parametrize("module, function, case_id", CASB_BLOCK_LEGS)
def test_a_late_block_fails_every_leg_while_its_budget_is_still_running(
    module, function, case_id, instant_polling, monkeypatch
):
    """BAT-X-011도 포함한다. 여기서는 DLP 채널에 시간이 들지 않아 CASB 정책의 예산이
    아직 남아 있었으므로, 그 전파 구간을 다른 케이스와 똑같이 판정한다."""
    tenant = _FakeJourneyTenant(
        casb_screen=_Screens(10, during=("render",), after=("block",)), casb_rows="observed", visit_sec=1.0
    )
    status, reason, case = _run_casb_leg(module, function, case_id, tenant, monkeypatch)
    assert status is Status.FAIL, reason
    assert "did not take effect within the 10s propagation budget" in reason
    assert not [s for s in case.steps if "excluded from judgment" in s.detail]


@pytest.mark.parametrize("module, function, case_id, reference", [
    (*CASB_BLOCK_LEGS[0], r"SaaS Access BLOCK BAT-CASB-004-\S+ created"),
    (*CASB_BLOCK_LEGS[1], r"web ALLOW BAT-X-006-\S+ raised to priority 1"),
    (*CASB_BLOCK_LEGS[2], r"SaaS Access BLOCK BAT-X-010-\S+ created"),
    (*CASB_BLOCK_LEGS[3], r"SaaS Access BLOCK BAT-X-011-\S+ created"),
])
def test_each_leg_counts_its_budget_from_its_own_policy_change(
    module, function, case_id, reference, instant_polling, monkeypatch
):
    tenant = _FakeJourneyTenant(casb_rows="observed")
    status, reason, case = _run_casb_leg(module, function, case_id, tenant, monkeypatch)
    assert status is Status.PASS, reason
    timing = next(s for s in case.steps if s.detail.startswith("propagation deadline +10s from"))
    assert re.match(rf"propagation deadline \+10s from: {reference} \(", timing.detail), timing.detail
    assert ("the CASB policy itself went in" in timing.detail) is (case_id == "BAT-X-006")


@pytest.mark.parametrize("renders_until, expected", [
    pytest.param(40, Status.FAIL, id="still-rendering-30s-after-the-casb-policy"),
    pytest.param(5, Status.PASS, id="blocked-by-then"),
])
def test_x_011_times_its_casb_leg_from_the_casb_policy_not_from_after_the_dlp_channel(
    renders_until, expected, instant_polling, monkeypatch
):
    """DLP 채널이 먼저 돈다(여기서는 30초). 그래서 첫 CASB 요청 때는 CASB 정책의
    예산이 이미 한참 지났다. 그때 렌더링된 페이지는 두 BLOCK 채널이 모두 활성이어야 할
    때 렌더링된 것이다."""
    tenant = _FakeJourneyTenant(
        casb_screen=lambda t: "render" if t < renders_until else "block", casb_rows="observed",
        visit_sec=1.0, dlp_sec=30.0,
    )
    status, reason, case = _run_casb_leg(*CASB_BLOCK_LEGS[3], tenant, monkeypatch)
    assert status is expected, reason
    timing = next(s for s in case.steps if s.detail.startswith("propagation deadline +10s from"))
    assert "this check began at +30.0s and sent its first request at +30.0s; the budget had " \
           "already run out, so the propagation window is excluded from judgment" in timing.detail
    assert not _casb_screens(case, "propagation") and not _casb_screens(case, "boundary")
    assert len(_casb_screens(case, "hold")) == 5


def test_every_casb_request_is_recorded_and_judged_on_its_own_row(instant_polling, monkeypatch):
    from tests.support import marker_of

    tenant = _FakeJourneyTenant(
        casb_screen=_Screens(10, during=("render", "block")), casb_rows="observed", visit_sec=1.0
    )
    status, reason, case = _run_casb_leg(*CASB_BLOCK_LEGS[0], tenant, monkeypatch)
    assert status is Status.PASS, reason
    sent = [url for url, _ in tenant.casb_visits]
    recorded = [s.detail.split(" (#")[0] for s in case.steps if s.step is Step.USER_RESULT and " (#" in s.detail]
    assert recorded == sent, "one record per request, in the order they were made"
    hold = [s.detail.split(" (#")[0] for s in _casb_screens(case, "hold")]
    assert hold == sent[-5:]
    judged = [s.actual["request"] for s in case.steps if s.step is Step.EVENT and s.kind is Kind.ASSERTION]
    assert [marker_of(uri) for uri in judged] == [marker_of(url) for url in hold]
    ledger = next(s for s in case.steps if s.step is Step.ACTION and isinstance(s.actual, list))
    assert [entry["marker"] for entry in ledger.actual] == [marker_of(url) for url in sent]
    assert [entry["phase"] for entry in ledger.actual] == ["propagation"] * 4 + ["boundary"] + ["hold"] * 5
    assert all(entry["row"] for entry in ledger.actual if entry["result"] == "block page")


def test_a_transient_error_after_propagation_is_unverified_not_a_failure(instant_polling, monkeypatch):
    tenant = _FakeJourneyTenant(
        casb_screen=_Screens(10, after=("block", "error", "block")), casb_rows="observed", visit_sec=1.0
    )
    status, reason, case = _run_casb_leg(*CASB_BLOCK_LEGS[0], tenant, monkeypatch)
    assert status is Status.UNVERIFIED, reason
    assert "inconclusive" in reason


# -- 전파 기한: 기한에 나간 요청이 증명할 수 있는 것과 없는 것 ---

def _effective_from(moment):
    """정책이 들어간 지 `moment`초 뒤에 BLOCK이 적용되는 제품."""
    return lambda elapsed: "block" if elapsed >= moment else "render"


def _ledger(case):
    ledger = next(s for s in case.steps if s.step is Step.ACTION and isinstance(s.actual, list))
    return [(e["request"], e["phase"], e["sent"], e["back"]) for e in ledger.actual]


def test_each_request_is_placed_by_when_it_went_out_and_came_back(instant_polling):
    tenant = _FakeJourneyTenant(casb_screen=_effective_from(0), casb_rows="observed", visit_sec=1.0)
    status, reason, case = _judge_casb_block(tenant, instant_polling)
    assert status is Status.PASS, reason
    assert _ledger(case) == [
        (1, "propagation", "+0.0s", "+1.0s"), (2, "propagation", "+3.0s", "+4.0s"),
        (3, "propagation", "+6.0s", "+7.0s"), (4, "propagation", "+9.0s", "+10.0s"),
        (5, "boundary", "+10.0s", "+11.0s"),
        (6, "hold", "+11.0s", "+12.0s"), (7, "hold", "+14.0s", "+15.0s"), (8, "hold", "+17.0s", "+18.0s"),
        (9, "hold", "+20.0s", "+21.0s"), (10, "hold", "+23.0s", "+24.0s"),
    ]
    boundary = _casb_screens(case, "boundary")
    assert len(boundary) == 1 and boundary[0].kind is Kind.EVIDENCE
    assert "sent at the 10s deadline: no proof it took effect in time" in boundary[0].detail


@pytest.mark.parametrize("effective, visit_sec, expected, fragment", [
    pytest.param(8.5, 1.0, Status.PASS, "all mandatory criteria passed", id="blocked-and-back-exactly-at-the-deadline"),
    pytest.param(9.5, 1.0, Status.UNVERIFIED, "the first was #5, sent at it", id="first-block-sent-at-the-deadline"),
    pytest.param(8.5, (1, 1, 1, 3), Status.UNVERIFIED, "the first was #4, in flight across it",
                 id="first-block-out-across-the-deadline"),
    pytest.param(10.5, 1.0, Status.FAIL, "#5 sent at it still rendered", id="still-rendering-at-the-deadline"),
    pytest.param(9.5, (1, 1, 1, 3), Status.UNVERIFIED, "#4 rendered while in flight across it",
                 id="render-out-across-the-deadline"),
])
def test_the_deadline_boundary_gives_no_false_pass_and_no_false_fail(
    effective, visit_sec, expected, fragment, instant_polling
):
    """기한까지 돌아온 차단 페이지만이 정책이 제때 적용됐다는 증거다.
    기한에 걸친 요청은 어느 쪽도 증명하지 못한다. 단, 기한 시각에 나갔는데도 렌더링됐다면
    예외다. 여기 나오는 제품은 각각 그 시각 이후 모든 요청을 차단한다."""
    tenant = _FakeJourneyTenant(casb_screen=_effective_from(effective), casb_rows="observed", visit_sec=visit_sec)
    status, reason, case = _judge_casb_block(tenant, instant_polling)
    assert status is expected, reason
    assert fragment in reason
    hold = _casb_screens(case, "hold")
    assert len(hold) == 5 and all(s.kind is Kind.ASSERTION and s.ok for s in hold)
    boundary = _casb_screens(case, "boundary")
    assert len(boundary) == 1 and boundary[0].kind is Kind.EVIDENCE, "the boundary request is never a hold request"


@pytest.mark.parametrize("trouble", [
    pytest.param(dict(casb_read_error=ApiError("GraphQL HTTP 502", status_code=502)), id="log-api-error"),
    pytest.param(dict(casb_read_error=AuthError("GraphQL client is not logged in")), id="session-refused"),
    pytest.param(dict(casb_read_error=SelfBlockedError("intercepted by an SSE block page")), id="self-blocked"),
    pytest.param(dict(casb_crash_on=8), id="browser-failure"),
])
def test_a_stability_violation_stays_a_fail_through_whatever_follows(trouble, instant_polling):
    tenant = _FakeJourneyTenant(
        casb_screen=_Screens(10, during=("render", "block", "render")), casb_rows="observed",
        visit_sec=1.0, **trouble,
    )
    status, reason, case = _judge_casb_block(tenant, instant_polling)
    assert status is Status.FAIL, reason
    assert "propagation stability violation: #3, #4, #5 rendered again after the block page of #2" in reason


# -- 실패하는 casb_security_log 조회 ----------------------------------------

LOG_READ_FAILURES = [
    pytest.param(ApiError("GraphQL HTTP 502", status_code=502), "api", Status.UNVERIFIED, id="api"),
    pytest.param(httpx.ConnectError("connection reset"), "network", Status.UNVERIFIED, id="network"),
    pytest.param(AuthError("GraphQL client is not logged in"), "session", Status.ERROR, id="session-auth-error"),
    pytest.param(ApiError("GraphQL errors: Duplicate login\nThe cached console session is stale."),
                 "session", Status.ERROR, id="session-duplicate-login"),
    pytest.param(ApiError("GraphQL HTTP 401", status_code=401), "session", Status.ERROR, id="session-http-401"),
    pytest.param(SelfBlockedError("The GraphQL request was intercepted by an SSE block page"),
                 "self-block", Status.ERROR, id="self-block"),
]


@pytest.mark.parametrize("error, kind, expected", LOG_READ_FAILURES)
def test_log_read_failures_are_told_apart(error, kind, expected):
    from tests.support import _log_read_failure

    assert _log_read_failure(error) == kind


@pytest.mark.parametrize("error, kind, expected", LOG_READ_FAILURES)
def test_a_log_read_failure_before_anything_failed_is_judged_by_its_kind(error, kind, expected, instant_polling):
    """읽지 못한 행은 검증 불가다. 거부된 세션이나 자기 차단은 BAT의 다른 곳과
    마찬가지로 실행 문제다."""
    tenant = _FakeJourneyTenant(casb_screen=_Screens(10), casb_rows="observed", visit_sec=1.0, casb_read_error=error)
    status, reason, case = _judge_casb_block(tenant, instant_polling)
    assert status is expected, reason
    unread = [s for s in case.steps if s.step is Step.EVENT and s.kind is Kind.UNAVAILABLE]
    assert len(unread) == 5 and all(f"could not be read ({kind} failure" in s.detail for s in unread)


@pytest.mark.parametrize("error, kind, expected", LOG_READ_FAILURES)
def test_a_log_read_failure_never_overturns_a_fail(error, kind, expected, instant_polling):
    tenant = _FakeJourneyTenant(
        casb_screen=_Screens(10, after=("render", "block")), casb_rows="observed", visit_sec=1.0,
        casb_read_error=error,
    )
    status, reason, case = _judge_casb_block(tenant, instant_polling)
    assert status is Status.FAIL, reason
    assert "rendered under the BLOCK policy: #6" in reason


def test_a_log_read_that_works_records_no_read_failure(instant_polling):
    tenant = _FakeJourneyTenant(casb_screen=_Screens(10), casb_rows="observed", visit_sec=1.0)
    status, reason, case = _judge_casb_block(tenant, instant_polling)
    assert status is Status.PASS, reason
    assert not [s for s in case.steps if "could not be read" in s.detail]


# -- BAT-X-011과 BAT-X-006: 예산을 어느 시각부터 세는가 ----------------

@pytest.mark.parametrize("dlp_sec, expected", [
    pytest.param(30.0, Status.PASS, id="dlp-channel-outlasted-the-budget"),
    pytest.param(3.0, Status.FAIL, id="budget-still-running"),
])
def test_x_011_excludes_its_propagation_window_only_once_the_budget_is_spent(
    dlp_sec, expected, instant_polling, monkeypatch
):
    """두 번 모두 같은 늦은 차단이다. 전파 구간을 빼면 기한 뒤 요청 5개가 판정하고,
    그 요청은 차단됐다. 예산이 아직 남아 있으면 그 구간을 판정한다."""
    tenant = _FakeJourneyTenant(
        casb_screen=_Screens(10, during=("render",), after=("block",)), casb_rows="observed",
        visit_sec=1.0, dlp_sec=dlp_sec,
    )
    status, reason, case = _run_casb_leg(*CASB_BLOCK_LEGS[3], tenant, monkeypatch)
    assert status is expected, reason
    exclusion = [s for s in case.steps if s.detail.startswith("propagation window excluded from judgment")]
    if dlp_sec > 10:
        assert len(exclusion) == 1 and exclusion[0].kind is Kind.EVIDENCE
        assert exclusion[0].ok is False, "excluded is never recorded as a pass"
        assert "not passed: the DLP channel ran first and outlasted the CASB policy's budget" in exclusion[0].detail
        assert "first request +30.0s after SaaS Access BLOCK BAT-X-011-" in exclusion[0].detail
        assert not [s for s in case.steps if s.kind is Kind.ASSERTION and s.detail.startswith("block page back by")]
    else:
        assert not exclusion
        assert "did not take effect within the 10s propagation budget" in reason


@pytest.mark.parametrize("screen, expected, fragment", [
    pytest.param(_Screens(10, after=("block", "render", "block")), Status.FAIL,
                 "1 of 5 requests after the 10s propagation budget rendered under the BLOCK policy: #2",
                 id="a-render-after-the-deadline"),
    pytest.param(_Screens(10, unlogged=(4,)), Status.UNVERIFIED, "are for other requests", id="a-row-missing"),
])
def test_x_011_still_judges_its_five_requests_and_their_rows_when_excluded(
    screen, expected, fragment, instant_polling, monkeypatch
):
    tenant = _FakeJourneyTenant(casb_screen=screen, casb_rows="observed", visit_sec=1.0, dlp_sec=30.0)
    status, reason, case = _run_casb_leg(*CASB_BLOCK_LEGS[3], tenant, monkeypatch)
    assert status is expected, reason
    assert fragment in reason
    assert [s for s in case.steps if s.detail.startswith("propagation window excluded from judgment")]
    assert len(_casb_screens(case, "hold")) == 5


@pytest.mark.parametrize("effective, expected", [
    pytest.param(15, Status.PASS, id="in-time-from-the-priority-change"),
    pytest.param(19, Status.FAIL, id="late-even-from-the-priority-change"),
])
def test_x_006_counts_its_budget_from_the_priority_change_and_reports_both_times(
    effective, expected, instant_polling, monkeypatch
):
    """여기서는 우선순위 변경에 8초가 걸린다. CASB 정책 생성 시각부터 세면, 10초
    예산은 테스트 대상 구성이 생기기도 전에 끝났을 것이다."""
    tenant = _FakeJourneyTenant(
        casb_screen=_effective_from(effective), casb_rows="observed", visit_sec=1.0, priority_sec=8.0
    )
    status, reason, case = _run_casb_leg(*CASB_BLOCK_LEGS[1], tenant, monkeypatch)
    assert status is expected, reason
    timing = next(s for s in case.steps if s.detail.startswith("propagation deadline +10s from"))
    assert re.match(r"propagation deadline \+10s from: web ALLOW BAT-X-006-\S+ raised to priority 1 \(", timing.detail)
    assert "the CASB policy itself went in 8.0s before that: SaaS Access BLOCK BAT-X-006-" in timing.detail
    assert "sent its first request at +0.0s (+8.0s after the CASB policy went in)" in timing.detail
    setup = [s.detail for s in case.steps if s.step is Step.SETUP]
    assert [d for d in setup if re.match(r"SaaS Access BLOCK BAT-X-006-\S+ created at ", d)]
    assert [d for d in setup if re.match(r"web ALLOW BAT-X-006-\S+ raised to priority 1 at ", d)]


# -- BAT-ZTNA-001: 인증 행은 이 단말의 것이어야 한다 ---------------------

THIS_DEVICE = "0A1B2C3D-4E5F-1111-2222-333344445555"
CONFIGURED_DEVICE = "9F8E7D6C-5B4A-3333-4444-555566667777"
OTHER_DEVICE = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"  # 서버 터널의 id에는 대시가 없다


def _auth_row(row_id, result, device_id=None, time="2026-10-13T06:17:04Z"):
    return _event(id=row_id, auth_result=result, device_id=device_id, login_id="someone",
                  user_name="someone", src_ip="10.0.8.1", time=time)


# 이 단말의 것이 아닌 auth_log 행: 몇 분마다 다시 연결하는 서버 터널, 그리고
# 단말이 아예 없는 행.
UNRELATED_AUTH_ROWS = [
    _auth_row(101, "AUTH_DISCONNECT_SERVER_TUNNEL", OTHER_DEVICE),
    _auth_row(102, "AUTH_CONNECT_SERVER_TUNNEL", OTHER_DEVICE),
    _auth_row(103, "AUTH_SUCCESS_CONNECTOR"),
    _auth_row(104, "AUTH_SUCCESS_CONSOLE"),
]


class _FakeConnectorEndpoint:
    """BAT-ZTNA-001용 단말(커넥터 프로세스, 하드웨어 UUID)과 auth_log."""

    def __init__(self, rows, *, uuid=THIS_DEVICE, running=True, honours_filter=True):
        self.rows, self.uuid, self.running, self.honours_filter = list(rows), uuid, running, honours_filter
        self.device_filters: list[str] = []

    def run_powershell(self, script, timeout_sec=60):
        if "Get-Process -Name 'AIConnector for Client'" in script:
            output = "Running" if self.running else "NotRunning"
        elif "Win32_ComputerSystemProduct" in script:
            output = self.uuid
        else:
            output = ""
        return SimpleNamespace(stdout=f"{output}\r\n", stderr="", ok=True)

    def events(self, *, lookback_min=10, device_id="", **_):
        self.device_filters.append(device_id)
        if device_id and self.honours_filter:
            return [row for row in self.rows if row.get("device_id") == device_id]
        return list(self.rows)


def _run_ztna_001(endpoint, configured_device_id=""):
    lane = SimpleNamespace(endpoint=SimpleNamespace(name="local-pc", device_id=configured_device_id))
    return _run_case_body(
        "tests.ztna.test_ztna_access", "test_connector_session_is_recorded", "BAT-ZTNA-001",
        lane=lane, auth_log=endpoint, executor=endpoint,
    )


@pytest.mark.parametrize("honours_filter", [True, False], ids=["filtered", "filter-ignored"])
def test_ztna_001_does_not_pass_on_other_devices_auth_rows(honours_filter):
    """다른 장치(서버 터널, 콘솔 로그인)의 인증 행으로는 BAT-ZTNA-001이 절대 PASS하지 않는다."""
    endpoint = _FakeConnectorEndpoint(UNRELATED_AUTH_ROWS, honours_filter=honours_filter)
    status, reason, case = _run_ztna_001(endpoint)
    assert status is Status.UNVERIFIED, reason
    assert not case.event_ids
    assert THIS_DEVICE in endpoint.device_filters


def test_ztna_001_passes_on_this_endpoints_own_sign_in():
    own = _auth_row(201, "AUTH_SUCCESS_SDP", THIS_DEVICE)
    status, reason, case = _run_ztna_001(_FakeConnectorEndpoint([*UNRELATED_AUTH_ROWS, own]))
    assert status is Status.PASS, reason
    assert case.event_ids == ["201"]


def test_ztna_001_fails_when_this_endpoints_newest_row_is_a_disconnect():
    """세션이 맺어졌던 기록이 있어도 가장 최근 행이 연결 해제면 지금 연결돼 있다는 근거가 아니다."""
    rows = [
        *UNRELATED_AUTH_ROWS,
        _auth_row(206, "AUTH_CONNECT_VPN", THIS_DEVICE, time="2026-10-13T06:00:00Z"),
        _auth_row(202, "AUTH_DISCONNECT_VPN", THIS_DEVICE, time="2026-10-13T07:00:00Z"),
    ]
    status, reason, case = _run_ztna_001(_FakeConnectorEndpoint(rows))
    assert status is Status.FAIL, reason
    assert "AUTH_DISCONNECT_VPN" in reason


def test_ztna_001_a_reconnect_after_a_disconnect_passes():
    rows = [
        *UNRELATED_AUTH_ROWS,
        _auth_row(202, "AUTH_DISCONNECT_VPN", THIS_DEVICE, time="2026-10-13T06:00:00Z"),
        _auth_row(207, "AUTH_CONNECT_VPN", THIS_DEVICE, time="2026-10-13T07:00:00Z"),
    ]
    status, reason, case = _run_ztna_001(_FakeConnectorEndpoint(rows))
    assert status is Status.PASS, reason
    assert case.event_ids == ["207"]


@pytest.mark.parametrize("uuid", ["", "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF", "To be filled by O.E.M."])
def test_ztna_001_without_a_usable_device_id_is_unverified(uuid):
    rows = [*UNRELATED_AUTH_ROWS, _auth_row(203, "AUTH_SUCCESS_SDP", uuid or None)]
    status, reason, case = _run_ztna_001(_FakeConnectorEndpoint(rows, uuid=uuid))
    assert status is Status.UNVERIFIED, reason
    assert "No device id" in reason


def test_ztna_001_a_configured_device_id_takes_precedence():
    rows = [*UNRELATED_AUTH_ROWS, _auth_row(204, "AUTH_CONNECT_VPN", CONFIGURED_DEVICE)]
    endpoint = _FakeConnectorEndpoint(rows)
    status, reason, case = _run_ztna_001(endpoint, configured_device_id=CONFIGURED_DEVICE)
    assert status is Status.PASS, reason
    assert CONFIGURED_DEVICE in endpoint.device_filters and THIS_DEVICE not in endpoint.device_filters


def test_ztna_001_still_fails_when_the_connector_is_stopped():
    own = _auth_row(205, "AUTH_SUCCESS_SDP", THIS_DEVICE)
    status, reason, case = _run_ztna_001(_FakeConnectorEndpoint([own], running=False))
    assert status is Status.FAIL, reason


# -- BAT-SWG-022: 목적지 IP로 직접 접속해도 호스트 차단이 유지돼야 한다 -------

RAW_IP = "198.51.100.7"  # TEST-NET-2


class _FakeRawIpTenant:
    """BAT-SWG-022용 웹 정책 API, 단말(nslookup, curl), 보안로그.

    httpbin.org는 RAW_IP로 해석된다. curl 요청은 rule이 맞는 첫 활성 BLOCK 정책에
    차단되고(403) 그 정책으로 기록된다. 그런 정책이 없으면 맞는 활성 정책이 전부 기록하고
    요청은 통과한다(200). HTTP_HOST는 URL의 호스트를 비교하므로, IP를 직접 쓴 URL은
    `maps_ip_to_host`일 때만 매칭된다. `blocks_hostname`을 끄면 아무것에도 매칭되지 않는다.
    기본값은 실제로 관측된 동작이다. IP 직접 접속은 통과하고, LOGGING DESTINATION_IP
    정책이 그것을 기록한다."""

    def __init__(self, *, maps_ip_to_host=False, sees_raw_ip=True, ip_answers=True, blocks_hostname=True):
        self.maps_ip_to_host, self.sees_raw_ip, self.ip_answers = maps_ip_to_host, sees_raw_ip, ip_answers
        self.blocks_hostname = blocks_hostname
        self.active: dict[str, SimpleNamespace] = {}
        self.events: list[SecurityEvent] = []
        self._ids = iter(range(600, 700))

    @contextlib.contextmanager
    def temporary(self, name, rules, *, action_type="BLOCK", **_):
        handle = SimpleNamespace(policy_id=str(next(self._ids)), name=name, action=str(action_type), rules=rules)
        self.active[name] = handle
        try:
            yield handle
        finally:
            del self.active[name]

    def _matches(self, handle, host):
        from bat.fixtures.enums import Subject
        from bat.fixtures.testdata import BLOCK_TARGET_HOST

        named = BLOCK_TARGET_HOST if host == RAW_IP and self.maps_ip_to_host else host
        resolved = RAW_IP if host in (RAW_IP, BLOCK_TARGET_HOST) else None
        checks = {
            Subject.HTTP_HOST: lambda values: self.blocks_hostname and named in values,
            Subject.DESTINATION_IP: lambda values: resolved in values,
        }
        return all(checks.get(rule["subject"], lambda values: False)(rule["value"]) for rule in handle.rules)

    def run(self, command, timeout_sec=None):  # 단말
        from urllib.parse import urlsplit

        from bat.fixtures.testdata import BLOCK_TARGET_HOST

        if command.startswith("nslookup"):
            return SimpleNamespace(stderr="", stdout=(
                f"Server:  UnKnown\nAddress:  127.0.2.1\n\nName:    {BLOCK_TARGET_HOST}\nAddress:  {RAW_IP}\n"
            ))
        url = re.search(r'"(https?://[^"]+)"\s*$', command).group(1)
        raw = urlsplit(url).hostname == RAW_IP
        if raw and not self.ip_answers:
            return SimpleNamespace(stdout='"000"', stderr="")
        if raw and not self.sees_raw_ip:
            return SimpleNamespace(stdout='"200"', stderr="")
        ordered = sorted(self.active.values(), key=lambda handle: int(handle.policy_id))
        for handle in ordered:
            if handle.action == "BLOCK" and self._matches(handle, urlsplit(url).hostname):
                self._log(handle, url)
                return SimpleNamespace(stdout='"403"', stderr="")
        for handle in ordered:
            if self._matches(handle, urlsplit(url).hostname):
                self._log(handle, url)
        return SimpleNamespace(stdout='"200"', stderr="")

    def _log(self, handle, url):
        self.events.insert(0, _event(
            id=len(self.events) + 1, policy_name=handle.name, policy_id=int(handle.policy_id),
            action=handle.action, full_uri=url,
        ))

    def security_events(self, lookback_min=10):
        return list(self.events)

    def wait_for_security_event(self, match, *, timeout_sec=30.0, description="", **_):
        return _first(self.events, match, description, timeout_sec)


def _run_swg_022(tenant):
    return _run_case_body(
        "tests.swg.test_swg_http_host", "test_host_block_matches_the_hostname_not_the_raw_ip", "BAT-SWG-022",
        web_policies=tenant, executor=tenant, web_log=tenant,
    )


def _reach_records(case):
    return [s for s in case.steps if s.kind is Kind.EVIDENCE and "reach policy" in str(s.expected)]


@pytest.mark.parametrize(
    "options, expected",
    [({}, Status.PASS), ({"maps_ip_to_host": True}, Status.FAIL), ({"ip_answers": False}, Status.UNVERIFIED)],
    ids=["raw-ip-gets-through", "raw-ip-blocked", "raw-ip-no-answer"],
)
def test_swg_022_the_raw_ip_request_has_to_go_through(options, expected, instant_polling):
    """HTTP_HOST는 호스트명 조건이라 IP 직접 접속은 통과해야 한다(판정 기준). 막히면 FAIL, 응답이 없으면 UNVERIFIED."""
    status, reason, case = _run_swg_022(_FakeRawIpTenant(**options))
    assert status is expected, reason
    raw = [s for s in case.steps if s.step is Step.USER_RESULT and "raw-IP request" in str(s.expected)]
    assert raw and all(s.kind in (Kind.ASSERTION, Kind.UNAVAILABLE) for s in raw)


def test_swg_022_the_hostname_block_needs_its_own_row(instant_polling):
    """호스트명 차단(403)은 그 요청 자신의 정책 행(마커)이 있어야 정책 차단이다."""
    tenant = _FakeRawIpTenant()
    tenant._log = lambda handle, url: None  # 아무 행도 남기지 않는 제품
    status, reason, case = _run_swg_022(tenant)
    assert status is Status.FAIL, reason
    assert "no security event appeared" in reason


def test_swg_022_records_that_sse_saw_the_raw_ip_request(instant_polling):
    status, reason, case = _run_swg_022(_FakeRawIpTenant())
    assert status is Status.PASS, reason
    assert [(s.ok, "it sees the request" in s.detail) for s in _reach_records(case)] == [(True, True)]


def test_swg_022_records_when_sse_never_saw_the_raw_ip_request(instant_polling):
    status, reason, case = _run_swg_022(_FakeRawIpTenant(sees_raw_ip=False))
    assert status is Status.PASS, reason
    assert [(s.ok, "may not reach SSE" in s.detail) for s in _reach_records(case)] == [(False, True)]


def test_swg_022_still_fails_when_the_hostname_is_not_blocked(instant_polling):
    status, reason, case = _run_swg_022(_FakeRawIpTenant(blocks_hostname=False))
    assert status is Status.FAIL, reason
    assert "by hostname" in reason

# -- 케이스 현황 (reports/bat-test-status.xlsx, 스테이지별 열) ----------

_CASE_FILE = '''
import pytest

pytestmark = [pytest.mark.product("swg")]


{cases}
'''


def _write_cases(tests_dir, *specs):
    """specs: (case_id, 추가 데코레이터 줄) -> 호출 한 번에 테스트 모듈 하나."""
    body = "\n\n".join(
        f'@pytest.mark.case("{cid}")\n{extra}@pytest.mark.priority("P2")\n'
        f'def test_{cid.lower().replace("-", "_")}(case):\n    """{cid} 시나리오."""\n'
        for cid, extra in specs
    )
    path = tests_dir / f"test_{specs[0][0].lower().replace('-', '_')}.py"
    path.write_text(_CASE_FILE.format(cases=body), encoding="utf-8")


def _write_run(reports_dir, profile, run_id, started, results):
    """bat run이 남기는 형태의 저장된 실행: 케이스별 result.json과 run-report.json."""
    run_dir = reports_dir / started[:10] / run_id
    cases = []
    for cid, status in results.items():
        case = {"case_id": cid, "product": "swg", "priority": "P2", "scenario": cid, "status": status,
                "started_at": started, "verdict_reason": f"{cid} {status} reason"}
        (run_dir / cid).mkdir(parents=True)
        (run_dir / cid / "result.json").write_text(json.dumps(case), encoding="utf-8")
        cases.append(case)
    report = {"run_id": run_id, "profile": profile, "started_at": started, "cases": cases}
    (run_dir / "run-report.json").write_text(json.dumps(report), encoding="utf-8")


def _tracker(tmp_path):
    tests_dir, reports_dir = tmp_path / "tests", tmp_path / "reports"
    tests_dir.mkdir()
    reports_dir.mkdir()
    return tests_dir, reports_dir


def _rows(reports_dir):
    from bat.report import status_book

    return {r["case_id"]: r for r in status_book.read_rows(status_book.book_path(reports_dir))}


def test_a_new_case_is_added_to_the_tracker_on_every_stage(tmp_path):
    from bat.report import status_book

    tests_dir, reports_dir = _tracker(tmp_path)
    _write_cases(tests_dir, ("BAT-SWG-001", ""), ("BAT-SWG-002", "@pytest.mark.crud\n"))
    assert status_book.sync_catalog(reports_dir, tests_dir) == ["BAT-SWG-001", "BAT-SWG-002"]
    rows = _rows(reports_dir)
    for stage in ("qa", "lg", "real"):
        assert {r[f"{stage}_status"] for r in rows.values()} == {"미실행"}
    assert "crud" in rows["BAT-SWG-002"]["note"]

    status_book.upsert_case("BAT-SWG-001", reports_dir, status="PASS", note="kept")
    _write_cases(tests_dir, ("BAT-FW-099", ""))
    assert status_book.sync_catalog(reports_dir, tests_dir) == ["BAT-FW-099"]
    kept = _rows(reports_dir)["BAT-SWG-001"]
    assert (kept["status"], kept["note"]) == ("PASS", "kept"), "a sync never touches what is already there"
    assert status_book.sync_catalog(reports_dir, tests_dir) == []


def test_a_run_fills_only_its_own_stage_columns(tmp_path):
    from bat.report import status_book

    tests_dir, reports_dir = _tracker(tmp_path)
    _write_cases(tests_dir, ("BAT-SWG-001", ""), ("BAT-SWG-002", ""))
    status_book.sync_catalog(reports_dir, tests_dir)
    status_book.upsert_case("BAT-SWG-001", reports_dir, status="PASS", actual_results="by hand")
    _write_run(reports_dir, "lguplus", "20261015-100000-aaaaaa", "2026-10-15T10:00:00",
               {"BAT-SWG-001": "FAIL", "BAT-SWG-002": "UNVERIFIED"})
    path = status_book.record_run("lguplus", "20261015-100000-aaaaaa", reports_dir, tests_dir)
    assert path.name == "bat-test-status.xlsx"
    rows = _rows(reports_dir)
    one = rows["BAT-SWG-001"]
    assert (one["lg_status"], one["lg_last_run"]) == ("FAIL", "20261015-100000-aaaaaa")
    assert (one["status"], one["actual_results"]) == ("PASS", "by hand"), "the hand-kept columns stay"
    assert rows["BAT-SWG-002"]["lg_status"] == "UNVERIFIED", "UNVERIFIED is kept as itself, never as a pass"
    assert {(r["qa_status"], r["real_status"]) for r in rows.values()} == {("미실행", "미실행")}


def test_stage_columns_take_each_case_latest_result_on_that_stage(tmp_path):
    from bat.report import status_book

    tests_dir, reports_dir = _tracker(tmp_path)
    _write_cases(tests_dir, ("BAT-SWG-001", ""), ("BAT-SWG-002", ""))
    _write_run(reports_dir, "swg", "20260917-100000-aaaaaa", "2026-09-17T10:00:00", {"BAT-SWG-001": "FAIL"})
    _write_run(reports_dir, "qa", "20261014-100000-bbbbbb", "2026-10-14T10:00:00", {"BAT-SWG-001": "PASS"})
    _write_run(reports_dir, "real", "20261020-100000-cccccc", "2026-10-20T10:00:00", {"BAT-SWG-001": "FAIL"})
    _write_run(reports_dir, "swg", "20260918-100000-dddddd", "2026-09-18T10:00:00", {"BAT-SWG-002": "SKIP"})
    status_book.rebuild_stage_columns(reports_dir, tests_dir)
    rows = _rows(reports_dir)
    assert (rows["BAT-SWG-001"]["qa_status"], rows["BAT-SWG-001"]["qa_last_run"]) == ("PASS", "20261014-100000-bbbbbb")
    assert rows["BAT-SWG-001"]["real_status"] == "FAIL"
    assert rows["BAT-SWG-001"]["lg_status"] == "미실행"
    assert rows["BAT-SWG-002"]["qa_status"] == "SKIP", "runs under the old name swg count as qa"


def test_the_catalog_reads_every_case_in_tests():
    from bat.report import status_book

    entries = {e["case_id"]: e for e in status_book.catalog()}
    declared = set(re.findall(r'mark\.case\("([^"]+)"\)', "\n".join(
        p.read_text(encoding="utf-8") for p in TESTS_DIR.rglob("test_*.py") if p.name != "test_selfcheck.py"
    )))
    parked = status_book.parked_ids()
    assert set(entries) | parked == declared and not set(entries) & parked
    assert all(e["product"] and e["priority"] and e["scenario"] for e in entries.values())
    assert entries["BAT-X-006"]["product"] == "cross", "product comes from the module, not the id"


def test_parked_products_stay_out_of_the_default_run_and_the_tracker(tmp_path):
    """보류(parked)된 RBI 케이스는 기본 실행에서 돌지 않고, 현황에 오르지 않으며, 다음 sync에서 지워진다."""
    from bat import cli
    from bat.report import status_book

    assert "not parked" in cli.DEFAULT_MARKERS
    parked = status_book.parked_ids()
    assert {"BAT-RBI-001", "BAT-RBI-002", "BAT-X-004"} <= parked, "X-004 lives in the RBI file"
    assert not any(i.startswith("BAT-RBI-") for i in {e["case_id"] for e in status_book.catalog()})

    tests_dir, reports_dir = _tracker(tmp_path)
    _write_cases(tests_dir, ("BAT-SWG-001", ""))
    (tests_dir / "rbi").mkdir()
    (tests_dir / "rbi" / "test_rbi_x.py").write_text(
        'import pytest\npytestmark = [pytest.mark.product("rbi"), pytest.mark.parked]\n\n'
        '@pytest.mark.case("BAT-RBI-001")\ndef test_x():\n    """RBI."""\n', encoding="utf-8")
    status_book.write_rows([{"case_id": "BAT-RBI-001", "status": "PASS"}], status_book.book_path(reports_dir))
    status_book.sync_catalog(reports_dir, tests_dir)
    _write_run(reports_dir, "qa", "20261015-150000-aaaaaa", "2026-10-15T15:00:00",
               {"BAT-SWG-001": "PASS", "BAT-RBI-001": "SKIP"})
    status_book.record_run("qa", "20261015-150000-aaaaaa", reports_dir, tests_dir)
    assert set(_rows(reports_dir)) == {"BAT-SWG-001"}


def test_results_saved_under_old_ztna_numbers_land_on_their_new_ids(tmp_path):
    """번호를 바꾼 ZTNA id로 저장된 결과는 새 id에 들어간다. 삭제된 케이스의 예전 id는 아무것도 채우지 않는다."""
    from bat.report import status_book

    tests_dir, reports_dir = _tracker(tmp_path)
    _write_cases(tests_dir, ("BAT-ZTNA-008", ""), ("BAT-ZTNA-002", ""))
    _write_run(reports_dir, "qa", "20261014-100000-aaaaaa", "2026-10-14T10:00:00",
               {"BAT-ZTNA-008": "FAIL", "BAT-ZTNA-013": "PASS", "BAT-ZTNA-002": "SKIP", "BAT-ZTNA-005": "PASS"})
    status_book.rebuild_stage_columns(reports_dir, tests_dir)
    rows = _rows(reports_dir)
    assert rows["BAT-ZTNA-008"]["qa_status"] == "PASS", "old 013 is today's 008; old 008 was deleted"
    assert rows["BAT-ZTNA-002"]["qa_status"] == "PASS", "old 005 is today's 002; old 002 was merged into it"

# -- preflight: 단말의 트래픽이 테스트 대상 워크스페이스에 닿는가? ------

class _FakePreflightTenant:
    """웹 정책 API, 단말, 웹 로그. `connected`이면 LOGGING 정책이 활성인 동안 보낸
    요청이 그 정책으로 기록된다. 아니면(커넥터가 다른 워크스페이스에 로그인돼 있으면) 이
    워크스페이스 로그에는 아무것도 닿지 않는다."""

    def __init__(self, *, connected, logged_from_request=2, taken_by=None):
        self.connected, self.logged_from, self.taken_by = connected, logged_from_request, taken_by
        self.requests, self.events, self.active, self.created = 0, [], {}, []
        self.now = 0.0

    @contextlib.contextmanager
    def temporary(self, name, rules, *, action_type="BLOCK", **_):
        self.created.append((name, str(action_type), rules[0]["value"]))
        self.active[name] = True
        try:
            yield SimpleNamespace(policy_id="901", name=name)
        finally:
            del self.active[name]

    def run(self, command, timeout_sec=None):  # 단말의 curl
        self.requests += 1
        if self.taken_by:  # 이 워크스페이스의 다른 정책이 호스트를 먼저 매칭한다
            uri = re.search(r"https://\S+?bat=[\w.-]+", command).group(0)
            self.events.insert(0, _event(id=f"t{self.requests}", policy_name=self.taken_by,
                                         policy_id=20, action="BLOCK", full_uri=uri))
            return SimpleNamespace(stdout="403", stderr="")
        if self.connected and self.requests >= self.logged_from:
            for name in self.active:
                self.events.insert(0, _event(id=f"p{self.requests}", policy_name=name, action="LOGGING"))
        return SimpleNamespace(stdout="200", stderr="")

    def security_events(self, lookback_min=10):
        return list(self.events)

    def sleep(self, seconds):
        self.now += seconds


@pytest.mark.parametrize("connected", [True, False])
def test_preflight_sees_the_endpoints_own_traffic_or_says_it_did_not(connected):
    from bat.preflight import traffic_reaches

    tenant = _FakePreflightTenant(connected=connected)
    ok, detail = traffic_reaches(tenant, tenant, tenant, "BAT-BASIC-004-x-preflight-b", "httpbin.org",
                                 timeout_sec=30, interval_sec=5, sleep=tenant.sleep, clock=lambda: tenant.now)
    assert ok is connected, detail
    assert tenant.created == [("BAT-BASIC-004-x-preflight-b", "LOGGING", ["httpbin.org"])], \
        "one LOGGING policy on one host: it can neither block nor lock the runner out"
    assert not tenant.active, "the probe policy is removed either way"
    if connected:
        assert tenant.requests == 2, "requests are resent while the policy propagates"
    else:
        assert "no event" in detail and tenant.requests == 7, detail


def test_preflight_names_a_policy_that_takes_the_test_host_first():
    """다른 정책이 가져간 요청은 "not connected"가 아니라 그 사실대로 보고된다."""
    from bat.preflight import traffic_reaches

    tenant = _FakePreflightTenant(connected=True, taken_by="tt")
    ok, detail = traffic_reaches(tenant, tenant, tenant, "BAT-BASIC-004-x-preflight-b", "httpbin.org",
                                 timeout_sec=30, interval_sec=5, sleep=tenant.sleep, clock=lambda: tenant.now)
    assert ok is False
    assert detail.startswith("connected, but policy 'tt' (id 20, BLOCK)"), detail
    assert not tenant.active

def test_a_failed_preflight_stops_the_run_before_pytest(monkeypatch, capsys):
    import bat.cli as cli
    import bat.preflight as preflight

    monkeypatch.setattr(cli, "build_run_context", lambda profile_name: None)
    monkeypatch.setattr(preflight, "check", lambda context, run_id: [
        preflight.PreflightResult("sbatest1", "local-pc", False, "no event within 60s"),
    ])
    assert cli._preflight_passes("qa", RUN_ID) is False
    out = capsys.readouterr().out
    assert "Not running" in out and "local-pc did not show up in sbatest1" in out
    assert cli.EXIT_PREFLIGHT == 7

    monkeypatch.setattr(preflight, "check", lambda context, run_id: [
        preflight.PreflightResult("sbatest1", "local-pc", True, "event 1 after 9s"),
    ])
    assert cli._preflight_passes("qa", RUN_ID) is True

def test_curl_can_be_pinned_to_the_ip_an_ip_scoped_policy_names():
    """curl을 IP 스코프 정책(BAT-SWG-020)이 지정한 A 레코드 하나에 고정할 수 있다."""
    from bat.traffic.http import curl_status

    sent = []
    executor = SimpleNamespace(run=lambda command, timeout_sec=None: (
        sent.append(command) or SimpleNamespace(stdout='"403"', stderr="")))
    curl_status(executor, "https://httpbin.org/get", pin_ip="98.88.155.171")
    curl_status(executor, "http://example.com:8080/x", pin_ip="192.0.2.1")
    curl_status(executor, "https://httpbin.org/get")
    assert "--resolve httpbin.org:443:98.88.155.171" in sent[0]
    assert "--resolve example.com:8080:192.0.2.1" in sent[1]
    assert "--resolve" not in sent[2]


def test_lanes_on_one_workspace_never_run_side_by_side():
    """한 워크스페이스를 쓰는 레인들은 서로의 정책을 보므로 직렬로 돈다."""
    from bat.scheduler import Lane, concurrency_group, parallel_slots

    def lanes(*pairs):
        return [Lane(name="api", workspace=SimpleNamespace(name=pairs[0][0]), endpoint=None, products=())] + [
            Lane(name=name, workspace=SimpleNamespace(name=ws), endpoint=SimpleNamespace(name=f"pc-{name}"),
                 products=products)
            for ws, name, products in pairs]

    merged = lanes(("sbatest1", "b", ("basic", "swg", "fwaas", "cross", "dlp", "rbi", "casb", "genai", "ztna")))
    assert parallel_slots(merged) == 1
    assert {concurrency_group(merged, p) for p in ("swg", "dlp", "casb", "cross")} == {"ws-sbatest1"}

    shared = lanes(("sedr", "b", ("swg",)), ("sedr", "c", ("dlp",)))
    assert parallel_slots(shared) == 1, "two machines on one workspace still see each other's policies"
    assert concurrency_group(shared, "swg") == concurrency_group(shared, "dlp")

    apart = lanes(("ws1", "b", ("swg",)), ("ws2", "c", ("dlp",)))
    assert parallel_slots(apart) == 2
    assert concurrency_group(apart, "swg") != concurrency_group(apart, "dlp")


def test_the_files_lane_group_is_replaced_not_joined(monkeypatch):
    """xdist는 노드 체인의 xdist_group을 전부 합치므로, 파일의 레인 그룹을 워크스페이스
    그룹으로 대체한다."""
    import tests.conftest as conftest
    from bat.scheduler import Lane

    one = [Lane(name="api", workspace=SimpleNamespace(name="sbatest1"), endpoint=None, products=()),
           Lane(name="b", workspace=SimpleNamespace(name="sbatest1"), endpoint=SimpleNamespace(name="pc"),
                products=("swg", "dlp", "casb"))]
    monkeypatch.setattr(conftest, "build_run_context", lambda profile_name: None)
    monkeypatch.setattr(conftest, "build_lanes", lambda context: one)

    class Node:
        def __init__(self, *marks, parent=None):
            self.own_markers, self.parent = list(marks), parent

        def listchain(self):
            return ([*self.parent.listchain()] if self.parent else []) + [self]

        def iter_markers(self, name):
            return (m for node in reversed(self.listchain()) for m in node.own_markers if m.name == name)

        def get_closest_marker(self, name):
            return next(self.iter_markers(name), None)

        def add_marker(self, mark):
            self.own_markers.append(mark.mark)

    items = []
    for lane, product in (("lane-b", "swg"), ("lane-c", "dlp"), ("lane-d", "casb")):
        module = Node(pytest.mark.xdist_group(lane).mark, pytest.mark.product(product).mark)
        items.append(Node(parent=module))
    items.append(Node(parent=Node()))  # selfcheck: product가 없으니 그대로 둔다
    conftest._group_by_workspace(items)
    groups = ["_".join(sorted(str(m.args[0]) for m in i.iter_markers("xdist_group"))) for i in items]
    assert groups == ["ws-sbatest1", "ws-sbatest1", "ws-sbatest1", ""], groups


def test_renumberings_apply_in_turn_and_only_to_runs_before_them():
    from bat.report.status_book import current_id

    assert current_id("BAT-RBI-005", "2026-10-15T14:01:17") == "BAT-RBI-002"
    assert current_id("BAT-RBI-005", "2026-10-16T09:00:00") == "BAT-RBI-005", "a later run keeps its id"
    assert current_id("BAT-ZTNA-013", "2026-10-14T16:10:54") == "BAT-ZTNA-008"
    assert current_id("BAT-BAS-004", "2026-10-27T10:00:00") == "BAT-BASIC-004"
    assert current_id("BAT-GAI-001", "2026-10-26T14:43:38") == "BAT-GEN-001"
    assert current_id("BAT-EDR-003", "2026-10-15T09:00:00") is None, "EDR cases were removed"
    assert current_id("BAT-ZTNA-014", "2026-10-14T16:10:54") is None
    assert current_id("BAT-SWG-001", "2026-10-01T00:00:00") == "BAT-SWG-001"


def test_a_new_stage_gets_its_columns_on_the_next_sync(tmp_path, monkeypatch):
    """기존 현황 파일에는 다음 sync 때 새 스테이지의 열이 붙고, 그 열에서 모든 케이스가 미실행이다."""
    from bat.report import status_book

    tests_dir, reports_dir = _tracker(tmp_path)
    _write_cases(tests_dir, ("BAT-SWG-001", ""))
    monkeypatch.setattr(status_book, "DEFAULT_STAGES", ("qa", "lg", "real"))
    status_book.sync_catalog(reports_dir, tests_dir)
    status_book.upsert_case("BAT-SWG-001", reports_dir, note="hand-kept")
    monkeypatch.setattr(status_book, "DEFAULT_STAGES", ("qa", "lg", "lg-preprod", "real"))
    status_book.sync_catalog(reports_dir, tests_dir)
    rows, stages = status_book.read_book(status_book.book_path(reports_dir))
    assert stages == ["qa", "lg", "lg-preprod", "real"]
    assert rows[0]["lg-preprod_status"] == status_book.NOT_RUN and rows[0]["note"] == "hand-kept"
    assert status_book._has_columns_for(status_book.book_path(reports_dir), stages)


def test_run_progress_counts_what_the_run_left_on_disk(tmp_path):
    """bat progress: plan.json + result.json 파일에서 완료/전체, 상태별 개수,
    도는 중인 케이스, FAIL/ERROR id, 남은 시간을 낸다."""
    from datetime import datetime
    from bat.report import progress

    run_dir = tmp_path / "2026-10-19" / RUN_ID
    progress.write_plan(run_dir, RUN_ID, "qa", ["BAT-SWG-001", "BAT-SWG-002", "BAT-DLP-001", "BAT-X-001"], 1)
    for cid, status in (("BAT-SWG-001", "PASS"), ("BAT-X-001", "FAIL")):
        (run_dir / cid).mkdir()
        (run_dir / cid / "result.json").write_text(json.dumps({"case_id": cid, "status": status}), encoding="utf-8")
    progress.mark_running(run_dir, "BAT-SWG-002", worker="gw0")
    started = datetime.fromisoformat(json.loads((run_dir / "plan.json").read_text(encoding="utf-8"))["started_at"])
    text = progress.render(run_dir, now=started.replace(microsecond=0) + __import__("datetime").timedelta(minutes=4),
                           estimates={"BAT-SWG-002": 60, "BAT-DLP-001": 120})
    assert f"Run {RUN_ID} (qa) — 2/4 (50%)" in text and "경과 4분" in text and "예상 남은 시간 ~3분" in text, text
    assert "PASS 1 / FAIL 1 / UNVERIFIED 0 / SKIP 0 / ERROR 0" in text
    assert "현재: BAT-SWG-002" in text and "FAIL/ERROR: BAT-X-001" in text

    progress.mark_running(run_dir, None, worker="gw0")
    (run_dir / "run-report.json").write_text("{}", encoding="utf-8")
    done = progress.render(run_dir, estimates={})
    assert "끝남" in done and "현재:" not in done, done
    assert progress.latest_run_dir(tmp_path) == run_dir


class _FakeModuleTenant:
    """module_scope_or_stop용 웹 정책 + 단말 + 웹 로그. `logs_under`: 두 LOGGING 정책
    중 어느 쪽이 probe 요청을 가져가는지("module", "control", 아무것도 기록되지 않으면 None)."""

    def __init__(self, logs_under):
        self.logs_under, self.active, self.created, self.events = logs_under, [], [], []

    @contextlib.contextmanager
    def temporary(self, name, rules, *, action_type="BLOCK", **_):
        self.created.append((name, str(action_type), rules[0]["subject"]))
        self.active.append(name)
        try:
            yield SimpleNamespace(policy_id=str(len(self.created)), name=name)
        finally:
            self.active.remove(name)

    def run(self, command, timeout_sec=None):
        uri = re.search(r"https://\S+?bat=[\w.-]+", command).group(0)
        if self.logs_under:
            taker = self.active[0] if self.logs_under == "module" else self.active[1]
            self.events.append(_event(id=str(len(self.events)), policy_name=taker, full_uri=uri))
        return SimpleNamespace(stdout='"200"', stderr="")

    def security_events(self, lookback_min=10):
        return list(self.events)


@pytest.mark.parametrize("logs_under, status", [("control", None), ("module", "FAIL"), (None, "UNVERIFIED")])
def test_a_signature_module_is_scoped_before_it_may_block(monkeypatch, logs_under, status):
    """가드는 LOGGING 정책만 만들고, probe 호스트를 건드리지 않는 모듈만 BLOCK할 수 있다."""
    import tests.support as support
    from bat.fixtures.policies import WebPolicyFactory

    monkeypatch.setattr(support.time, "sleep", lambda s: None)
    tenant = _FakeModuleTenant(logs_under)
    case = CaseResult(case_id="BAT-SWG-021", product="swg", scenario="s", criteria=["user_visible_result"])
    ctx = SimpleNamespace(run_id=RUN_ID, event_poll_timeout_sec=0.05)
    rule = WebPolicyFactory.module_rule("BLOCK_RISKY_WEBSITES")
    raised = None
    try:
        support.module_scope_or_stop(case, ctx, tenant, tenant, tenant, rule)
    except BaseException as exc:  # noqa: BLE001 - 어떤 종류의 중단인지가 요점이다
        raised = exc
    assert [c[1] for c in tenant.created] == ["LOGGING", "LOGGING"], "the guard never creates a BLOCK"
    assert [c[2] for c in tenant.created] == ["BLOCK_RISKY_WEBSITES", "HTTP_HOST"]
    assert not tenant.active, "both probe policies are removed"
    if status is None:
        assert raised is None
    elif status == "FAIL":
        assert isinstance(raised, AssertionError) and "BLOCK not attempted" in str(raised)
    else:
        assert raised is not None and not isinstance(raised, AssertionError)


class _FakeSignatureGql:
    """서버가 동작하는 대로의 signature_pattern: mutation은 두 목록을 모두 교체한다."""

    def __init__(self, deny, allow):
        self.lists = {"CNC": (list(deny), list(allow))}
        self.writes = []

    def execute(self, query, variables=None):
        import re

        pattern_type = re.search(r"pattern_type: (\w+)", query).group(1)
        if query.startswith("mutation"):
            deny = json.loads(re.search(r"deny_list: (\[.*?\])", query).group(1))
            allow = json.loads(re.search(r"allow_list: (\[.*?\])", query).group(1))
            self.lists[pattern_type] = (deny, allow)
            self.writes.append((deny, allow))
        deny, allow = self.lists.get(pattern_type, ([], []))
        return {"SIA": {"security": {"signature_pattern": {"deny_list": deny, "allow_list": allow}}}}


def test_signature_entry_keeps_the_admins_entries():
    """BAT의 deny 항목은 들어갔다 빠지고, 두 목록의 다른 항목은 모두 남는다."""
    from bat.fixtures.graphql_policies import SignaturePatternList

    gql = _FakeSignatureGql(["www.naver.com"], ["allowed.example"])
    with SignaturePatternList(gql).temporary_deny("CNC", "www.example.org"):
        assert gql.lists["CNC"] == (["www.naver.com", "www.example.org"], ["allowed.example"])
    assert gql.lists["CNC"] == (["www.naver.com"], ["allowed.example"])
    assert all(allow == ["allowed.example"] for _, allow in gql.writes)

    # 이전 실행이 남긴 항목: 마지막에 지워지고, 두 번 추가되지 않는다.
    gql = _FakeSignatureGql(["www.example.org"], [])
    with SignaturePatternList(gql).temporary_deny("CNC", "www.example.org"):
        assert gql.lists["CNC"] == (["www.example.org"], [])
    assert gql.lists["CNC"] == ([], [])

    with pytest.raises(ValueError):
        SignaturePatternList(gql).read("CNC) { x } } } } mutation { y")


def test_result_book_has_only_the_published_columns(tmp_path):
    """결과 CSV: 실행마다 날짜·시각이 붙은 파일, 9개 열, 한국어 결과, 이번 실행에 없는 케이스는 미실행."""
    import codecs
    import csv

    from bat.report import result_book

    assert result_book.result_path("qa", "20261022-084546-efa6b8", tmp_path).name == "20261022-0845-qa-bat-test-result.csv"
    statuses = {"BAT-SWG-001": "PASS", "BAT-SWG-002": "FAIL", "BAT-SWG-003": "FAIL"}
    descriptions = {
        "BAT-SWG-001": {"test_steps": "1. 요청", "expected_results": "차단된다"},
        "BAT-SWG-002": {"expected_results": "차단된다", "actual_result": "차단되지 않음"},
    }
    cases = [{"case_id": f"BAT-SWG-00{i}", "product": "swg", "scenario": f"s{i}"} for i in (1, 2, 3, 4)]
    rows = result_book.build_rows(statuses, cases, descriptions)
    assert [r["status"] for r in rows] == ["PASS", "FAIL", "FAIL", "미실행"]
    assert [r["actual_result"] for r in rows] == ["차단된다", "차단되지 않음", "기대 결과와 다르게 동작함", "미실행"]
    assert rows[0]["test_steps"] == "1. 요청" and rows[0]["expected_results"] == "차단된다"

    path = result_book.write(rows, tmp_path / "r.csv")
    assert path.read_bytes().startswith(codecs.BOM_UTF8)  # 엑셀이 한글을 UTF-8로 읽도록 BOM
    with path.open(encoding="utf-8-sig", newline="") as f:
        table = list(csv.reader(f))
    assert table[0] == [
        "Case ID", "Product", "Status", "Scenario", "Test Steps", "Test Parameters", "Test Data",
        "Expected Results", "Actual Result",
    ]
    assert table[1][0] == "BAT-SWG-001" and table[1][4] == "1. 요청" and len(table) == 5


def test_results_across_targets_are_pass_fail_or_unverified():
    """대상 여러 개: 전부 기대대로면 통과, 하나라도 어긋나면 FAIL, 어긋남 없이 확인 못 한 대상만 있으면 UNVERIFIED."""
    from bat.verdict import Raised, classify
    from tests.support import VerificationUnavailable, across_targets, unverified

    def run(outcomes: dict[str, str]):
        case = CaseResult(case_id="BAT-SWG-001", product="swg", scenario="s",
                          criteria=[Step.USER_RESULT.value])

        def check(target: str) -> None:
            outcome = outcomes[target]
            ok = outcome == "pass"
            if outcome == "unknown":
                unverified(case, Step.USER_RESULT, f"{target}: no answer")
            case.record(Step.USER_RESULT, ok=ok, detail=target)
            assert ok, f"{target} was not blocked"

        try:
            across_targets(case, list(outcomes), check, what="block")
        except VerificationUnavailable as exc:
            return classify(case, Raised.UNAVAILABLE, str(exc))
        except AssertionError as exc:
            return classify(case, Raised.ASSERTION, str(exc))
        case.status = Status.PASS
        return classify(case, Raised.NOTHING)

    assert run({"a": "pass", "b": "pass", "c": "pass"})[0] is Status.PASS
    status, reason = run({"a": "fail", "b": "fail", "c": "fail"})
    assert status is Status.FAIL and "failed on ['a', 'b', 'c']" in reason
    # 하나라도 어긋나면 FAIL이고, 어긋난 대상과 통과한 대상을 둘 다 적는다.
    status, reason = run({"a": "pass", "b": "fail", "c": "pass"})
    assert status is Status.FAIL and "failed on ['b']" in reason and "held on ['a', 'c']" in reason
    status, reason = run({"a": "fail", "b": "unknown", "c": "pass"})
    assert status is Status.FAIL and "could not be checked on ['b']" in reason
    # 어긋난 대상 없이 확인 못 한 대상만 있을 때만 UNVERIFIED다.
    status, reason = run({"a": "pass", "b": "unknown", "c": "pass"})
    assert status is Status.UNVERIFIED and "['b']" in reason


def test_multi_target_hosts_are_distinct_and_aaaa_hosts_exclude_httpbin():
    from bat.fixtures import testdata

    for hosts in (testdata.ECHO_HOSTS, testdata.AAAA_HOSTS, testdata.UNRELATED_URLS):
        assert 2 <= len(hosts) <= 3 and len(set(hosts)) == len(hosts)
    assert testdata.ECHO_HOSTS[0] == testdata.BLOCK_TARGET_HOST
    assert "httpbin.org" not in testdata.AAAA_HOSTS, "httpbin.org has no AAAA record"
    assert testdata.SIGNATURE_TARGET_HOST not in testdata.ECHO_HOSTS + testdata.AAAA_HOSTS
    assert not any(h in url for url in testdata.UNRELATED_URLS for h in testdata.ECHO_HOSTS)


def test_skip_is_only_for_user_accepted_results():
    """SKIP은 사용자가 버그로 보지 않기로 한 증상(known_issue의 match와 일치하는 FAIL)에만 쓴다.

    실행 조건 미비는 environment_error(ERROR), 확인 불가는 unverified(UNVERIFIED)다.
    보류(parked) 제품 파일은 검사하지 않는다.
    """
    from bat.report import status_book

    parked_dirs = {"rbi"}
    offenders = []
    for path in sorted(TESTS_DIR.rglob("*.py")):
        if path.name in ("support.py", "test_selfcheck.py") or path.parent.name in parked_dirs:
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if "pytest.skip(" in line:
                offenders.append(f"{path.relative_to(TESTS_DIR)}:{number}")
    assert not offenders, offenders
    assert "BAT-X-010" in status_book.parked_ids()


def test_every_case_has_a_description():
    """기본 실행 케이스마다 tests/case_descriptions.yaml에 Test Steps와 Expected Results가 있다."""
    from bat.report import result_book, status_book

    descriptions = result_book.load_descriptions()
    missing = [c["case_id"] for c in status_book.catalog()
               if not (descriptions.get(c["case_id"], {}).get("test_steps")
                       and descriptions.get(c["case_id"], {}).get("expected_results"))]
    assert not missing, f"add these to tests/case_descriptions.yaml: {missing}"


def test_result_book_takes_only_this_runs_cases(tmp_path):
    """결과 CSV의 상태는 그 실행의 케이스 결과뿐이다. 다른 실행의 결과는 섞이지 않는다."""
    from bat.report import result_book

    for run_id, case_id, status in [("20261023-090000-aaaaaa", "BAT-BASIC-001", "PASS"),
                                    ("20261023-100000-bbbbbb", "BAT-SWG-001", "FAIL")]:
        case_dir = tmp_path / "2026-10-23" / run_id / case_id
        case_dir.mkdir(parents=True)
        (case_dir / "result.json").write_text(
            json.dumps({"case_id": case_id, "status": status, "started_at": "2026-10-23T10:00:00"}),
            encoding="utf-8")
    assert result_book.run_statuses("20261023-100000-bbbbbb", tmp_path) == {"BAT-SWG-001": "FAIL"}


def test_connector_process_comes_from_the_stage():
    """스테이지마다 커넥터 프로세스 이름이 다를 수 있다(lguplus 계열은 U+SASE). 생략하면 AIConnector for Client."""
    from bat.settings import _build_profile

    base = {"console_url": "https://c", "graphql_url": "https://g", "rest_base_url": "https://r"}
    assert _build_profile("qa", base).connector_process == "AIConnector for Client"
    assert _build_profile("lguplus", {**base, "connector_process": "U+SASE"}).connector_process == "U+SASE"


def test_dns_answer_pointing_at_a_block_page_is_blocked(monkeypatch):
    """DNS 차단은 해석 실패와, 차단 페이지를 내주는 주소로 답한 경우 둘 다다. 실제 주소는 해석이다."""
    from bat.traffic import http

    def lookup(answer, block_ips=()):
        def run(command, **_):
            if command.startswith("curl"):
                ip = command.split(":80:")[1].split()[0]
                body = ("Your request / response has been blocked by DNS FireWall" if ip in block_ips
                        else "Your request / response has been blocked by a web security policy")
                return SimpleNamespace(stdout=body, stderr="")
            stdout = f"Server:  UnKnown\nAddress:  127.0.2.1\n\nName:    httpbin.org\nAddresses:  {answer}\n"
            return SimpleNamespace(stdout=stdout, stderr="")
        return http.dns_lookup(SimpleNamespace(run=run), "httpbin.org")

    monkeypatch.setattr(http, "_BLOCK_PAGE_IPS", {})
    blocked = lookup("211.234.121.17\n\t  211.234.121.18", block_ips={"211.234.121.17", "211.234.121.18"})
    assert blocked.blocked and not blocked.delivered
    resolved = lookup("54.174.189.226\n\t  35.170.125.171")
    assert resolved.delivered and not resolved.blocked


# -- 콘솔 로그인: GraphQL이 실패하면 Auth Server로 (bat/clients/graphql.py) ----


def _login_client(monkeypatch, issuance_error):
    from bat.clients import auth_server
    from bat.clients.graphql import GraphQLClient
    from bat.settings import Profile

    profile = Profile(name="t", console_url="https://console.invalid", graphql_url="https://gql.invalid",
                      rest_base_url="https://rest.invalid", block_page_marker="x")
    client = GraphQLClient(profile, "ws1")
    calls = []

    def execute(*args, **kwargs):
        if issuance_error:
            raise issuance_error
        client._client.cookies.set("sia_t_console", "a.eyJyb2xlIjoiTUFOQUdFUiJ9.c")
        return {"authorization": {"session": {"issuance": {"expire_at": 1}}}}

    def fallback(profile_, workspace, login_id, password):
        calls.append((workspace, login_id, password))
        return "h.eyJyb2xlIjoiTUFOQUdFUiJ9.s", {"session_expire_at": 2}

    monkeypatch.setattr(client, "execute", execute)
    monkeypatch.setattr(auth_server, "login_via_auth_server", fallback)
    return client, calls


def test_console_login_falls_back_to_the_auth_server_only_when_graphql_fails(monkeypatch):
    from bat.clients.errors import ApiError

    client, calls = _login_client(monkeypatch, None)
    assert client.login("u", "pw")["via"] == "graphql" and not calls

    client, calls = _login_client(monkeypatch, ApiError("GraphQL errors: Database Error"))
    session = client.login("u", "pw")
    assert session["via"] == "auth-server" and session["expire_at"] == 2
    assert calls == [("ws1", "u", "pw")]  # 평문 비밀번호를 넘긴다
    assert client.token.startswith("h.")

    client, calls = _login_client(monkeypatch, ApiError("GraphQL errors: Database Error"))
    with pytest.raises(ApiError):
        client.login("u", "hashed", pre_hashed=True)  # 평문이 없으면 대체하지 않는다
    assert not calls


def test_auth_server_password_encryption_fits_the_key():
    """RSA-OAEP(SHA-256) 패딩 길이와 키 파싱: 2048비트 키로 256바이트 암호문이 나와야 한다."""
    from bat.clients.auth_server import _rsa_public_numbers, rsa_oaep_encrypt

    # 공개키만 있으면 되므로 고정 모듈러스(2048비트, 아무 홀수)로 SPKI를 만든다.
    n = (1 << 2047) | 0xF1
    e = 65537

    def tlv(tag, value):
        length = len(value)
        head = bytes([length]) if length < 0x80 else bytes([0x82]) + length.to_bytes(2, "big")
        return bytes([tag]) + head + value

    def integer(v):
        raw = v.to_bytes((v.bit_length() + 8) // 8, "big")
        return tlv(0x02, raw)

    rsa_key = tlv(0x30, integer(n) + integer(e))
    algorithm = tlv(0x30, bytes.fromhex("06092a864886f70d0101010500"))
    spki = tlv(0x30, algorithm + tlv(0x03, b"\x00" + rsa_key))
    import base64 as b64

    pem = "-----BEGIN PUBLIC KEY-----\n" + b64.b64encode(spki).decode() + "\n-----END PUBLIC KEY-----"
    assert _rsa_public_numbers(pem) == (n, e)
    assert len(rsa_oaep_encrypt(pem, b"user@example.com#_password")) == 256


# -- 2단계: 요청 단위 이벤트, 상태 유지(hold), 부재 확인 (tests/support.py) -----------


def _answer(kind: str) -> TrafficResult:
    return {
        "blocked": TrafficResult(url="u", status_code=403, blocked=True, via="curl"),
        "delivered": TrafficResult(url="u", status_code=200, blocked=False, via="curl", delivered=True),
        "none": TrafficResult(url="u", status_code=0, blocked=False, via="curl"),
    }[kind]


def _hold(clock, sequence, *, steady=False, budget=10.0):
    """sequence[i]는 i번째 check의 결과. 시계는 instant_polling의 가짜 시계다."""
    from tests.support import hold_after_change

    answers = iter(sequence)
    start = clock.now
    return hold_after_change(
        lambda: _answer(next(answers)),
        want=lambda t: t.blocked if not steady else t.delivered,
        against=lambda t: t.delivered if not steady else t.blocked,
        changed_at=start, budget_sec=budget, steady=steady, interval_sec=2.0,
    )


def test_hold_requires_the_state_after_the_propagation_budget(instant_polling):
    """상태 변경 뒤에는 첫 차단에서 멈추지 않는다. 기한 뒤 HOLD_REPEATS번 모두 차단이어야 held다."""
    from tests.support import HOLD_REPEATS

    held = _hold(instant_polling, ["delivered", "blocked"] + ["blocked"] * HOLD_REPEATS)
    assert held.outcome == "held" and held.after_deadline == HOLD_REPEATS
    assert instant_polling.now >= 10.0, "the repeats must come after the deadline"
    # 이미 막혀 있다가(첫 결과 차단) 기한 뒤 풀리면 broke: X-001의 예전 거짓 PASS
    broke = _hold(instant_polling, ["blocked", "blocked", "delivered"])
    assert broke.outcome == "broke"
    assert _hold(instant_polling, ["delivered"] * 20).outcome == "never"
    assert _hold(instant_polling, ["blocked", "blocked", "none", "blocked"]).outcome == "inconclusive"


def test_steady_hold_fails_on_any_block_during_or_after_the_budget(instant_polling):
    """steady(바뀌면 안 되는 상태): 전파 구간이든 그 뒤든 한 번이라도 막히면 broke다."""
    from tests.support import HOLD_REPEATS

    assert _hold(instant_polling, ["delivered"] * 20, steady=True).outcome == "held"
    late = ["delivered"] * 6 + ["blocked"] + ["delivered"] * 20
    assert _hold(instant_polling, late, steady=True).outcome == "broke"
    after = ["delivered"] * 6 + ["delivered"] * (HOLD_REPEATS - 1) + ["blocked"]
    assert _hold(instant_polling, after, steady=True).outcome == "broke"
    assert _hold(instant_polling, ["delivered", "none"] + ["delivered"] * 20, steady=True).outcome == "inconclusive"


def test_expect_hold_verdicts(instant_polling):
    """held만 통과한 assertion, inconclusive는 UNVERIFIED, never/broke는 FAIL(failure 문구를 그대로 씀)."""
    from bat.verdict import Raised, classify
    from tests.support import HOLD_REPEATS, Hold, VerificationUnavailable, expect_hold

    def run(outcome):
        case = CaseResult(case_id="BAT-X-001", product="cross", scenario="s", criteria=[Step.USER_RESULT.value])
        hold = Hold(outcome, [_answer("blocked")] * 4, after_deadline=HOLD_REPEATS)
        try:
            expect_hold(case, hold, expected="blocked", failure="A higher-priority ALLOW policy on h let it through")
        except VerificationUnavailable as exc:
            return classify(case, Raised.UNAVAILABLE, str(exc))
        except AssertionError as exc:
            return classify(case, Raised.ASSERTION, str(exc))
        case.status = Status.PASS
        return classify(case, Raised.NOTHING)

    assert run("held")[0] is Status.PASS
    assert run("inconclusive")[0] is Status.UNVERIFIED
    for outcome in ("broke", "never"):
        status, reason = run(outcome)
        assert status is Status.FAIL and reason.startswith("A higher-priority ALLOW policy on h let it through")


class _FakeWebLog:
    """보안 로그. sentinel_lag번 조회한 뒤에야 표지 행이 보인다(로그 지연)."""

    def __init__(self, rows, *, sentinel_row=None, sentinel_lag=1):
        self.rows = list(rows)
        self.sentinel_row = sentinel_row
        self.sentinel_lag = sentinel_lag
        self.reads = 0

    def security_events(self, lookback_min=10):
        self.reads += 1
        visible = list(self.rows)
        if self.sentinel_row is not None and self.reads > self.sentinel_lag:
            visible.append(self.sentinel_row)
        return visible

    def wait_for_security_event(self, match, *, timeout_sec=30.0, description="", **_):
        from bat.events.poller import poll_until

        return poll_until(
            lambda: next((e for e in self.security_events() if match(e)), None),
            timeout_sec=timeout_sec, description=description,
        )


def _no_event_case(log, absent_uri):
    from bat.events.web_log import all_of, matches_policy, matches_target
    from bat.verdict import Raised, classify
    from tests.support import VerificationUnavailable, expect_no_event

    case = CaseResult(case_id="BAT-SWG-002", product="swg", scenario="s", criteria=[Step.EVENT.value])
    mine = matches_policy("P", "9")
    try:
        expect_no_event(
            case, log, absent=all_of(mine, matches_target(absent_uri)), what="P rows for the other site",
            sentinel=lambda: "https://httpbin.org/get?bat=s", sentinel_match=mine, timeout_sec=10,
        )
    except VerificationUnavailable as exc:
        return classify(case, Raised.UNAVAILABLE, str(exc))
    except AssertionError as exc:
        return classify(case, Raised.ASSERTION, str(exc))
    case.status = Status.PASS
    return classify(case, Raised.NOTHING)


def test_absence_is_judged_only_after_a_later_sentinel_row_appears(instant_polling):
    """부재는 표지 요청의 행이 로그에 나타난 다음에 판정한다. 표지가 안 보이면 UNVERIFIED다."""
    sentinel = _event(id=50, policy_name="P", policy_id=9, action="BLOCK", full_uri="https://httpbin.org/get?bat=s")
    other = "https://www.iana.org/?bat=other1"
    assert _no_event_case(_FakeWebLog([], sentinel_row=sentinel), other)[0] is Status.PASS
    stray = _event(id=40, policy_name="P", policy_id=9, action="BLOCK", full_uri=other)
    status, reason = _no_event_case(_FakeWebLog([stray], sentinel_row=sentinel), other)
    assert status is Status.FAIL and "40" in reason
    status, reason = _no_event_case(_FakeWebLog([]), other)  # 표지 행이 끝내 없다
    assert status is Status.UNVERIFIED and "sentinel" in reason


def test_marker_url_binds_the_event_to_that_request(instant_polling):
    """marker_url을 주면 같은 정책의 이전 단계 행이 아니라 그 요청 자신의 행만 인정한다."""
    from tests.support import await_security_event

    earlier = _event(id=1, policy_name="P", policy_id=9, action="BLOCK", full_uri="https://httpbin.org/post?bat=x-before")
    log = _FakeWebLog([earlier])
    case = CaseResult(case_id="BAT-X-001", product="cross", scenario="s", criteria=[Step.EVENT.value])
    with pytest.raises(AssertionError, match="no security event"):
        await_security_event(case, log, "P", timeout_sec=5, policy_id=9,
                             marker_url="https://httpbin.org/post?bat=x-after3")
    own = _event(id=2, policy_name="P", policy_id=9, action="BLOCK", full_uri="https://httpbin.org/post?bat=x-after3")
    log.rows.insert(0, own)
    event = await_security_event(case, log, "P", timeout_sec=5, policy_id=9,
                                 marker_url="https://httpbin.org/post?bat=x-after3")
    assert event.event_id == "2"


def test_request_until_logged_names_the_request_that_was_logged(instant_polling):
    """정책이 늦게 적용돼도 되풀이해 보낸 요청 중 실제로 찍힌 요청의 URL을 돌려준다."""
    from bat.events.web_log import matches_policy
    from tests.support import request_until_logged

    log = _FakeWebLog([])
    sent = []

    def send(url):
        sent.append(url)
        if len(sent) == 3:  # 세 번째 요청부터 정책이 적용됐다
            log.rows.insert(0, _event(id=len(sent), policy_name="P", policy_id=9, action="LOGGING", full_uri=url))
        return _answer("delivered")

    found = request_until_logged(
        log, send, match=matches_policy("P", 9), url_for=lambda n: f"https://httpbin.org/post?bat=p{n}",
        budget_sec=20, event_timeout_sec=10,
    )
    assert found is not None and found[0] == "https://httpbin.org/post?bat=p3"
    assert request_until_logged(
        _FakeWebLog([]), lambda url: _answer("delivered"), match=matches_policy("P", 9),
        url_for=lambda n: f"https://h/?bat={n}", budget_sec=6, event_timeout_sec=6,
    ) is None


# -- 3단계: 정책 차단으로 인정하기, 기준선, 삭제·변경 재확인, 저장값 비교, 실행 종료 잔여 검사

class _CurlEndpoint:
    """curl 명령을 받아 정해진 출력을 차례로 돌려주는 단말(마지막 출력을 반복). 받은 명령을 남긴다."""

    def __init__(self, *outputs):
        self.outputs, self.commands = list(outputs), []

    def run(self, command, timeout_sec=None):
        self.commands.append(command)
        return SimpleNamespace(stdout=self.outputs.pop(0) if len(self.outputs) > 1 else self.outputs[0], stderr="")


def test_a_curl_block_can_require_the_block_page_text():
    """block_text를 주면 403/451이면서 본문에 그 문구가 있어야 차단이다. 문구 없는 403은
    원 서버나 프록시의 거부일 수 있어 차단도 전달도 아니다(판단 불가). 주지 않으면 예전대로다."""
    from bat.traffic.http import curl_status

    marker = "Your request / response has"
    page = _CurlEndpoint(f"<html><title>Browsing blocked by P</title>{marker} been blocked</html>\n403")
    blocked = curl_status(page, "http://h/get", block_text=marker)
    assert blocked.blocked and not blocked.delivered
    assert "-o NUL" not in page.commands[0], "the body has to be read to find the block page text"

    proxy = curl_status(_CurlEndpoint("<html>Forbidden by proxy</html>\n403"), "http://h/get", block_text=marker)
    assert not proxy.blocked and not proxy.delivered and "without the block page text" in proxy.detail

    ok = curl_status(_CurlEndpoint('{"args": {}}\n200'), "http://h/get", block_text=marker)
    assert ok.delivered and not ok.blocked
    assert curl_status(_CurlEndpoint('"403"'), "http://h/get").blocked  # 문구를 요구하지 않으면 예전대로


def test_restored_connectivity_needs_a_delivered_answer(instant_polling):
    """curl_until_reachable은 아무 응답(403·5xx)이 아니라 전달에서 멈춘다."""
    from tests.support import curl_until_reachable

    endpoint = _CurlEndpoint('"000"', '"403"', '"502"', '"200"')
    assert curl_until_reachable(endpoint, "https://h/", 60).status_code == 200
    assert len(endpoint.commands) == 4
    assert not curl_until_reachable(_CurlEndpoint('"403"'), "https://h/", 5).delivered


def test_a_failed_baseline_is_unverified_not_a_block():
    """정책 전에 대상이 해석·도달되지 않으면 정책 뒤의 실패를 차단으로 셀 수 없다."""
    from tests.support import VerificationUnavailable, require_baseline

    case = CaseResult(case_id="BAT-FW-001", product="fwaas", scenario="s")
    require_baseline(case, _answer("delivered"), what="h resolves")
    assert case.steps[-1].kind is Kind.EVIDENCE
    for kind in ("blocked", "none"):
        with pytest.raises(VerificationUnavailable, match="baseline"):
            require_baseline(case, _answer(kind), what="h resolves")


class _FakeNetworkLog:
    """DNS·방화벽 로그. rows_after번 조회한 뒤에야 later 행이 보인다(로그 지연)."""

    def __init__(self, rows=(), later=(), rows_after=1):
        self.rows, self.later, self.rows_after, self.reads = list(rows), list(later), rows_after, 0

    def _read(self):
        self.reads += 1
        return [*self.rows, *(self.later if self.reads > self.rows_after else [])]

    def dns_events(self, lookback_min=10):
        return self._read()

    def firewall_events(self, lookback_min=10):
        return self._read()


def test_a_network_row_is_the_new_row_of_that_request(instant_polling):
    """요청 전에 있던 행(after)과 조건(where)에 맞지 않는 행은 그 요청의 행이 아니다."""
    from tests.support import await_network_row, ip_of, not_aaaa

    old = _event(id=1, policy_name="P", action="BLOCK", record_type="A")
    aaaa = _event(id=2, policy_name="P", action="BLOCK", record_type="AAAA")
    other_policy = _event(id=3, policy_name="P-probe", action="BLOCK", record_type="A")
    mine = _event(id=4, policy_name="P", action="BLOCK", record_type="A")
    case = CaseResult(case_id="BAT-FW-001", product="fwaas", scenario="s")
    log = _FakeNetworkLog([old, aaaa, other_policy], later=[mine])
    row = await_network_row(case, log, "P", kind="dns", after={"1"}, where={"record_type": not_aaaa},
                            timeout_sec=10, what="the lookup")
    assert row.event_id == "4" and case.event_ids == ["4"] and case.steps[-1].ok

    case = CaseResult(case_id="BAT-FW-001", product="fwaas", scenario="s")
    with pytest.raises(AssertionError, match="not attributable"):
        await_network_row(case, _FakeNetworkLog([old, aaaa]), "P", kind="dns", after={"1"},
                          where={"record_type": not_aaaa}, timeout_sec=5, what="the lookup")
    assert case.steps[-1].step is Step.EVENT and not case.steps[-1].ok

    # 방화벽 행: dst_ip가 그 IP여야 한다("<ip>:<port>"도 같은 IP)
    elsewhere = _event(id=5, policy_name="F", action="BLOCK", dst_ip="198.51.100.9")
    there = _event(id=6, policy_name="F", action="LOGGING", dst_ip="198.51.100.7:443")
    case = CaseResult(case_id="BAT-FW-003", product="fwaas", scenario="s")
    with pytest.raises(AssertionError, match="records action 'LOGGING'"):
        await_network_row(case, _FakeNetworkLog([elsewhere, there]), "F", kind="firewall",
                          where={"dst_ip": lambda v: ip_of(v) == "198.51.100.7"}, timeout_sec=5, what="c")
    assert ip_of("198.51.100.7:443") == ip_of("198.51.100.7") == "198.51.100.7"
    assert ip_of("2001:db8::1") == "2001:db8::1"


class _BlockingResolver:
    """정책이 있으면 nslookup이 거부되고, logs면 그때마다 그 정책의 A 행을 남기는 단말."""

    def __init__(self, log, *, logs=True):
        self.log, self.logs, self.policy = log, logs, ""

    def run(self, command, timeout_sec=None):
        if self.policy and command.startswith("nslookup"):
            if self.logs:
                self.log.rows.append(_event(id=100 + len(self.log.rows), policy_name=self.policy,
                                            action="BLOCK", record_type="A"))
            return SimpleNamespace(stdout=NSLOOKUP_REFUSED, stderr="")
        return SimpleNamespace(stdout=NSLOOKUP_RESOLVED, stderr="")


@pytest.mark.parametrize("logs", [True, False], ids=["row-left", "no-row"])
def test_a_failed_lookup_counts_as_the_policys_block_only_with_its_row(instant_polling, logs):
    """이름 해석 실패는 그 조회 뒤 그 정책의 새 A 행이 있어야 정책 차단이다. 행이 없으면 FAIL."""
    from tests.support import expect_dns_block

    log = _FakeNetworkLog()
    endpoint = _BlockingResolver(log, logs=logs)
    endpoint.policy = "P"
    case = CaseResult(case_id="BAT-FW-001", product="fwaas", scenario="s")
    if logs:
        row = expect_dns_block(case, endpoint, log, "P", "example.com", budget_sec=5, event_timeout_sec=5, failure="f")
        assert row.get("record_type") == "A"
        assert {s.step for s in case.steps if s.kind is Kind.ASSERTION and s.ok} == {Step.USER_RESULT, Step.EVENT}
    else:
        with pytest.raises(AssertionError, match="not attributable"):
            expect_dns_block(case, endpoint, log, "P", "example.com", budget_sec=5, event_timeout_sec=5, failure="f")
        assert [s.step for s in case.steps if not s.ok] == [Step.EVENT]


def test_values_read_back_are_compared_not_just_found():
    """저장값은 요청값과 비교한다. 객체는 id로, 리스트는 순서 없이. 다르면 FAIL, 못 읽으면 UNVERIFIED."""
    from tests.support import MISSING, VerificationUnavailable, as_list, expect_values, rule_values, stored

    case = CaseResult(case_id="BAT-ZTNA-003", product="ztna", scenario="s")
    expect_values(case, "policy", {
        "user": ([7], [{"id": 7, "name": "root"}]),
        "country": (["AQ", "KR"], ["KR", "AQ"]),
        "action_type": ("BLOCK", "BLOCK"),
    })
    assert case.steps[-1].ok and case.steps[-1].kind is Kind.ASSERTION
    with pytest.raises(AssertionError, match="country"):
        expect_values(case, "policy", {"country": (["AQ"], None), "action_type": ("BLOCK", "BLOCK")})
    with pytest.raises(VerificationUnavailable, match="could not read"):
        expect_values(case, "policy", {"action_type": ("BLOCK", MISSING)})
    assert stored(None, "x") is MISSING and stored({"x": 0}, "x") == 0
    assert as_list("AQ") == ["AQ"] and as_list(None) == [] and as_list(MISSING) is MISSING
    rules = [[{"id": 1, "subject": "GENAI_REQUEST_KEYWORD", "condition": "IN", "value": ["password"]}]]
    assert rule_values(rules, "GENAI_REQUEST_KEYWORD") == ["password"]
    assert rule_values(rules, "GENAI_REQUEST_TOPIC") == [] and rule_values(MISSING, "X") is MISSING


class _FakeRest:
    """웹 정책 REST. 삭제를 무시하는 제품(ignore_delete)과 활성화 변경을 무시하는 제품을 흉내 낸다."""

    def __init__(self, *, ignore_delete=False, ignore_enable=False):
        self.web = {7: {"id": 7, "name": "BAT-SWG-001-x", "enable": True}}
        self.ignore_delete, self.ignore_enable = ignore_delete, ignore_enable

    def get(self, path, params=None):
        if path.endswith("/list"):
            rows = list(self.web.values())
            return {"total": len(rows), "policies": rows}
        return dict(self.web[int(path.rsplit("/", 1)[-1])])

    def delete(self, path, json=None):
        if not self.ignore_delete:
            for policy_id in json["ids"]:
                self.web.pop(policy_id, None)
        return {}

    def patch(self, path, json=None):
        if not self.ignore_enable:
            self.web[int(path.split("/")[-2])]["enable"] = json["enable"]
        return {}


def test_deletes_and_enable_changes_are_read_back():
    """삭제·활성화 변경은 성공 응답만 믿지 않고 다시 읽어 반영됐는지 본다."""
    from bat.clients.errors import ApiError
    from bat.fixtures.policies import PolicyHandle, WebPolicyFactory, confirm_gone

    handle = PolicyHandle("7", "BAT-SWG-001-x", "swg", "rest")
    WebPolicyFactory(_FakeRest()).delete(handle)
    with pytest.raises(ApiError, match="still listed after delete"):
        WebPolicyFactory(_FakeRest(ignore_delete=True)).delete(handle)
    WebPolicyFactory(_FakeRest()).set_enabled(handle, False)
    with pytest.raises(ApiError, match="reads back as True"):
        WebPolicyFactory(_FakeRest(ignore_enable=True)).set_enabled(handle, False)
    # 목록이 일부뿐이면 없다고 확정할 수 없어 경고만 남긴다(실행 종료 검사가 다시 본다)
    confirm_gone("web policy", handle, [], complete=False)
    with pytest.raises(ApiError):
        confirm_gone("dns firewall policy", PolicyHandle("9", "N", "fwaas", "graphql"), [{"id": 9, "name": "N"}])


def test_a_pass_whose_cleanup_failed_says_so():
    """검사는 통과했지만 정리가 실패한 케이스는 판정은 그대로 두고 사유에 남긴다."""
    from tests.conftest import _with_cleanup_note

    assert _with_cleanup_note(Status.PASS, "all passed", []) == "all passed"
    note = _with_cleanup_note(Status.PASS, "all passed", ["web policy P: HTTP 500"])
    assert note.startswith("all passed; cleanup failed after the checks passed: web policy P")
    assert _with_cleanup_note(Status.FAIL, "r", ["w"]) == "r"


def test_resources_left_by_this_run_fail_the_run(monkeypatch):
    """실행이 끝났을 때 이번 실행의 리소스가 남았으면 종료 코드가 실패가 된다. 읽지 못한 목록은
    알리기만 한다. BAT 케이스가 하나도 판정되지 않은 세션(selfcheck)은 환경에 접속하지 않는다."""
    import bat.leftovers as leftovers
    import tests.conftest as conftest

    lines: list[str] = []
    reporter = SimpleNamespace(
        stats={"passed": [SimpleNamespace(user_properties=[("bat_status", "PASS")])]},
        write_line=lambda line, **_: lines.append(line),
        section=lambda title, **_: lines.append(title),
    )
    config = SimpleNamespace(pluginmanager=SimpleNamespace(get_plugin=lambda name: reporter))
    monkeypatch.delenv("PYTEST_XDIST_WORKER", raising=False)
    monkeypatch.setattr(conftest, "build_run_context", lambda **_: SimpleNamespace(run_id=RUN_ID))

    session = SimpleNamespace(config=config, exitstatus=0)
    monkeypatch.setattr(leftovers, "find_run_leftovers", lambda context, run_id: ([], ["rbi: denied"]))
    conftest.pytest_sessionfinish(session, 0)
    assert session.exitstatus == 0 and any("not confirmed" in line for line in lines)

    monkeypatch.setattr(leftovers, "find_run_leftovers",
                        lambda context, run_id: ([f"web policy id=1 BAT-SWG-001-{RUN_ID}"], []))
    conftest.pytest_sessionfinish(session, 0)
    assert session.exitstatus == pytest.ExitCode.TESTS_FAILED

    quiet = SimpleNamespace(config=config, exitstatus=0)
    reporter.stats = {"passed": [SimpleNamespace(user_properties=[])]}

    def must_not_connect(*args):
        pytest.fail("selfcheck-only sessions must not connect")

    monkeypatch.setattr(leftovers, "find_run_leftovers", must_not_connect)
    conftest.pytest_sessionfinish(quiet, 0)
    assert quiet.exitstatus == 0


def test_a_2xx_html_page_from_the_management_api_counts_as_intercepted():
    from tests.basic.test_basic import _html_answer

    assert _html_answer({"_raw": "<!DOCTYPE html><html><body>Your request / response has been blocked"})
    assert not _html_answer({"id": 3})
    assert not _html_answer({"_raw": "plain text"})
    assert not _html_answer(None)
