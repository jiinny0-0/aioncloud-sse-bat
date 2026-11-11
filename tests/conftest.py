"""공용 fixture.

세션 범위 객체(콘솔 세션, REST 토큰, 브라우저)는 워커마다 한 번 만든다. 케이스 범위
객체(정책, 사용자)는 각 테스트 안에서 만들고 지워서 케이스 사이에 아무것도 새지 않는다.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Iterator

import pytest

from bat.clients.errors import EndpointError, SelfBlockedError
from bat.clients.graphql import GraphQLClient
from bat.clients.rest import RestClient
from bat.clients.tokens import TokenBudget, load_console_token
from bat.endpoint.base import build_executor
from bat.events.audit_log import AuditLogReader
from bat.events.auth_log import AuthLogReader
from bat.events.casb_log import CasbLogReader
from bat.events.network_log import NetworkLogReader
from bat.events.web_log import WebLogReader
from bat.fixtures.graphql_policies import (
    ApplicationFirewallFactory,
    DnsFirewallFactory,
    SaasAccessFactory,
)
from bat.fixtures.policies import UNRAISED_CLEANUP_FAILURES, DlpPolicyFactory, WebPolicyFactory
from bat.models import CaseResult, Status
from bat.report.collector import ResultCollector
from bat.report import progress
from bat.health import no_response, pc_network, runner_executor
from bat.scheduler import build_lanes, concurrency_group, lane_for_product
from bat.settings import build_run_context, env
from bat.traffic.browser import BrowserSession
from bat.verdict import MinorFailure, Raised, apply_gate, apply_known_issue, classify, merge_retry, product_failure
from tests.support import VerificationUnavailable, environment_error

log = logging.getLogger(__name__)


# -- 세션 기반 구성 -------------------------------------------------------


@pytest.fixture(scope="session")
def run_context():
    return build_run_context(profile_name=env("BAT_PROFILE", "qa"))


@pytest.fixture(scope="session")
def lanes(run_context):
    return build_lanes(run_context)


@pytest.fixture(scope="session")
def token_budget(run_context) -> TokenBudget:
    return TokenBudget(run_context.token_budget)


@pytest.fixture(scope="session")
def collector(run_context) -> Iterator[ResultCollector]:
    collector = ResultCollector(
        report_dir=run_context.report_dir,
        run_id=run_context.run_id,
        profile=run_context.profile.name,
    )
    yield collector
    collector.write_run_report()


@pytest.fixture
def lane(request, lanes):
    """현재 케이스가 속한 레인.

    워커 전체 설정이 아니라 케이스 자신의 마커에서 구한다: xdist에서는 같은 워커가 여러
    레인의 케이스를 가져갈 수 있어, 세션 범위로 짐작하면 모든 케이스에 첫 레인의
    워크스페이스와 단말이 조용히 넘어간다.
    """
    lane_marker = request.node.get_closest_marker("lane")
    if lane_marker:
        wanted = str(lane_marker.args[0])
        for candidate in lanes:
            if candidate.name == wanted:
                return candidate
        # 단말이 모자라 이 레인이 다른 레인에 병합됐다. 병합을 따라가는 제품 매핑으로
        # 넘어간다.
    product_marker = request.node.get_closest_marker("product")
    product = product_marker.args[0] if product_marker else "swg"
    return lane_for_product(lanes, product)


@pytest.fixture(scope="session")
def _lane_clients(run_context) -> Iterator[dict]:
    """레인별 클라이언트 캐시.

    세션은 비싸서(콘솔 로그인, 브라우저 실행) 레인마다 한 번 만들어 재사용한다. 하지만
    레인은 케이스 단위로만 알 수 있어 평범한 세션 fixture로는 만들 수 없다. 여기서 연
    것은 전부 여기서 닫는다.
    """
    store: dict[str, dict] = {"console": {}, "rest": {}, "executor": {}, "browser": {}}
    yield store

    for client in store["console"].values():
        try:
            client.close()
        except Exception as exc:  # pragma: no cover - teardown은 최선 노력이다
            log.debug("Console close failed: %s", exc)
    for client in store["rest"].values():
        try:
            client.close()
        except Exception as exc:  # pragma: no cover
            log.debug("REST close failed: %s", exc)
    for session in store["browser"].values():
        try:
            session.stop()
        except Exception as exc:  # pragma: no cover
            log.debug("Browser stop failed: %s", exc)


@pytest.fixture
def console(run_context, lane, _lane_clients) -> GraphQLClient:
    """콘솔 GraphQL 세션.

    REST로 다룰 수 없는 제품만 이것이 필요하다. 캐시된 세션도 콘솔 자격증명도 없으면
    실행 조건 미비로 BAT_ERROR가 된다.
    """
    workspace = lane.workspace
    cached = _lane_clients["console"].get(lane.name)
    if cached:
        return cached

    client = GraphQLClient(run_context.profile, workspace.name)

    # 'bat login'이 저장한 세션이 있으면 여기서 로그인하지 않는다. SSE가 비밀번호가 든
    # 요청 본문을 차단하는 동안에는 이게 중요하다: 자격증명이 맞아도 로그인이 실패한다.
    cached_token = load_console_token(workspace.name)
    if cached_token:
        client.use_token(cached_token)
        log.info("Using the cached console session for %s", workspace.name)
        _lane_clients["console"][lane.name] = client
        return client

    if not workspace.has_console_credentials:
        environment_error(
            "No console credentials configured "
            "(BAT_CONSOLE_USER / BAT_CONSOLE_PASSWORD); GraphQL-only cases are skipped"
        )

    try:
        client.login(workspace.login_id, workspace.password)
    except SelfBlockedError as exc:
        environment_error(
            f"Console sign-in was blocked by SSE: {exc}\n"
            f"Disconnect the connector, run 'bat login', then run this again — "
            f"the cached session works with the connector up."
        )

    _lane_clients["console"][lane.name] = client
    return client


@pytest.fixture
def rest(run_context, lane, token_budget, _lane_clients, request) -> RestClient:
    """/sia/v1/**용 REST 클라이언트.

    콘솔에서 수동 발급한 토큰을 우선한다. 없으면 GraphQL 세션으로 토큰을 발급받는다.
    그래서 console fixture를 파라미터로 선언하지 않고 지연 해석한다.
    """
    cached = _lane_clients["rest"].get(lane.name)
    if cached:
        return cached

    workspace = lane.workspace
    token = workspace.openapi_token
    source = "env"
    if not token:
        console_client = request.getfixturevalue("console")
        token = token_budget.token_for(console_client, workspace.name)
        source = "makeOpenAPIToken"

    log.info("REST token for %s obtained via %s", workspace.name, source)
    client = RestClient(run_context.profile, token)
    if not client.health():
        environment_error("REST health probe failed; check the API base URL and token")
    _lane_clients["rest"][lane.name] = client
    return client


@pytest.fixture
def executor(lane, _lane_clients):
    """레인 단말에서의 명령 실행.

    단말이 없거나 닿지 않는 것은 제품 결함이 아니라 구성 공백이다. 이런 케이스는 실행
    조건 미비로 BAT_ERROR가 된다.
    """
    cached = _lane_clients["executor"].get(lane.name)
    if cached:
        return cached

    if not lane.needs_endpoint:
        environment_error("This lane has no endpoint assigned")

    endpoint = lane.endpoint
    username = env("BAT_ENDPOINT_USER")
    password = env("BAT_ENDPOINT_PASSWORD")
    if not endpoint.is_local and not (username and password):
        environment_error(
            f"Endpoint {endpoint.name} is configured for WinRM but "
            f"BAT_ENDPOINT_USER / BAT_ENDPOINT_PASSWORD are not set. "
            f"Set them, or use transport: local in config/environments.yaml."
        )

    try:
        executor = build_executor(endpoint, username=username, password=password)
    except EndpointError as exc:
        environment_error(f"Endpoint {endpoint.name} unavailable: {exc}")

    _lane_clients["executor"][lane.name] = executor
    return executor


@pytest.fixture
def browser_session(run_context, lane, _lane_clients) -> BrowserSession:
    """레인마다 브라우저 하나를 두고 케이스 사이에 재사용한다.

    케이스마다 다시 띄우면 약 15초가 들고, 이는 전체 실행 시간에서 피할 수 있는 가장 큰
    덩어리다.
    """
    cached = _lane_clients["browser"].get(lane.name)
    if cached:
        return cached

    session = BrowserSession(
        profile=run_context.profile,
        headed=env("BAT_HEADED", "").lower() in {"1", "true", "yes"},
        artifacts_dir=run_context.report_dir / "artifacts",
    ).start()
    _lane_clients["browser"][lane.name] = session
    return session


# -- 케이스별 헬퍼 -------------------------------------------------------


@pytest.fixture
def web_policies(rest, request) -> WebPolicyFactory:
    """DLP를 연결하는 rule은 콘솔 GraphQL 세션이 필요하고(policies.py의
    CREATE_WEB_SECURITY 참조), 다른 rule은 전부 REST로 간다. console fixture를 지연
    해석하므로 일반 SWG 케이스는 콘솔 자격증명이 전혀 필요 없다."""
    return WebPolicyFactory(rest, gql=lambda: request.getfixturevalue("console"))


@pytest.fixture
def dlp_policies(rest) -> DlpPolicyFactory:
    return DlpPolicyFactory(rest)


@pytest.fixture
def web_log(console) -> WebLogReader:
    return WebLogReader(console)


@pytest.fixture
def auth_log(console) -> AuthLogReader:
    return AuthLogReader(console)


@pytest.fixture
def audit_log(console) -> AuditLogReader:
    return AuditLogReader(console)


@pytest.fixture
def network_log(console) -> NetworkLogReader:
    return NetworkLogReader(console)


@pytest.fixture
def casb_log(console) -> CasbLogReader:
    return CasbLogReader(console)


@pytest.fixture
def dns_firewall(console) -> DnsFirewallFactory:
    return DnsFirewallFactory(console)


@pytest.fixture
def application_firewall(console) -> ApplicationFirewallFactory:
    return ApplicationFirewallFactory(console)


@pytest.fixture
def saas_access(console) -> SaasAccessFactory:
    return SaasAccessFactory(console)


@pytest.fixture
def case(request, run_context, lane, collector) -> Iterator[CaseResult]:
    """결과 행을 만들고, 시간을 기록하고, collector에 넘긴다.

    예외를 던진 테스트도 행을 남긴다: 아래 pytest_runtest_makereport가 어떻게 끝났는지
    분류하므로(bat.verdict) 리포트에서 케이스가 조용히 사라지지 않는다.
    """
    marker = request.node.get_closest_marker("case")
    product_marker = request.node.get_closest_marker("product")
    priority_marker = request.node.get_closest_marker("priority")
    verifies_marker = request.node.get_closest_marker("verifies")

    result = CaseResult(
        case_id=marker.args[0] if marker else request.node.name,
        product=product_marker.args[0] if product_marker else "unknown",
        scenario=(request.node.function.__doc__ or "").strip().splitlines()[0]
        if request.node.function.__doc__
        else request.node.name,
        priority=priority_marker.args[0] if priority_marker else "P1",
        lane=lane.name,
        workspace=lane.workspace.name,
        endpoint=lane.endpoint.name if lane.endpoint else "",
        started_at=datetime.now(),
        criteria=[str(getattr(arg, "value", arg)) for arg in verifies_marker.args]
        if verifies_marker
        else [],
        diagnostic=request.node.get_closest_marker("diagnostic") is not None,
        gate=request.node.get_closest_marker("gate") is not None,
    )
    prior = _prior_attempt(run_context.report_dir, result.case_id)
    if prior is not None:
        result.attempts = [prior]
    # 케이스가 실패해도 report hook이 닿을 수 있도록 테스트 본문이 돌기 전에 묶는다.
    # teardown에서 묶으면 너무 늦다.
    request.node._bat_case = result
    UNRAISED_CLEANUP_FAILURES.clear()  # 케이스는 자기 본문이 남긴 것만 가진다
    progress.mark_running(run_context.report_dir, result.case_id)
    try:
        yield result
    except Exception as exc:
        result.status = Status.BAT_ERROR
        result.error = str(exc)[:1000]
        raise
    finally:
        result.ended_at = datetime.now()
        _take_unraised_cleanup_failures(result)
        if result.status is Status.BAT_ERROR and not result.error:
            result.error = result.verdict_reason or "case did not set a status"
        collector.add(result)
        progress.mark_running(run_context.report_dir, None)


def _take_unraised_cleanup_failures(result: CaseResult) -> None:
    """실패한 본문 뒤에 가려진 정리 실패를 케이스로 옮긴다.

    판정은 call 단계에서 이미 정해졌으므로 상태는 바꾸지 않는다. 남은 리소스가 리포트에
    드러나게 할 뿐이다.
    """
    result.cleanup_warnings.extend(UNRAISED_CLEANUP_FAILURES)
    UNRAISED_CLEANUP_FAILURES.clear()


def _prior_attempt(report_dir: Path, case_id: str) -> dict | None:
    """FAIL 재확인(BAT_ATTEMPT=2)이면 같은 실행에서 1차로 남긴 그 케이스의 결과."""
    if os.environ.get("BAT_ATTEMPT") != "2":
        return None
    path = report_dir / case_id / "result.json"
    try:
        first = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return first if first.get("status") == Status.FAIL.value else None


def _how_it_ended(call) -> tuple[Raised, str, str]:
    """(끝난 방식, 메시지, minor). minor는 치명적이지 않은 실패(MinorFailure)의 이유다."""
    if call.excinfo is None:
        return Raised.NOTHING, "", ""
    exc = call.excinfo.value
    message = str(exc)[:500]
    if isinstance(exc, VerificationUnavailable):
        return Raised.UNAVAILABLE, message, ""
    if isinstance(exc, pytest.skip.Exception):
        return Raised.SKIP, message, ""
    if isinstance(exc, MinorFailure):
        return Raised.ASSERTION, message, exc.why
    if isinstance(exc, (AssertionError, pytest.fail.Exception)):
        return Raised.ASSERTION, message, ""
    # 관리 API가 응답하지 않거나 5xx를 줬다: 테스트 도구 문제가 아니라 제품 장애다.
    down = product_failure(exc)
    if down:
        if no_response(exc):
            # 응답이 하나도 없었으면 이 PC 네트워크가 끊긴 것일 수도 있다. 그러면 제품 장애가 아니다.
            network = pc_network(runner_executor())
            if network.ok is False:
                return Raised.ERROR, f"{down} — but this PC's own network is down ({network.detail})"[:500], ""
            down = f"{down} [PC network: {network.detail}]"
        return Raised.ASSERTION, down[:500], ""
    return Raised.ERROR, f"{type(exc).__name__}: {message}", ""


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_makereport(item, call):
    """결과를 bat.verdict에 넘기고, pytest 자신의 결과가 그것과 일치하게 한다.

    setup이 성공하지 않았을 때도 분류하므로, skip하거나 예외를 던진 fixture는 실제
    원인을 보고한다.
    """
    outcome = yield
    report = outcome.get_result()
    if report.when == "teardown" or (report.when == "setup" and report.passed):
        return
    case_result = getattr(item, "_bat_case", None)
    if case_result is None:
        return

    raised, message, minor = _how_it_ended(call)
    status, reason = classify(case_result, raised, message)
    known = item.get_closest_marker("known_issue")
    if known:
        # 사용자가 버그로 보지 않기로 한 증상(match)과 일치하는 FAIL만 SKIP이 된다.
        status, reason = apply_known_issue(
            status, reason, str(known.args[0]) if known.args else "", known.kwargs.get("match")
        )
        if status is Status.SKIP:
            report.outcome = "skipped"
            report.longrepr = (str(item.path), item.location[1] or 0, reason)
    # FAIL은 치명적일 때만 남는다(gate 케이스, 전부 실패, 사용자 결과까지 틀림).
    status, reason = apply_gate(case_result, status, reason, minor=minor)
    if case_result.attempts:
        status, reason = merge_retry(case_result.attempts[0], status, reason)
    reason = _with_cleanup_note(status, reason, case_result.cleanup_warnings)
    case_result.status = status
    case_result.verdict_reason = reason
    if status in (Status.FAIL, Status.WARN, Status.BAT_ERROR):
        case_result.error = case_result.error or str(report.longrepr or reason)[:1000]
        if report.passed:
            # 기록만 되고 예외로 올라가지 않은 실패나 끝났다고 주장하지 않은 본문 때문에
            # pytest(따라서 종료 코드)가 성공을 보고하면 안 된다.
            report.outcome = "failed"
            report.longrepr = reason
    # 새 리스트로 만든다: report.user_properties는 item 자신의 리스트라, 여기에 append하면
    # 상태가 teardown 리포트까지 넘어가 두 번 세어진다.
    report.user_properties = [
        *report.user_properties,
        ("bat_status", status.value),
        ("bat_reason", reason),
    ]


def _with_cleanup_note(status: Status, reason: str, warnings: list[str]) -> str:
    """검사는 전부 통과했지만(PASS) 정리가 실패한 케이스는 사유에 그 사실을 남긴다. 판정은 바꾸지
    않는다. 남은 리소스는 실행 종료 검사(pytest_sessionfinish)가 실행 실패로 만든다."""
    if status is Status.PASS and warnings:
        return f"{reason}; cleanup failed after the checks passed: {'; '.join(warnings)}"
    return reason


_TESTSTATUS = {
    Status.UNVERIFIED.value: ("unverified", "U", "UNVERIFIED"),
    Status.WARN.value: ("warn", "W", "WARN"),
    Status.BAT_ERROR.value: ("bat_error", "E", "BAT_ERROR"),
}


def pytest_report_teststatus(report, config):
    if report.when == "teardown":
        return None
    return _TESTSTATUS.get(dict(getattr(report, "user_properties", None) or []).get("bat_status"))


def pytest_terminal_summary(terminalreporter):
    for category, title in (("warn", "BAT WARN (needs a look)"), ("unverified", "BAT UNVERIFIED (not a pass)"),
                            ("bat_error", "BAT_ERROR (test tool / environment, not the product)")):
        reports = terminalreporter.stats.get(category, [])
        if not reports:
            continue
        terminalreporter.section(title)
        for report in reports:
            props = dict(report.user_properties)
            terminalreporter.line(f"{props.get('bat_status')} {report.nodeid} - {props.get('bat_reason', '')}")


@pytest.hookimpl(tryfirst=True)  # xdist가 그룹을 node id 접미사로 바꾸기 전에
def pytest_collection_modifyitems(config, items):
    log.info("Collected %d test(s) before filtering", len(items))
    _group_by_workspace(items)

    # --case는 case 마커로 거른다. pytest의 -k로는 이 마커를 볼 수 없다.
    wanted = env("BAT_CASE_FILTER")
    if not wanted:
        return

    targets = {value.strip().upper() for value in wanted.split(",") if value.strip()}
    selected, deselected = [], []
    for item in items:
        marker = item.get_closest_marker("case")
        case_id = str(marker.args[0]).upper() if marker else ""
        (selected if case_id in targets else deselected).append(item)

    if deselected:
        config.hook.pytest_deselected(items=deselected)
    items[:] = selected

    if not selected:
        log.warning("No case matched %s", ", ".join(sorted(targets)))


def _group_by_workspace(items) -> None:
    """파일마다 고정된 lane-x 그룹을 그 워크스페이스의 그룹으로 바꾼다.

    파일 마커는 설계대로의 레인(레인마다 단말과 워크스페이스 하나)을 가리킨다. 그 수가
    모자라면 스케줄러가 레인을 병합하는데, 그룹도 따라가지 않으면 병합된 레인이 여전히
    나란히 돈다(bat/scheduler.py).
    """
    product_items = [i for i in items if i.get_closest_marker("product")]
    if not product_items:
        return
    try:
        lanes = build_lanes(build_run_context(profile_name=env("BAT_PROFILE", "qa")))
    except Exception as exc:  # noqa: BLE001 - 스테이지 설정 없음: 파일 그룹을 유지한다
        log.warning("Keeping file lane groups: %s", exc)
        return
    for item in product_items:
        product = str(item.get_closest_marker("product").args[0])
        # xdist는 node 체인의 xdist_group을 전부 이어 붙이므로("lane-b_ws-sbatest1"),
        # 파일의 그룹은 우선순위에서 밀리는 정도가 아니라 아예 없어져야 한다.
        for node in item.listchain():
            node.own_markers[:] = [m for m in node.own_markers if m.name != "xdist_group"]
        item.add_marker(pytest.mark.xdist_group(concurrency_group(lanes, product)))


def pytest_collection_finish(session):
    """`bat progress`용으로 이번 실행의 계획(돌 케이스)을 쓴다.

    모든 워커가 같은 item을 수집하므로 계획은 하나면 된다.
    """
    if session.config.option.collectonly or os.environ.get("PYTEST_XDIST_WORKER", "gw0") != "gw0":
        return
    if os.environ.get("BAT_PHASE", "main") != "main":  # 기준선·재확인은 본 실행의 계획을 덮지 않는다
        return
    case_ids = [str(m.args[0]) for m in (i.get_closest_marker("case") for i in session.items) if m]
    if not case_ids:
        return
    try:
        context = build_run_context(profile_name=env("BAT_PROFILE", "qa"))
        progress.write_plan(context.report_dir, context.run_id, context.profile.name, case_ids,
                            int(os.environ.get("PYTEST_XDIST_WORKER_COUNT", "1")))
    except Exception as exc:  # noqa: BLE001 - 진행 상황 기록 때문에 실행이 멈추면 안 된다
        log.warning("No progress plan for this run: %s", exc)


def _ran_bat_cases(terminalreporter) -> bool:
    """이번 세션에서 BAT 케이스(case fixture를 쓴 테스트)가 하나라도 판정됐는가. selfcheck만
    돌린 세션은 환경에 접속하지 않는다."""
    return any(
        dict(getattr(report, "user_properties", []) or []).get("bat_status")
        for reports in terminalreporter.stats.values()
        for report in reports
    )


def pytest_sessionfinish(session, exitstatus):
    """이번 실행(run_id)이 만든 리소스가 남았으면 실행을 실패로 끝낸다.

    xdist에서는 모든 워커가 끝난 뒤 컨트롤러에서만 본다(워커끼리는 서로의 진행 중인 리소스를
    잔여물로 볼 수 있다). 목록을 읽지 못하면 확인 못 함으로 알리고 실패로 만들지는 않는다.
    """
    if os.environ.get("PYTEST_XDIST_WORKER"):
        return
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is None or not _ran_bat_cases(reporter):
        return
    from bat.leftovers import find_run_leftovers

    try:
        context = build_run_context(profile_name=env("BAT_PROFILE", "qa"))
        found, unread = find_run_leftovers(context, context.run_id)
    except Exception as exc:  # noqa: BLE001 - 확인 못 함으로 알린다
        reporter.write_line(f"BAT leftover check could not run: {type(exc).__name__}: {exc}", yellow=True)
        return
    for line in unread:
        reporter.write_line(f"BAT leftover check: not confirmed, {line}", yellow=True)
    if not found:
        return
    try:  # 실행 판정(gate)이 읽는다
        context.report_dir.mkdir(parents=True, exist_ok=True)
        (context.report_dir / f"leftovers-{os.environ.get('BAT_PHASE', 'main')}.json").write_text(
            json.dumps(found, ensure_ascii=False, indent=1), encoding="utf-8")
    except (OSError, AttributeError) as exc:
        reporter.write_line(f"BAT leftover list not saved: {exc}", yellow=True)
    reporter.section("BAT resources this run left behind (the run fails)", red=True)
    for line in found:
        reporter.write_line(line, red=True)
    reporter.write_line("Remove them with 'bat sweep --delete' before the next run.")
    session.exitstatus = pytest.ExitCode.TESTS_FAILED


def pytest_configure(config):
    os.environ.setdefault("BAT_RUN_ID", datetime.now().strftime("%Y%m%d-%H%M%S"))
    Path("reports").mkdir(exist_ok=True)
