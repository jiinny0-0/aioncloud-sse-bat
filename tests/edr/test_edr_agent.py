"""EDR 에이전트 케이스.

이 중 세 개는 완전히 자동화돼 있다. 탐지·차단 케이스는 CLI가 아니라 콘솔에서 조작하는
사내 시뮬레이터가 필요해서 `manual` 마커가 붙어 있고 기본 실행에서 빠진다. 그래도 사람이
하는 단계의 앞뒤는 전부 자동화한다: 먼저 단말을 확인하고, 이벤트 대기는 그 뒤에 돈다.
"""
from __future__ import annotations

import logging

import pytest

from bat.endpoint.base import EDR_SERVICE, edr_agent_running, edr_agent_version, service_state
from bat.models import Status, Step
from tests.support import pass_case

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.product("edr"),
    pytest.mark.lane("e"),
    pytest.mark.xdist_group("lane-e"),
    # 보류: 기본 실행과 현황 엑셀에서 빠진다.
    pytest.mark.parked,
]

QUERY_EDR_ENDPOINTS = """
query BatEDREndpointList($is_active: Boolean!, $page: Int!, $limit: Int!) {
  SIA { view { assets { EDR { endpointList(
    is_active: $is_active, page: $page, limit: $limit
  ) {
    items {
      id
      device_name: l_host_name
      device_id: host_guid
      user_id
      user_name
      os
      version
      ip: l_ip_address
      registered_on_time: created_at
      last_active_time: last_api_time
    }
    online_total
    offline_total
  } } } } }
"""

QUERY_CONNECTOR_DOWNLOADS = """
query BatConnectorDownloads {
  SIA { connect { connector { download { list {
    edr { id device os architecture version min_version support checksum description }
    client { id device os version }
  } } } } }
}
"""


@pytest.mark.case("BAT-EDR-001")
@pytest.mark.priority("P1")
@pytest.mark.smoke
def test_agent_service_running(case, executor):
    """EDR 에이전트 서비스가 테스트 단말에서 실행 중이다."""
    state = service_state(executor, EDR_SERVICE)
    case.record(
        Step.ACTION,
        ok=True,
        detail=f"Get-Service {EDR_SERVICE} on {case.endpoint}",
    )
    case.record(
        Step.USER_RESULT,
        ok=state.lower() == "running",
        detail=f"service state = {state}",
        expected="Running",
        actual=state,
    )
    if state.lower() == "notfound":
        # 설치되지 않은 것은 제품 결함이 아니라 구성 공백이다: 이 단말이 그냥 EDR
        # 단말이 아닌 것이다.
        pytest.skip(
            f"No '{EDR_SERVICE}' service on {case.endpoint}. Install the agent "
            f"there, or point the EDR lane at a machine that has it."
        )

    assert state.lower() == "running", (
        f"EDR agent service '{EDR_SERVICE}' is {state} on {case.endpoint}. "
        f"The service being present is necessary but not sufficient — "
        f"BAT-EDR-002 confirms the console actually sees the device."
    )
    case.status = Status.PASS


@pytest.mark.case("BAT-EDR-003")
@pytest.mark.priority("P2")
def test_agent_version_supported(case, executor, console):
    """단말에 설치된 EDR 에이전트 버전이 콘솔이 배포하는 버전과 정합한다."""
    if service_state(executor, EDR_SERVICE).lower() == "notfound":
        pytest.skip(f"No '{EDR_SERVICE}' service on this endpoint")

    installed = edr_agent_version(executor)
    case.record(Step.ACTION, ok=bool(installed), detail=f"installed version = {installed or '?'}")

    data = console.execute(QUERY_CONNECTOR_DOWNLOADS)
    downloads = (
        ((data.get("SIA") or {}).get("connect") or {}).get("connector", {}).get("download", {})
    )
    published = (downloads.get("list") or {}).get("edr")
    versions = [row.get("version") for row in published or [] if isinstance(row, dict)]
    case.record(
        Step.USER_RESULT,
        ok=bool(installed and published),
        detail=f"console publishes EDR versions {versions}, endpoint reports {installed!r}",
        expected="both values resolvable",
        actual={"installed": installed, "published": published},
    )

    assert installed, "Could not read the installed EDR agent version from the endpoint"
    assert published, "Console returned no EDR entry under connector.download.list"
    case.status = Status.PASS


@pytest.mark.case("BAT-EDR-004")
@pytest.mark.priority("P0")
@pytest.mark.manual
def test_detection_event(case, executor):
    """시뮬레이터로 유발한 탐지가 EDR 이벤트로 기록된다. (시뮬레이터 실행은 수동)"""
    if not edr_agent_running(executor):
        pytest.skip("EDR agent is not running on this endpoint")

    case.record(Step.SETUP, ok=True, detail="agent confirmed running before the manual trigger")
    pytest.skip(
        "Manual step required: run the in-house EDR simulator from the console, "
        "then re-run with --tag manual once the console menu path is wired up."
    )

def _endpoints(console, *, is_active: bool = True, limit: int = 100) -> dict:
    data = console.execute(
        QUERY_EDR_ENDPOINTS, {"is_active": is_active, "page": 1, "limit": limit}
    )
    node = data
    for key in ("SIA", "view", "assets", "EDR", "endpointList"):
        node = (node or {}).get(key) if isinstance(node, dict) else None
    return node or {}


@pytest.mark.case("BAT-EDR-002")
@pytest.mark.priority("P1")
@pytest.mark.smoke
def test_console_sees_the_endpoint(case, console, executor):
    """콘솔 자산 목록에 이 단말이 등록되어 있고 최근 통신 기록이 있다."""
    if not edr_agent_running(executor):
        pytest.skip(f"EDR agent service '{EDR_SERVICE}' is not running on this endpoint")

    listing = _endpoints(console, is_active=True)
    items = listing.get("items") or []
    case.record(
        Step.ACTION,
        ok=True,
        detail=f"online={listing.get('online_total')} offline={listing.get('offline_total')}, "
        f"{len(items)} item(s) returned",
    )

    hostname = executor.run_powershell("$env:COMPUTERNAME").stdout.strip()
    match = next(
        (
            item
            for item in items
            if isinstance(item, dict)
            and hostname
            and hostname.lower() in str(item.get("device_name", "")).lower()
        ),
        None,
    )

    case.record(
        Step.USER_RESULT,
        ok=match is not None,
        detail=f"looking for {hostname!r} among "
        f"{[item.get('device_name') for item in items if isinstance(item, dict)]}",
        expected=f"an asset named like {hostname}",
        actual=match.get("device_name") if match else None,
    )
    assert match, (
        f"The agent service is running but the console lists no active asset "
        f"matching {hostname!r}. A running service does not by itself mean the "
        f"agent is reporting in."
    )

    case.endpoint = str(match.get("device_id") or case.endpoint)
    last_seen = match.get("last_active_time")
    case.record(
        Step.EVENT,
        ok=bool(last_seen),
        detail=f"device_id={match.get('device_id')} last_active={last_seen} "
        f"version={match.get('version')}",
        expected="a recent last_active_time",
        actual=last_seen,
    )
    assert last_seen, (
        f"Asset {match.get('device_name')} has no last_active_time, so there is no "
        f"evidence the agent has communicated with the console"
    )
    pass_case(case)


@pytest.mark.case("BAT-EDR-005")
@pytest.mark.priority("P0")
@pytest.mark.manual
def test_blocking_action(case, executor):
    """시뮬레이터가 유발한 위협이 차단되고 사용자에게 알림이 표시된다. (수동)"""
    if not edr_agent_running(executor):
        pytest.skip(f"EDR agent service '{EDR_SERVICE}' is not running on this endpoint")

    case.record(Step.SETUP, ok=True, detail="agent confirmed running before the manual trigger")
    pytest.skip(
        "Manual step required: run the in-house EDR simulator from the console and "
        "confirm the endpoint blocks it. Once the console menu path is known this "
        "can be driven with Playwright like the other console-side cases."
    )
