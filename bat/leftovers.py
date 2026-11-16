"""BAT가 만든 리소스가 테넌트에 남았는지 본다.

남은 BLOCK 정책은 다음 실행의 결과를 바꾸고, 그 실패는 잔여물이 아니라 제품 결함처럼
보인다. 실행이 끝날 때는 그 실행(run_id)이 만든 것만(find_run_leftovers), BAT-BASIC-005는
이전 실행들이 남긴 것을 본다. 이름이 BAT 규칙(BAT-<제품>-<번호>-<run_id>...)이거나, 이름 없이
description에 그 이름을 담는 정책(GenAI)을 센다. 다른 사람의 실행은 run_id가 달라 실행 종료
검사에서는 세지 않는다.
"""
from __future__ import annotations

import logging
from typing import Callable

from bat.fixtures.naming import belongs_to_run, is_bat_resource

log = logging.getLogger(__name__)


def readers(rest, gql) -> list[tuple[str, Callable[[], tuple[list[dict], bool]]]]:
    """(종류, 읽기) 목록. 읽기는 (행, 목록이 전체인지)를 돌려준다."""
    from bat.fixtures import graphql_policies as g
    from bat.fixtures.policies import DlpPolicyFactory, WebPolicyFactory

    def whole(read: Callable[[], list[dict]]) -> Callable[[], tuple[list[dict], bool]]:
        return lambda: (read(), True)  # GraphQL 목록은 페이지를 나누지 않는다

    return [
        ("web policy", lambda: WebPolicyFactory(rest).list()),
        ("dlp policy", lambda: DlpPolicyFactory(rest).list()),
        ("genai policy", whole(lambda: g.GenAIPolicyFactory(gql).list())),
        ("casb in-app control", whole(lambda: g.InAppControlReader(gql).list())),
        ("casb saas access", whole(lambda: g.SaasAccessFactory(gql).list())),
        ("rbi policy", whole(lambda: g.RbiPolicyReader(gql).list())),
        ("dns firewall policy", whole(lambda: g.DnsFirewallFactory(gql).list())),
        ("application firewall policy", whole(lambda: g.ApplicationFirewallFactory(gql).list())),
        ("ztna access control", whole(lambda: g.AccessControlFactory(gql).list())),
        ("ztna tunnel", whole(lambda: g.TunnelFactory(gql).list())),
        ("ztna access policy", whole(lambda: g.AccessPolicyFactory(gql).list())),
    ]


def bat_name(row: dict) -> str:
    """행이 BAT 리소스면 그 BAT 이름, 아니면 "". GenAI는 이름 대신 description에 담는다."""
    name = str(row.get("name") or "")
    if is_bat_resource(name):
        return name
    description = str(row.get("description") or "")
    marker = "BAT generated GenAI policy "
    words = description.split(marker, 1)[1].split() if not name and marker in description else []
    return words[0] if words and is_bat_resource(words[0]) else ""


def scan(rest, gql, keep: Callable[[str], bool]) -> tuple[list[str], list[str]]:
    """(keep(이름)이 참인 BAT 리소스, 확인하지 못한 목록)."""
    found: list[str] = []
    unread: list[str] = []
    for label, read in readers(rest, gql):
        try:
            rows, complete = read()
        except Exception as exc:  # noqa: BLE001 - 목록 하나를 못 읽어도 나머지는 본다
            unread.append(f"{label}: {type(exc).__name__}: {str(exc)[:120]}")
            continue
        if not complete:
            unread.append(f"{label}: only the first {len(rows)} rows could be read")
        for row in rows:
            name = bat_name(row)
            if name and keep(name):
                found.append(f"{label} id={row.get('id')} {name}")
    return found, unread


def find_run_leftovers(context, run_id: str) -> tuple[list[str], list[str]]:
    """(이번 실행이 남긴 리소스, 확인하지 못한 목록). 레인이 쓰는 워크스페이스마다 본다."""
    from bat.cli import _console_for, _rest_for
    from bat.scheduler import build_lanes

    found: list[str] = []
    unread: list[str] = []
    seen: set[str] = set()
    for lane in build_lanes(context):
        workspace = lane.workspace
        if workspace.name in seen:
            continue
        seen.add(workspace.name)
        try:
            rest = _rest_for(context, workspace)
            gql = _console_for(context, workspace)
        except Exception as exc:  # noqa: BLE001 - 확인하지 못한 것으로 보고한다
            unread.append(f"{workspace.name}: cannot connect ({type(exc).__name__}: {str(exc)[:120]})")
            continue
        with rest, gql:
            left, missed = scan(rest, gql, lambda name: belongs_to_run(name, run_id))
        found += [f"{workspace.name} {line}" for line in left]
        unread += [f"{workspace.name} {line}" for line in missed]
    return found, unread
