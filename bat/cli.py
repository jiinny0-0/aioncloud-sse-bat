"""`bat` 명령줄 진입점.

러너를 새로 구현하지 않고 pytest를 감싼다. fixture, 마커, 재시도, xdist 스케줄링을
그대로 얻고, 레인 묶음은 각 테스트가 선언하는 xdist_group 마커로 표현한다.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from bat.scheduler import build_lanes, estimate_runtime, parallel_slots
from bat.settings import ROOT, build_run_context, new_run_id

PRODUCT_DIRS = {
    "swg": "tests/swg",
    "dlp": "tests/dlp",
    "fwaas": "tests/fwaas",
    "rbi": "tests/rbi",
    "casb": "tests/casb",
    "genai": "tests/genai",
    "ztna": "tests/ztna",
    "edr": "tests/edr",
    "cross": "tests/cross",
    "basic": "tests/basic",
}

# EDR, RBI는 보류(parked)다. `--tag parked`로는 여전히 돌릴 수 있다.
DEFAULT_MARKERS = "not manual and not crud and not parked"

# 케이스당 초. qa 직렬 실행에서 잰 값이다(5초 단위로 올림).
ESTIMATED_SECONDS = {
    "BAT-BAS-001": 5, "BAT-BAS-002": 5, "BAT-BAS-003": 5, "BAT-BAS-004": 5, "BAT-BAS-005": 5,
    "BAT-BAS-006": 5,
    "BAT-SWG-001": 30, "BAT-SWG-002": 25, "BAT-SWG-003": 75, "BAT-SWG-004": 35, "BAT-SWG-005": 45,
    "BAT-SWG-006": 110, "BAT-SWG-007": 10, "BAT-SWG-008": 15, "BAT-SWG-009": 5, "BAT-SWG-010": 5,
    "BAT-SWG-011": 40, "BAT-SWG-012": 40, "BAT-SWG-013": 35, "BAT-SWG-014": 45, "BAT-SWG-015": 15,
    "BAT-SWG-016": 25, "BAT-SWG-017": 15, "BAT-SWG-018": 30, "BAT-SWG-019": 25, "BAT-SWG-020": 10,
    "BAT-SWG-021": 15, "BAT-SWG-022": 20, "BAT-SWG-023": 25,
    "BAT-DLP-001": 35, "BAT-DLP-002": 35, "BAT-DLP-003": 35, "BAT-DLP-004": 35, "BAT-DLP-005": 25,
    "BAT-DLP-006": 15, "BAT-DLP-007": 20, "BAT-DLP-008": 25,
    "BAT-FW-001": 25, "BAT-FW-002": 15, "BAT-FW-003": 15, "BAT-FW-004": 5, "BAT-FW-005": 5,
    "BAT-FW-006": 15, "BAT-FW-007": 5, "BAT-FW-008": 5, "BAT-FW-009": 10, "BAT-FW-010": 15,
    "BAT-FW-011": 15, "BAT-FW-012": 5, "BAT-FW-013": 15,
    "BAT-RBI-001": 25, "BAT-RBI-002": 5,
    "BAT-CASB-001": 5, "BAT-CASB-002": 5, "BAT-CASB-003": 10, "BAT-CASB-004": 55, "BAT-CASB-005": 5,
    "BAT-GAI-001": 5,
    "BAT-ZTNA-001": 5, "BAT-ZTNA-002": 5, "BAT-ZTNA-003": 5, "BAT-ZTNA-004": 5, "BAT-ZTNA-005": 5,
    "BAT-ZTNA-006": 5, "BAT-ZTNA-007": 5, "BAT-ZTNA-008": 5,
    "BAT-EDR-001": 5, "BAT-EDR-002": 5, "BAT-EDR-003": 5, "BAT-EDR-004": 60, "BAT-EDR-005": 60,
    "BAT-X-001": 25, "BAT-X-002": 20, "BAT-X-003": 25, "BAT-X-004": 25, "BAT-X-005": 20,
    "BAT-X-006": 50, "BAT-X-007": 20, "BAT-X-008": 15, "BAT-X-009": 15, "BAT-X-010": 70,
    "BAT-X-011": 50,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bat", description="AIONCLOUD SSE BAT runner")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="execute BAT cases")
    run.add_argument("--product", action="append", default=[], choices=sorted(PRODUCT_DIRS))
    run.add_argument("--tag", action="append", default=[], help="critical, smoke, manual, crud, parked")
    run.add_argument("--profile", default=os.getenv("BAT_PROFILE", "qa"))
    run.add_argument("--workers", type=int, default=0, help="0 = one worker per lane")
    run.add_argument("--case", default="", help="run a single case id, e.g. BAT-SWG-001")
    run.add_argument("--headed", action="store_true", help="show the browser")
    run.add_argument("--dry-run", action="store_true", help="print the plan and exit")
    run.add_argument(
        "--skip-preflight", action="store_true",
        help="do not first check that each endpoint's traffic reaches its workspace",
    )
    run.add_argument("pytest_args", nargs="*", help="extra args passed through to pytest")

    sub.add_parser("progress", help="print the latest run's progress (also in reports/run-progress.md)")

    lanes_cmd = sub.add_parser("lanes", help="print the lane assignment for the current config")
    lanes_cmd.add_argument("--profile", default=os.getenv("BAT_PROFILE", "qa"))

    doctor_cmd = sub.add_parser("doctor", help="check configuration and connectivity")
    doctor_cmd.add_argument("--profile", default=os.getenv("BAT_PROFILE", "qa"))

    sweep = sub.add_parser("sweep", help="find and remove leftover BAT resources")
    sweep.add_argument("--delete", action="store_true", help="actually delete (default: list only)")
    sweep.add_argument("--profile", default=os.getenv("BAT_PROFILE", "qa"))

    status = sub.add_parser(
        "status", help="case tracker with per-stage columns (reports/bat-test-status.xlsx)"
    )
    status.add_argument(
        "action", choices=["sync", "rebuild", "show", "result"],
        help="sync: add new cases; rebuild: refill every stage's columns from saved run "
        "reports; show: print one case; result: rewrite the result CSV of --profile's latest run",
    )
    status.add_argument("case_id", nargs="?", default="", help="for show")
    status.add_argument("--profile", default=os.getenv("BAT_PROFILE", "qa"), help="for result")

    diag = sub.add_parser("traffic", help="check whether this machine's traffic reaches SSE")
    diag.add_argument("--profile", default=os.getenv("BAT_PROFILE", "qa"))

    login = sub.add_parser(
        "login", help="sign in once and cache the console session for later runs"
    )
    login.add_argument("--profile", default=os.getenv("BAT_PROFILE", "qa"))
    login.add_argument(
        "--all-workspaces", action="store_true", help="cache a session per workspace"
    )

    probe = sub.add_parser(
        "probe", help="discover console GraphQL fields without introspection"
    )
    probe.add_argument(
        "--path",
        action="append",
        default=[],
        help="dotted path to probe, e.g. SIA.ztna.accessPolicy (repeatable)",
    )
    probe.add_argument("--mutation", action="store_true", help="probe the mutation root")
    probe.add_argument("--profile", default=os.getenv("BAT_PROFILE", "qa"))

    inspect = sub.add_parser(
        "inspect", help="dump a policy exactly as the API stores it"
    )
    inspect.add_argument("--id", default="", help="web policy id; omit to list them all")
    inspect.add_argument("--dlp", action="store_true", help="dump DLP policies instead")
    inspect.add_argument("--predefined", action="store_true", help="list predefined DLP rules")
    inspect.add_argument("--genai", action="store_true", help="dump GenAI policies")
    inspect.add_argument("--casb", action="store_true", help="dump CASB in-app control policies")
    inspect.add_argument("--saas-access", action="store_true", help="dump CASB SaaS Access policies")
    inspect.add_argument("--rbi", action="store_true", help="dump RBI policies")
    inspect.add_argument("--profile", default=os.getenv("BAT_PROFILE", "qa"))

    diagnose = sub.add_parser(
        "diagnose-user", help="work out why POST /sia/v1/user is rejected"
    )
    diagnose.add_argument("--profile", default=os.getenv("BAT_PROFILE", "qa"))

    schema = sub.add_parser("schema", help="dump console GraphQL operations")
    schema.add_argument(
        "--domain",
        default="",
        help="SIA domain to expand: ztna, genai, casb, rbi, security, log, view ...",
    )
    schema.add_argument("--type", default="", help="describe one type by name")
    schema.add_argument("--query", action="store_true", help="read the query root, not mutation")
    schema.add_argument("--profile", default=os.getenv("BAT_PROFILE", "qa"))
    return parser


def _plan(profile: str) -> tuple[list, dict]:
    context = build_run_context(profile_name=profile)
    lanes = build_lanes(context)
    from bat.report.status_book import parked_ids

    parked = parked_ids()  # 기본 실행에 없으므로 추정에서도 뺀다
    return lanes, estimate_runtime(lanes, {k: v for k, v in ESTIMATED_SECONDS.items() if k not in parked})


def cmd_lanes(profile: str) -> int:
    lanes, estimate = _plan(profile)
    print(f"{'LANE':<6} {'WORKSPACE':<12} {'ENDPOINT':<14} PRODUCTS")
    for lane in lanes:
        endpoint = lane.endpoint.name if lane.endpoint else "-"
        print(f"{lane.name:<6} {lane.workspace.name:<12} {endpoint:<14} {', '.join(lane.products)}")
    print()
    for name, minutes in sorted(estimate.items()):
        if name.startswith("_"):
            continue
        print(f"  lane {name}: ~{minutes} min")
    print(f"\nEstimated wall clock: ~{estimate.get('_total_wall_clock', 0)} min")
    return 0


def cmd_doctor(profile: str) -> int:
    from bat.clients.graphql import GraphQLClient
    from bat.clients.rest import RestClient
    from bat.clients.tokens import TokenBudget, save_console_token

    context = build_run_context(profile_name=profile)
    print(f"Profile      : {context.profile.name}")
    print(f"Console      : {context.profile.console_url}")
    print(f"GraphQL      : {context.profile.graphql_url}")
    print(f"REST         : {context.profile.rest_base_url}")
    print(f"Workspaces   : {', '.join(w.name for w in context.workspaces) or '(none)'}")
    print(f"Endpoints    : {', '.join(e.name for e in context.endpoints) or '(none)'}")
    print(f"Token budget : {context.token_budget}")

    lanes = build_lanes(context)
    workspace = lanes[0].workspace
    budget = TokenBudget(context.token_budget)
    problems: list[str] = []

    # 콘솔 세션. REST 토큰이 있어도 확인한다. 그래야 GraphQL 전용 케이스가 돌기 전에
    # 로그인이 깨진 것이 드러난다.
    console_ok = False
    console_token = ""
    if workspace.has_console_credentials:
        try:
            with GraphQLClient(context.profile, workspace.name) as gql:
                session = gql.login(workspace.login_id, workspace.password)
                console_ok = True
                console_token = gql.token
                # 로그인하면 이 계정의 이전 세션이 끝나므로 캐시된 세션을 바꿔 둔다.
                # 아니면 다음 실행이 "Duplicate login"을 받는다.
                save_console_token(workspace.name, console_token, session.get("expire_at"))
                print(
                    f"Console login: OK ({workspace.name}, "
                    f"user={session.get('user_name')}, role={session.get('user_role')})"
                )
        except Exception as exc:
            print(f"Console login: FAILED - {exc}")
            problems.append("console login")
    else:
        print("Console login: SKIPPED (no BAT_CONSOLE_USER / BAT_CONSOLE_PASSWORD)")

    # REST 토큰. Open API 서버에는 토큰 발급 엔드포인트가 없으므로, 콘솔에서
    # 수동으로 발급한 토큰이 주 경로다.
    token = workspace.openapi_token
    if token:
        print(f"REST token   : from env ({workspace.name})")
    elif console_ok:
        with GraphQLClient(context.profile, workspace.name) as gql:
            gql.login(workspace.login_id, workspace.password)
            token = budget.token_for(gql, workspace.name)
        print("REST token   : minted via makeOpenAPIToken")
    else:
        print("REST token   : MISSING")
        print("  Set BAT_OPENAPI_TOKEN (or BAT_OPENAPI_TOKEN_<WORKSPACE>) in .env,")
        print("  or provide working console credentials.")
        problems.append("rest token")

    if token:
        with RestClient(context.profile, token) as rest:
            if rest.health():
                print("REST probe   : OK")
            else:
                print("REST probe   : FAILED")
                problems.append("rest probe")

    # 로그 점검. 시간대가 틀리면 오류가 아니라 빈 목록이 돌아오므로, 케이스가 이
    # 결과에 기대기 전에 여기서 빈 결과를 드러내 둘 가치가 있다.
    if console_ok:
        from bat.events.web_log import WebLogReader

        try:
            with GraphQLClient(context.profile, workspace.name) as gql:
                gql.use_token(console_token)
                events = WebLogReader(gql).security_events(lookback_min=24 * 60)
            print(f"Security log : {len(events)} event(s) in the last 24h")
            if events:
                print(f"  fields     : {', '.join(sorted(events[0].raw))}")
            else:
                print("  no events — fine on a quiet tenant, suspicious otherwise")
        except Exception as exc:
            print(f"Security log : FAILED - {exc}")
            problems.append("security log")

    print(f"Tokens minted: {budget.issued}/{context.token_budget}")
    print()
    if console_ok:
        print("GraphQL cases: enabled (ZTNA / CASB / RBI / GenAI)")
    else:
        print("GraphQL cases: will skip (console session unavailable)")

    if problems:
        print(f"\nProblems     : {', '.join(problems)}")
        return 1
    print("\nAll checks passed.")
    return 0


def _graphql_policies():
    import bat.fixtures.graphql_policies as module

    return module


def _console_for(context, workspace):
    """로그인된 콘솔 클라이언트. 캐시된 세션을 우선 쓴다."""
    from bat.clients.graphql import GraphQLClient
    from bat.clients.tokens import load_console_token

    client = GraphQLClient(context.profile, workspace.name)
    cached = load_console_token(workspace.name)
    if cached:
        client.use_token(cached)
        return client
    client.login(workspace.login_id, workspace.password)
    return client


def _rest_for(context, workspace):
    """스위트와 같은 방식으로 REST 클라이언트를 만든다."""
    from bat.clients.graphql import GraphQLClient
    from bat.clients.rest import RestClient
    from bat.clients.tokens import TokenBudget

    token = workspace.openapi_token
    if not token:
        budget = TokenBudget(context.token_budget)
        with GraphQLClient(context.profile, workspace.name) as gql:
            gql.login(workspace.login_id, workspace.password)
            token = budget.token_for(gql, workspace.name)
    return RestClient(context.profile, token)


def cmd_sweep(args: argparse.Namespace) -> int:
    """이전 실행이 남긴 리소스를 나열하고, 원하면 지운다.

    남아 있는 BLOCK 정책은 이후 모든 케이스의 결과를 바꾼다.
    """
    from bat.fixtures.naming import is_bat_resource

    context = build_run_context(profile_name=args.profile)
    total = 0

    seen: set[str] = set()
    for lane in build_lanes(context):
        workspace = lane.workspace
        if workspace.name in seen:
            # 테넌트가 하나만 설정돼 있으면 레인끼리 워크스페이스를 공유할 수 있다.
            continue
        seen.add(workspace.name)
        try:
            rest = _rest_for(context, workspace)
        except Exception as exc:
            print(f"{workspace.name}: cannot connect ({exc})")
            continue

        with rest:
            # 워크스페이스 하나에 접속이 안 된다고 sweep을 멈추면 안 된다. 켜진 BLOCK
            # 정책이 남으면 이후 실행의 결과가 바뀐다.
            try:
                payload = rest.get(
                    "/sia/v1/web/policy/list", params={"offset": 1, "limit": 500}
                )
            except Exception as exc:
                print(f"{workspace.name}: SKIPPED - {exc}")
                if "block page" in str(exc).lower():
                    print(
                        "  Stop the connector first: the sweep itself is being blocked "
                        "by the policy it is trying to remove."
                    )
                elif "403" in str(exc) or "401" in str(exc):
                    print(
                        f"  the token for {workspace.name} is not accepted. Issue one "
                        f"from the console and set BAT_OPENAPI_TOKEN_{workspace.name.upper()}."
                    )
                continue

            rows = payload.get("policies") or payload.get("list") or payload.get("data") or []
            leftovers = [
                row for row in rows
                if isinstance(row, dict) and is_bat_resource(str(row.get("name", "")))
            ]
            if not leftovers:
                print(f"{workspace.name}: clean")
                continue

            print(f"{workspace.name}: {len(leftovers)} leftover web policy/policies")
            for row in leftovers:
                print(f"  id={row.get('id')}  {row.get('name')}  enable={row.get('enable')}")
            total += len(leftovers)

            if args.delete:
                ids = [int(row["id"]) for row in leftovers if row.get("id") is not None]
                try:
                    rest.delete("/sia/v1/web/policy", json={"ids": ids})
                    print(f"  deleted {len(ids)}")
                except Exception as exc:
                    print(f"  delete failed: {exc}")

    # 콘솔 전용 제품은 자기 목록을 따로 갖고, 그 삭제 mutation이 아무것도 지우지
    # 않고 성공을 보고한 적이 있어서 따로 정리한다.
    total += _sweep_genai(context, build_lanes(context)[0].workspace, delete=args.delete)
    total += _sweep_fwaas(context, build_lanes(context)[0].workspace, delete=args.delete)
    total += _sweep_casb(context, build_lanes(context)[0].workspace, delete=args.delete)
    total += _sweep_rbi(context, build_lanes(context)[0].workspace, delete=args.delete)
    total += _sweep_signatures(context, build_lanes(context)[0].workspace, delete=args.delete)

    if total and not args.delete:
        print(f"\n{total} leftover resource(s). Re-run with --delete to remove them.")
    return 0


def _sweep_genai(context, workspace, *, delete: bool) -> int:
    from bat.fixtures.naming import is_bat_resource

    try:
        with _console_for(context, workspace) as gql:
            factory = _graphql_policies().GenAIPolicyFactory(gql)
            rows = factory.list()
            leftovers = [
                row
                for row in rows
                if is_bat_resource(f"{row.get('name') or ''}")
                or "BAT generated GenAI policy BAT-" in str(row.get("description") or "")
            ]
            if not leftovers:
                print(f"{workspace.name} (genai): clean")
                return 0

            print(f"{workspace.name} (genai): {len(leftovers)} leftover policy/policies")
            for row in leftovers:
                print(f"  id={row.get('id')}  {row.get('description') or row.get('name')}")

            if delete:
                ids = [int(row["id"]) for row in leftovers if row.get("id") is not None]
                gql.execute(
                    "mutation BatDeleteGenAI($id: [Int]) { SIA { genai { genAIPolicy "
                    "{ delete(id: $id) { status } } } } }",
                    {"id": ids},
                )
                remaining = len(
                    [
                        row
                        for row in factory.list()
                        if row.get("id") in ids
                    ]
                )
                if remaining:
                    print(f"  delete reported success but {remaining} remain")
                else:
                    print(f"  deleted {len(ids)}")
            return len(leftovers)
    except Exception as exc:
        print(f"{workspace.name} (genai): SKIPPED - {str(exc)[:160]}")
        return 0


def _sweep_rbi(context, workspace, *, delete: bool) -> int:
    """RBI 정책. `deleteRBIPolicy`가 실제로 지운 id를 돌려주므로 재확인이 필요 없다."""
    from bat.fixtures.graphql_policies import RbiPolicyReader
    from bat.fixtures.naming import is_bat_resource

    try:
        with _console_for(context, workspace) as gql:
            rows = RbiPolicyReader(gql).list()
            leftovers = [row for row in rows if is_bat_resource(f"{row.get('name') or ''}")]
            if not leftovers:
                print(f"{workspace.name} (rbi): clean")
                return 0

            print(f"{workspace.name} (rbi): {len(leftovers)} leftover policy/policies")
            for row in leftovers:
                print(f"  id={row.get('id')}  {row.get('name')}")

            if delete:
                ids = [int(row["id"]) for row in leftovers if row.get("id") is not None]
                result = gql.execute(
                    "mutation BatDeleteRBI($id: [Int]) { SIA { security "
                    "{ deleteRBIPolicy(id: $id) { result } } } }",
                    {"id": ids},
                )
                deleted = (
                    (((result.get("SIA") or {}).get("security") or {}).get("deleteRBIPolicy") or {}).get("result")
                    or []
                )
                print(f"  deleted {len(deleted)}")
            return len(leftovers)
    except Exception as exc:
        print(f"{workspace.name} (rbi): SKIPPED - {str(exc)[:160]}")
        return 0


def _sweep_signatures(context, workspace, *, delete: bool) -> int:
    """BAT 자신의 Signature Management 항목(testdata.SIGNATURE_TARGET_HOST).

    BAT-SWG-017/021이 이 값을 C&C / Risky Website deny 목록에 넣었다가 다시 뺀다.
    그 사이에 죽은 실행은 이 값을 남긴다. 그 값 하나만 지우고, 각 목록의 나머지는
    원래대로 다시 쓴다.
    """
    from bat.fixtures.graphql_policies import SignaturePatternList
    from bat.fixtures.testdata import SIGNATURE_TARGET_HOST

    found = 0
    try:
        with _console_for(context, workspace) as gql:
            lists = SignaturePatternList(gql)
            for pattern_type in ("CNC", "RISKY_WEBSITE"):
                deny, _ = lists.read(pattern_type)
                if SIGNATURE_TARGET_HOST not in deny:
                    continue
                found += 1
                print(f"{workspace.name} (signature): {SIGNATURE_TARGET_HOST} left in the {pattern_type} deny list")
                if delete:
                    lists.remove_deny(pattern_type, SIGNATURE_TARGET_HOST)
                    print("  removed")
            if not found:
                print(f"{workspace.name} (signature): clean")
            return found
    except Exception as exc:
        print(f"{workspace.name} (signature): SKIPPED - {str(exc)[:160]}")
        return found


def _sweep_fwaas(context, workspace, *, delete: bool) -> int:
    """DNS Firewall과 Application Firewall.

    genai와 달리 이 삭제는 성공을 보고하면 실제로 행을 지우므로, 남은 개수를 다시
    확인할 필요가 없다.
    """
    from bat.fixtures.naming import is_bat_resource

    total = 0
    try:
        with _console_for(context, workspace) as gql:
            for label, factory_name, delete_mutation in (
                ("dns_firewall", "DnsFirewallFactory", "dns_firewall"),
                ("firewall", "ApplicationFirewallFactory", "firewall"),
            ):
                factory = getattr(_graphql_policies(), factory_name)(gql)
                rows = factory.list()
                leftovers = [
                    row for row in rows if is_bat_resource(str(row.get("name") or ""))
                ]
                if not leftovers:
                    print(f"{workspace.name} ({label}): clean")
                    continue

                print(f"{workspace.name} ({label}): {len(leftovers)} leftover policy/policies")
                for row in leftovers:
                    print(f"  id={row.get('id')}  {row.get('name')}")
                total += len(leftovers)

                if delete:
                    ids = [int(row["id"]) for row in leftovers if row.get("id") is not None]
                    gql.execute(
                        f"mutation($id: [Int]) {{ SIA {{ network {{ {delete_mutation} "
                        f"{{ delete(id: $id) {{ result }} }} }} }} }}",
                        {"id": ids},
                    )
                    print(f"  deleted {len(ids)}")
        return total
    except Exception as exc:
        print(f"{workspace.name} (fwaas): SKIPPED - {str(exc)[:160]}")
        return 0


def _sweep_casb(context, workspace, *, delete: bool) -> int:
    """CASB SaaS Access. 남은 BLOCK은 실제 SaaS 앱에 계속 적용된다."""
    from bat.fixtures.naming import is_bat_resource

    try:
        with _console_for(context, workspace) as gql:
            factory = _graphql_policies().SaasAccessFactory(gql)
            leftovers = [
                row for row in factory.list() if is_bat_resource(str(row.get("name") or ""))
            ]
            if not leftovers:
                print(f"{workspace.name} (casb saas access): clean")
                return 0

            print(f"{workspace.name} (casb saas access): {len(leftovers)} leftover policy/policies")
            for row in leftovers:
                print(f"  id={row.get('id')}  {row.get('name')}")

            if delete:
                ids = [int(row["id"]) for row in leftovers if row.get("id") is not None]
                gql.execute(_graphql_policies().DELETE_SAAS_ACCESS, {"id": ids})
                print(f"  deleted {len(ids)}")
            return len(leftovers)
    except Exception as exc:
        print(f"{workspace.name} (casb saas access): SKIPPED - {str(exc)[:160]}")
        return 0


def cmd_traffic(args: argparse.Namespace) -> int:
    """질문 하나에 답한다: 이 단말의 트래픽이 SSE에 닿기는 하는가?

    차단을 기대한 곳에서 페이지가 렌더링되면, 정책이 적용되지 않았거나 요청이 SSE를
    아예 지나지 않은 것이다. 보안로그 양으로 둘을 가른다. 이 테넌트는 접근 로그를
    전혀 남기지 않으므로 접근 로그는 쓰지 않는다.
    """
    from bat.events.web_log import WebLogReader

    context = build_run_context(profile_name=args.profile)
    workspace = build_lanes(context)[0].workspace

    with _console_for(context, workspace) as gql:
        reader = WebLogReader(gql)
        recent = reader.security_events(lookback_min=60)
        day = reader.security_events(lookback_min=24 * 60)

        print(f"Workspace      : {workspace.name}")
        print(f"Security events: {len(recent)} in the last hour, {len(day)} in the last 24h")

        if recent:
            newest = recent[0].raw
            print("\nMost recent security event:")
            for key in ("time", "user_name", "policy_name", "action", "full_uri", "device_id"):
                if key in newest:
                    print(f"  {key}: {newest[key]}")
            print(f"  (all fields: {', '.join(sorted(newest))})")
            print("\nTraffic reaches SSE and events are readable through the API.")
        elif day:
            print("\nEvents exist but none in the last hour.")
            print("Generate traffic from this machine, then run this again:")
            print('  curl.exe -s -o NUL https://httpbin.org/get')
        else:
            print("\nNo security events at all. Check that the connector is connected")
            print("and signed into the same workspace the token was issued for.")
    return 0


DEFAULT_PROBE_PATHS = [
    "SIA.security",
    "SIA.casb",
    "SIA.genai",
    "SIA.ztna",
    "SIA.rbi",
    "SIA.network",
    "SIA.log",
    "SIA.view",
]


def cmd_login(args: argparse.Namespace) -> int:
    """콘솔 세션을 받아 이후 실행용으로 보관한다.

    커넥터가 켜져 있으면 SSE가 로그인 본문(비밀번호가 들어 있음)을 막을 수 있으므로
    터널을 내린 상태에서 실행한다. 이후 실행은 캐시된 세션을 재사용한다.
    """
    from bat.clients.graphql import GraphQLClient
    from bat.clients.tokens import save_console_token

    context = build_run_context(profile_name=args.profile)
    lanes = build_lanes(context)
    workspaces = (
        {lane.workspace.name: lane.workspace for lane in lanes}.values()
        if args.all_workspaces
        else [lanes[0].workspace]
    )

    failures = 0
    for workspace in workspaces:
        if not workspace.has_console_credentials:
            print(f"{workspace.name}: no console credentials configured")
            failures += 1
            continue

        try:
            with GraphQLClient(context.profile, workspace.name) as gql:
                session = gql.login(workspace.login_id, workspace.password)
                path = save_console_token(
                    workspace.name, gql.token, session.get("expire_at")
                )
            print(
                f"{workspace.name}: signed in as {session.get('user_name')} "
                f"({session.get('user_role')}), session cached in {path.name}"
            )
        except Exception as exc:
            print(f"{workspace.name}: {str(exc)[:300]}")
            failures += 1

    if failures:
        print(
            "\nIf the sign-in was intercepted, disconnect the connector and run "
            "this again. The cached session then works with the connector up."
        )
        return 1

    print("\nRuns will now reuse this session instead of signing in.")
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    """introspection 없이 도메인이 노출하는 필드를 알아낸다.

    서버는 __schema와 __type을 거부하지만, 모르는 필드에 대한 오류가 부모 타입을
    알려 주고, 서브셀렉션 없이 보낸 아는 필드는 그렇다고 알려 준다.
    """
    from bat.clients.graphql import GraphQLClient

    context = build_run_context(profile_name=args.profile)
    workspace = build_lanes(context)[0].workspace
    paths = args.path or DEFAULT_PROBE_PATHS
    prefix = "mutation " if args.mutation else ""

    with _console_for(context, workspace) as gql:
        for path in paths:
            parts = path.split(".")
            selection = "__bat_probe"
            for part in reversed(parts):
                selection = f"{part} {{ {selection} }}"
            query = f"{prefix}{{ {selection} }}"

            try:
                gql.execute(query)
                print(f"{path}: returned data for a field that should not exist")
            except Exception as exc:
                message = str(exc)
                if "Cannot query field" in message and "on type" in message:
                    type_name = message.rsplit("on type", 1)[-1].strip().strip('".')
                    print(f"{path}: type {type_name}")
                else:
                    print(f"{path}: {message[:200]}")

    print(
        "\nThe type name is the useful part. To list a type's fields, guess a "
        "field name and read the error: a real field complains about a missing "
        "sub-selection or a required argument, a missing one says 'Cannot query "
        "field'."
    )
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    """정책을 API가 저장한 그대로 출력한다.

    콘솔에서 손으로 정책을 만들고 여기서 다시 읽으면, 명세에 없는 입력 형태를 알 수
    있다.
    """
    import json as jsonlib

    context = build_run_context(profile_name=args.profile)
    workspace = build_lanes(context)[0].workspace

    # 콘솔 전용 제품은 REST 조회가 없으므로 GraphQL로 읽는다.
    console_dumps = {
        "genai": lambda gql: _graphql_policies().GenAIPolicyFactory(gql).list(),
        "casb": lambda gql: _graphql_policies().InAppControlReader(gql).list(),
        "saas_access": lambda gql: _graphql_policies().SaasAccessFactory(gql).list(),
        "rbi": lambda gql: _graphql_policies().RbiPolicyReader(gql).list(),
    }
    for name, dump in console_dumps.items():
        if getattr(args, name, False):
            with _console_for(context, workspace) as gql:
                print(jsonlib.dumps(dump(gql), indent=2, ensure_ascii=False))
            return 0

    with _rest_for(context, workspace) as rest:
        if args.predefined:
            payload = rest.get("/sia/v1/dlp/policy/predefined")
            print(jsonlib.dumps(payload, indent=2, ensure_ascii=False))
            return 0

        if args.dlp:
            payload = rest.get("/sia/v1/dlp/policy", params={"offset": 1, "limit": 100})
            print(jsonlib.dumps(payload, indent=2, ensure_ascii=False))
            return 0

        if args.id:
            try:
                payload = rest.get(f"/sia/v1/web/policy/{args.id}")
            except Exception as exc:
                if "404" in str(exc):
                    print(f"No web policy with id {args.id}.")
                    print("Run 'bat inspect' with no arguments to see which ids exist.")
                    return 1
                raise
            print(jsonlib.dumps(payload, indent=2, ensure_ascii=False))
            return 0

        listing = rest.get("/sia/v1/web/policy/list", params={"offset": 1, "limit": 100})
        rows = listing.get("policies") or listing.get("list") or listing.get("data") or []
        for row in rows:
            print(
                f"id={row.get('id')}  {row.get('name')!r}  "
                f"action={row.get('action_type')}  enable={row.get('enable')}"
            )
        print("\nRun again with --id <n> to see one policy in full.")
    return 0


def cmd_diagnose_user(args: argparse.Namespace) -> int:
    """요청이 "API가 거부함"인지 "SSE가 전달하지 않음"인지 가른다.

    사용자 생성은 500이나 403 차단 페이지로 응답할 수 있다. 전체 본문과 줄인 본문을
    나란히 보내 보면 두 원인을 구분할 수 있다.
    """
    import secrets

    context = build_run_context(profile_name=args.profile)
    workspace = build_lanes(context)[0].workspace
    suffix = secrets.token_hex(3)

    bodies = {
        "full (as the suite sends it)": {
            "login_id": f"bat-diag-{suffix}@bat.local",
            "first_name": "BAT",
            "last_name": "Tester",
            "password": f"Bat!{secrets.token_urlsafe(10)}9aA",
            "role": "USER",
            "description": "created by BAT diagnostics, safe to delete",
        },
        "minimal (required fields only)": {
            "login_id": f"bat-diag2-{suffix}@bat.local",
            "first_name": "BAT",
            "last_name": "Tester",
            "password": f"Bat!{secrets.token_urlsafe(10)}9aA",
            "role": "USER",
        },
        "simple password": {
            "login_id": f"bat-diag3-{suffix}@bat.local",
            "first_name": "BAT",
            "last_name": "Tester",
            "password": "BatTester1234!",
            "role": "USER",
        },
    }

    with _rest_for(context, workspace) as rest:
        print(f"Workspace: {workspace.name}\n")
        for label, body in bodies.items():
            try:
                rest.post("/sia/v1/user", json=body)
                print(f"{label}: CREATED")
                print(f"  login_id {body['login_id']} — delete it from the console")
            except Exception as exc:
                print(f"{label}: {str(exc)[:200]}")

    print(
        "\nReading the result:\n"
        "  block page  -> the request never reached the API. Disconnect the\n"
        "                 connector and run this again; if it then succeeds, an\n"
        "                 SSE policy is inspecting the suite's own management\n"
        "                 traffic.\n"
        "  500         -> the API accepted the shape and failed internally. That\n"
        "                 is a server-side defect worth reporting with the body\n"
        "                 printed above.\n"
        "  400         -> a field is wrong; the message names it.\n"
        "  CREATED     -> compare that body with the one the suite sends."
    )
    return 0


def cmd_schema(args: argparse.Namespace) -> int:
    """문서를 요청하는 대신 서버에서 스키마를 읽는다."""
    from bat.clients.graphql import GraphQLClient
    from bat.clients.introspect import describe_type, format_type, root_type_names, walk_domain

    context = build_run_context(profile_name=args.profile)
    workspace = build_lanes(context)[0].workspace

    with _console_for(context, workspace) as gql:
        query_root, mutation_root = root_type_names(gql)

        if args.type:
            lines = format_type(describe_type(gql, args.type))
        else:
            root = query_root if args.query else mutation_root
            if args.domain:
                # SIARootMutation은 제품마다 자기 필드 아래에 중첩해 둔다.
                sia = describe_type(gql, root)
                sia_field = next(
                    (f for f in sia.get("fields") or [] if f["name"] == "SIA"), None
                )
                if sia_field:
                    from bat.clients.introspect import render_type

                    root = render_type(sia_field.get("type")).strip("[]!")
                lines = walk_domain(gql, root, args.domain)
            else:
                lines = format_type(describe_type(gql, root))

    print("\n".join(lines))
    return 0


EXCLUDE_FILE = ROOT.parent / "bat-exclude.json"


def _load_exclusions() -> list[str]:
    """all 실행 제외 목록. 없거나 빈 파일이면 빈 목록, 형식이 깨졌으면 예외."""
    import json
    try:
        text = EXCLUDE_FILE.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        return []
    if not text.strip():
        return []
    data = json.loads(text)
    ids: list[str] = []
    for entry in (data.get("items", []) if isinstance(data, dict) else []):
        value = str(entry.get("id", "") if isinstance(entry, dict) else entry).strip()
        if value and value not in ids:
            ids.append(value)
    return ids


def cmd_run(args: argparse.Namespace) -> int:
    lanes, estimate = _plan(args.profile)

    if args.dry_run:
        cmd_lanes(args.profile)
        return 0

    run_id = os.getenv("BAT_RUN_ID") or new_run_id()
    env = {
        **os.environ,
        "BAT_PROFILE": args.profile,
        "BAT_RUN_ID": run_id,
        "BAT_HEADED": "1" if args.headed else "",
    }

    targets = [PRODUCT_DIRS[p] for p in args.product] or ["tests"]
    if args.case and not args.product:
        # 수집 범위도 좁힌다. 그래야 워커 다섯 개가 전부 버릴 테스트 모듈을 각자
        # 다 import하지 않는다.
        prefix = args.case.split("-")[1].lower() if "-" in args.case else ""
        mapped = {"swg": "swg", "dlp": "dlp", "fw": "fwaas", "rbi": "rbi", "casb": "casb",
                  "gai": "genai", "ztna": "ztna", "edr": "edr", "x": "cross"}.get(prefix)
        if mapped:
            targets = [PRODUCT_DIRS[mapped]]
    # 케이스 하나에는 워커 하나면 된다. 워커가 워크스페이스보다 많으면 케이스끼리
    # 서로의 정책을 맞는다.
    default_workers = 1 if args.case else parallel_slots(lanes)
    workers = args.workers or default_workers

    command = [sys.executable, "-m", "pytest", *targets, "-p", "xdist"]
    command += ["-n", str(workers), "--dist", "loadgroup"]

    tags = args.tag or []
    marker_expr = " or ".join(tags) if tags else DEFAULT_MARKERS
    command += ["-m", marker_expr]

    if args.case:
        # 케이스 id는 pytest 마커에 있으므로, 필터링은 -k가 아니라 conftest의 수집
        # 훅에서 한다.
        env["BAT_CASE_FILTER"] = args.case
    if not args.product and not args.case:
        try:
            excluded = _load_exclusions()
        except Exception as exc:
            print(f"[EXCLUDE] ERROR cannot read {EXCLUDE_FILE}: {exc.__class__.__name__}")
            return 2
        if excluded:
            env["BAT_EXCLUDE"] = ",".join(excluded)
            command += ["-p", "bat.exclude_plugin"]
            print(f"[EXCLUDE] items={','.join(excluded)}")
    command += args.pytest_args

    print(f"Run id       : {run_id}")
    print(f"Lanes        : {len(lanes)} (workers={workers})")
    print(f"Marker       : {marker_expr}")
    if args.case:
        print(f"Case filter  : {args.case}")
    print(f"Estimate     : ~{estimate.get('_total_wall_clock', 0)} min")
    missing = [
        target
        for target in targets
        if not list((ROOT / target).glob("test_*.py"))
    ]
    if missing:
        print(f"\nNo test files under: {', '.join(missing)}")
        print("Nothing will run. Check that the directory was extracted.")
        return 1

    print(f"Command      : {' '.join(command)}\n")

    if not args.skip_preflight and not _preflight_passes(args.profile, run_id):
        return EXIT_PREFLIGHT

    pytest_code = subprocess.call(command, cwd=str(ROOT), env=env)
    code = bat_exit_code(pytest_code, run_id)
    _record_in_status_book(args.profile, run_id)
    _finish_progress(run_id)
    return code


def _finish_progress(run_id: str) -> None:
    from bat.report import progress
    from bat.settings import REPORTS_DIR

    for run_dir in REPORTS_DIR.glob(f"*/{run_id}"):
        if (run_dir / progress.PLAN_NAME).exists() and progress.update(run_dir, finished=True):
            print(f"Progress     : {REPORTS_DIR / progress.PROGRESS_NAME}")


def cmd_progress() -> int:
    """가장 최근 실행의 진행 상황. 그 실행이 디스크에 남긴 파일로 만든다."""
    from bat.report import progress

    run_dir = progress.latest_run_dir()
    if run_dir is None:
        print("No run with a progress plan yet (bat run writes one).")
        return 1
    print(progress.render(run_dir), end="")
    return 0


def _record_in_status_book(profile: str, run_id: str) -> None:
    """실행 결과를 현황표와 그 스테이지의 결과 엑셀에 쓴다.

    기록용일 뿐이다. 여기서 실패하면 출력만 하고 종료 코드는 절대 바꾸지 않는다.
    """
    from bat.report import result_book, status_book

    try:
        path = status_book.record_run(profile, run_id)
    except Exception as exc:  # noqa: BLE001 - 실행의 판정이 이것에 좌우되면 안 된다
        print(f"Status book  : not updated ({type(exc).__name__}: {exc})")
        return
    if not path:
        return
    print(f"Status book  : {path}")
    try:
        print(f"Result book  : {result_book.write_for_run(profile, run_id)}")
    except Exception as exc:  # noqa: BLE001
        print(f"Result book  : not written ({type(exc).__name__}: {exc})")


def cmd_status(args: argparse.Namespace) -> int:
    from bat.report import status_book

    path = status_book.book_path()
    if args.action == "sync":
        added = status_book.sync_catalog()
        print(f"{path.name}: added {', '.join(added)}" if added else f"{path.name} already lists every case")
        return 0
    if args.action == "rebuild":
        print(f"stage columns refilled from saved runs: {status_book.rebuild_stage_columns()}")
        return 0
    if args.action == "result":
        from bat.report import result_book

        run_id = result_book.latest_run_id(args.profile)
        if not run_id:
            print(f"No saved run for {args.profile}")
            return 1
        print(result_book.write_for_run(args.profile, run_id))
        return 0
    row = next((r for r in status_book.read_rows(path) if r["case_id"] == args.case_id), None)
    print(row or f"{args.case_id} not in {path.name}")
    return 0 if row else 1


# 0~5는 pytest 것이다. 6 = 실패는 없지만 확인하지 못한 시나리오가 있다.
EXIT_UNVERIFIED = 6
# 7 = 실행 안 함: 단말의 트래픽이 테스트 대상 워크스페이스에 닿지 않았다.
EXIT_PREFLIGHT = 7


def _preflight_passes(profile: str, run_id: str) -> bool:
    """bat.preflight를 돌리고, 스위트를 돌릴 만한지 분명히 알린다."""
    from bat import preflight

    results = preflight.check(build_run_context(profile_name=profile), run_id)
    for r in results:
        print(f"Preflight    : {'OK  ' if r.ok else 'FAIL'} {r.endpoint} -> {r.workspace}: {r.detail}")
    failed = [r for r in results if not r.ok]
    if failed and all(r.detail.startswith("connected, but") for r in failed):
        print(
            "\nNot running: the endpoint reaches the workspace, but an existing policy takes "
            "the test host first, so cases on that host would be judged against it.\n"
            "Disable that policy (it is not a BAT resource), then run again. "
            "--skip-preflight runs anyway."
        )
    elif failed:
        print(
            "\nNot running: traffic from "
            + ", ".join(f"{r.endpoint} did not show up in {r.workspace}" for r in failed)
            + ".\nCheck that the connector is up and signed into that workspace (a connector "
            "on another workspace tunnels fine but is evaluated by that workspace's policies), "
            "then run again. --skip-preflight runs anyway."
        )
    return not failed


def bat_exit_code(pytest_code: int, run_id: str) -> int:
    """실행의 BAT 판정을 출력하고, 그것으로 종료 코드를 정한다.

    pytest만으로는 시나리오가 전부 UNVERIFIED인 실행도 0으로 끝난다. diagnostic
    케이스는 원래 UNVERIFIED라서 종료 코드를 바꾸지 않는다.
    """
    from collections import Counter

    from bat.report.collector import load_cases
    from bat.settings import REPORTS_DIR
    from bat.verdict import counts_against_run

    cases = [case for run_dir in REPORTS_DIR.glob(f"*/{run_id}") for case in load_cases(run_dir)]
    if not cases:
        return pytest_code

    totals = Counter(case["status"] for case in cases)
    blocking = [case for case in cases if counts_against_run(case)]
    diagnostic = totals.get("UNVERIFIED", 0) - len(blocking)
    print(
        f"\nBAT verdict  : PASS {totals.get('PASS', 0)} / FAIL {totals.get('FAIL', 0)} / "
        f"UNVERIFIED {totals.get('UNVERIFIED', 0)} "
        f"({len(blocking)} scenario, {diagnostic} diagnostic) / "
        f"SKIP {totals.get('SKIP', 0)} / ERROR {totals.get('ERROR', 0)}"
    )
    for case in blocking:
        print(f"  UNVERIFIED {case['case_id']} - {case.get('verdict_reason') or '-'}")

    if pytest_code != 0:
        return pytest_code
    if totals.get("FAIL") or totals.get("ERROR"):
        return 1
    if blocking:
        return EXIT_UNVERIFIED
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "run":
        return cmd_run(args)
    if args.command == "lanes":
        return cmd_lanes(args.profile)
    if args.command == "doctor":
        return cmd_doctor(args.profile)
    if args.command == "schema":
        return cmd_schema(args)
    if args.command == "sweep":
        return cmd_sweep(args)
    if args.command == "inspect":
        return cmd_inspect(args)
    if args.command == "probe":
        return cmd_probe(args)
    if args.command == "login":
        return cmd_login(args)
    if args.command == "diagnose-user":
        return cmd_diagnose_user(args)
    if args.command == "traffic":
        return cmd_traffic(args)
    if args.command == "status":
        return cmd_status(args)
    if args.command == "progress":
        return cmd_progress()
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
