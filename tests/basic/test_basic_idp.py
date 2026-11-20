"""IdP(SSO) 로그인 케이스: 콘솔 설정 > 로그인 설정 > SSO에 등록한 IdP가 실제 로그인에 쓰이는지 본다.

SSO 설정을 하나 만들면 워크스페이스 로그인 화면(Auth Server /auth/login)에 그 IdP 버튼
(form.idp-auth-form, hidden idpIndex = SSO id)이 생기고, 그 버튼(POST /auth/sso-login)은 등록한
발급자(issuer)의 OIDC 인증 주소로 302를 돌려준다.

BAT-BASIC-010은 공개 발급자(Google)와 가짜 client_id로 로그인 시작까지만 본다(IdP 계정 불필요).
BAT-BASIC-011은 `.env.idp`의 테스트 IdP 앱·계정으로 실제로 로그인해 콘솔에 들어가는지, 인증
로그에 SSO 로그인 행이 남는지 본다.

SSO가 있는 동안은 그 워크스페이스의 모든 사용자 로그인 화면에 버튼이 하나 더 보인다.
"""
from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

import pytest

from bat.clients.auth_server import console_env, idp_buttons, start_idp_login
from bat.events.poller import PollTimeout, poll_until
from bat.fixtures.graphql_policies import SsoFactory
from bat.fixtures.naming import resource_name
from bat.fixtures.policies import CleanupWarning
from bat.models import Kind, Step
from bat.traffic.idp_login import (
    IDP_ACCOUNT,
    IDP_REQUEST,
    SSE_CALLBACK,
    SSE_START,
    TIMED_OUT,
    IdpCredentials,
    IdpSignIn,
    check_idp_client,
    idp_button,
    open_login_page,
    sign_in,
)
from tests.support import cleanup_failed, environment_error, pass_case

pytestmark = [
    pytest.mark.product("basic"),
    pytest.mark.lane("b"),
    pytest.mark.xdist_group("lane-b"),
]

IDP_PROVIDER = "GOOGLE"
IDP_ISSUER = "https://accounts.google.com"
IDP_AUTHORIZE = ("accounts.google.com", "/o/oauth2/v2/auth")
SSO_LOGIN_RESULT = "AUTH_SUCCESS_SSO"


@pytest.fixture
def ssos(console) -> SsoFactory:
    return SsoFactory(console)


def _workspace(lane) -> str:
    return str(getattr(lane.workspace, "name", lane.workspace))


def _wait_buttons(run_context, workspace: str, want, timeout_sec: float) -> list[dict]:
    """want(버튼 목록)이 참이 될 때까지 로그인 화면을 다시 읽고, 마지막 목록을 돌려준다."""
    last: dict = {"value": []}

    def probe():
        last["value"] = idp_buttons(run_context.profile, workspace)
        return last["value"] if want(last["value"]) else None

    try:
        return poll_until(probe, timeout_sec=timeout_sec, description="login page IdP buttons", initial_interval=2.0)
    except PollTimeout:
        return last["value"]


def check_authorize_redirect(status: int, location: str, client_id: str) -> list[str]:
    """/auth/sso-login 응답이 그 발급자의 OIDC 인증 요청인지. 어긋난 점의 목록(비면 통과)."""
    problems = []
    if status != 302:
        problems.append(f"HTTP {status} instead of 302")
    url = urlparse(location or "")
    if (url.netloc, url.path) != IDP_AUTHORIZE:
        problems.append(f"redirects to {url.netloc}{url.path} instead of {''.join(IDP_AUTHORIZE)}")
    query = parse_qs(url.query)
    if query.get("client_id") != [client_id]:
        problems.append(f"client_id {query.get('client_id')} instead of {client_id}")
    if query.get("response_type") != ["code"]:
        problems.append(f"response_type {query.get('response_type')} instead of code")
    if "openid" not in " ".join(query.get("scope") or []).split():
        problems.append(f"scope {query.get('scope')} has no openid")
    for key in ("state", "nonce"):
        if not (query.get(key) or [""])[0]:
            problems.append(f"no {key}")
    return problems


def is_sso_login_of(row: dict, login_id: str, since_utc: str) -> bool:
    """인증 로그 행이 그 계정의 SSO 로그인 성공이고 since_utc(같은 형식의 UTC 문자열) 이후인지."""
    return (
        str(row.get("auth_result") or "") == SSO_LOGIN_RESULT
        and str(row.get("login_id") or "").lower() == login_id.lower()
        and str(row.get("time") or "") >= since_utc
    )


def sign_in_failure(provider: str, outcome: IdpSignIn, cookies: list[str], path: str) -> str:
    """IdP 설정이 맞는데(앞에서 확인) 콘솔에 들어가지 못한 이유. SSE 쪽 실패라 FAIL로 남는다."""
    if outcome.failure == SSE_START:
        return f"[SSE] pressing the {provider} button did not send the browser to the IdP: {outcome.detail} ({path})"
    if outcome.failure == SSE_CALLBACK:
        return (
            f"[SSE] the {provider} sign-in finished but SSE returned to its login page: {outcome.detail!r}. "
            f"The IdP app settings were accepted; if the IdP account is not a user of this workspace "
            f"this is expected ({path})"
        )
    if outcome.failure == TIMED_OUT:
        return f"[timeout] the {provider} sign-in did not finish: {outcome.detail} ({path})"
    return f"the {provider} sign-in reached {outcome.final_url} without a console session cookie ({cookies}; {path})"


@pytest.mark.case("BAT-BASIC-010")
@pytest.mark.verifies(Step.USER_RESULT)
@pytest.mark.priority("P2")
def test_sso_provider_appears_on_the_login_page_and_starts_oidc(case, run_context, lane, ssos):
    """IdP(SSO)를 등록하면 로그인 화면에 그 IdP 버튼이 생기고 누르면 그 발급자의 OIDC 인증 요청으로 넘어가며, 지우면 버튼이 사라진다."""
    workspace = _workspace(lane)
    name = resource_name(case.case_id, run_context.run_id)
    client_id = f"{name}-client"
    budget = run_context.policy_propagation_timeout_sec

    try:
        with ssos.temporary(name, provider=IDP_PROVIDER, domain=IDP_ISSUER, client_id=client_id) as sso:
            case.policy_ids.append(sso.policy_id)
            case.record(
                Step.SETUP, ok=True, kind=Kind.EVIDENCE,
                detail=f"SSO {name} (id={sso.policy_id}): {IDP_PROVIDER}/OIDC, issuer {IDP_ISSUER}, client_id {client_id}",
            )

            def mine(buttons: list[dict]) -> dict | None:
                return next((b for b in buttons if b.get("idpIndex") == sso.policy_id), None)

            buttons = _wait_buttons(run_context, workspace, mine, budget)
            button = mine(buttons) or {}
            shown = button.get("idpProvider") == IDP_PROVIDER and button.get("idpProtocol") == "OIDC"
            case.record(
                Step.USER_RESULT, ok=shown, kind=Kind.ASSERTION,
                detail=f"login page IdP buttons: {buttons}",
                expected=f"a button with idpIndex={sso.policy_id}, {IDP_PROVIDER}, OIDC",
                actual=button or buttons,
            )
            assert shown, f"the login page of {workspace} shows no {IDP_PROVIDER} button for SSO id {sso.policy_id}: {buttons}"

            status, location, body = start_idp_login(run_context.profile, workspace, sso.policy_id)
            problems = check_authorize_redirect(status, location, client_id)
            # state·nonce는 일회용 값이라 기록에서 뺀다.
            shown_location = location.split("?", 1)[0]
            case.record(
                Step.USER_RESULT, ok=not problems, kind=Kind.ASSERTION,
                detail=f"/auth/sso-login -> HTTP {status} {shown_location}"
                + (f"; {'; '.join(problems)}; body {body[:150]!r}" if problems else ""),
                expected=f"302 to https://{''.join(IDP_AUTHORIZE)} with client_id {client_id}, "
                "response_type code, scope openid, state, nonce",
                actual=f"HTTP {status} {shown_location}",
            )
            assert not problems, f"the {IDP_PROVIDER} button did not start an OIDC login: {'; '.join(problems)}"
    except CleanupWarning as warning:
        cleanup_failed(case, warning)
        return

    # 버튼이 사라지는 것도 이 시나리오의 일부라 SSO를 지운 뒤에 본다.
    buttons = _wait_buttons(run_context, workspace, lambda b: not any(x.get("idpIndex") == sso.policy_id for x in b), budget)
    gone = not any(b.get("idpIndex") == sso.policy_id for b in buttons)
    case.record(
        Step.USER_RESULT, ok=gone, kind=Kind.ASSERTION,
        detail=f"login page IdP buttons after delete: {buttons}",
        expected=f"no button with idpIndex={sso.policy_id} within {budget}s of deleting the SSO",
    )
    assert gone, f"the login page still shows the button of deleted SSO id {sso.policy_id}"
    pass_case(case)


@pytest.mark.case("BAT-BASIC-011")
@pytest.mark.verifies(Step.USER_RESULT, Step.EVENT)
@pytest.mark.priority("P1")
def test_idp_user_signs_in_through_the_sso_button(case, run_context, lane, ssos, browser_session, auth_log):
    """테스트 IdP 앱을 SSO로 등록하면 그 IdP 계정이 로그인 화면의 IdP 버튼으로 로그인해 콘솔에 들어가고, 인증 로그에 SSO 로그인 성공이 남는다."""
    creds, missing = IdpCredentials.from_env()
    if creds is None:
        environment_error(f"[IdP not configured] .env.idp has no value for {', '.join(missing)}")
    redirect_uri = run_context.profile.idp_redirect_uri
    if not redirect_uri:
        try:
            redirect_uri = console_env(run_context.profile, ("REDIRECT_URI",))["REDIRECT_URI"]
        except LookupError as exc:
            environment_error(
                f"[IdP not configured] no idp_redirect_uri in this stage's environments.yaml block "
                f"and no REDIRECT_URI in the console env.js: {exc}"
            )
    # IdP 쪽 설정은 브라우저 전에 확인한다. 틀린 client_secret은 IdP 로그인이 끝난 뒤 SSE 로그인 화면의
    # 일반 오류로만 보여서 SSE 실패와 구분되지 않는다.
    problem, detail = check_idp_client(creds, verify=run_context.profile.verify_tls)
    if problem == "issuer":
        environment_error(f"[IdP issuer] BAT_IDP_ISSUER does not serve OIDC settings: {detail}")
    if problem == "client":
        environment_error(f"[IdP app] BAT_IDP_CLIENT_ID/BAT_IDP_CLIENT_SECRET are not accepted by the IdP: {detail}")

    workspace = _workspace(lane)
    name = resource_name(case.case_id, run_context.run_id)
    budget = run_context.policy_propagation_timeout_sec
    issuer_host = urlparse(creds.issuer).hostname
    case.record(
        Step.SETUP, ok=True, kind=Kind.EVIDENCE,
        detail=f"IdP {creds.provider} issuer {creds.issuer}, redirect_uri {redirect_uri}, "
        f"TOTP {'set' if creds.totp_secret else 'not set'}",
    )

    try:
        with ssos.temporary(
            name, provider=creds.provider, domain=creds.issuer, client_id=creds.client_id,
            client_secret=creds.client_secret, redirect_uri=redirect_uri,
        ) as sso:
            case.policy_ids.append(sso.policy_id)
            case.record(Step.SETUP, ok=True, kind=Kind.EVIDENCE, detail=f"SSO {name} (id={sso.policy_id})")
            _wait_buttons(run_context, workspace, lambda b: any(x.get("idpIndex") == sso.policy_id for x in b), budget)

            started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            with browser_session.fresh_page() as page:
                open_login_page(page, run_context.profile.console_url, workspace)
                form = idp_button(page, sso.policy_id)
                case.record(
                    Step.USER_RESULT, ok=form is not None, kind=Kind.ASSERTION,
                    detail=f"login page of {workspace} in the browser",
                    expected=f"an IdP button with idpIndex={sso.policy_id}",
                )
                assert form is not None, f"the browser login page shows no IdP button for SSO id {sso.policy_id}"

                outcome = sign_in(page, form, creds, run_context.profile.console_url)
                path = " -> ".join(outcome.steps)
                # IdP 쪽 설정·계정 문제는 SSE를 판정할 근거가 아니다.
                if outcome.failure == IDP_REQUEST:
                    environment_error(
                        f"[IdP app] the IdP rejected the login request: {outcome.detail}. Register {redirect_uri} "
                        f"as a sign-in redirect URI of the IdP app and check BAT_IDP_CLIENT_ID ({path})"
                    )
                if outcome.failure == IDP_ACCOUNT:
                    environment_error(
                        f"[IdP account] the IdP refused the test account: {outcome.detail}. Check BAT_IDP_USER/"
                        f"BAT_IDP_PASSWORD/BAT_IDP_TOTP_SECRET and that the account is assigned to the app ({path})"
                    )
                cookies = sorted(
                    c["name"] for c in page.context.cookies()
                    if c.get("value", "").count(".") == 2 and urlparse(run_context.profile.console_url).hostname.endswith(
                        c["domain"].lstrip(".")
                    )
                )
                landed = outcome.landed and bool(cookies)
                case.record(
                    Step.USER_RESULT, ok=landed, kind=Kind.ASSERTION,
                    detail=f"{path}; final {outcome.final_url}; console session cookies {cookies}",
                    expected=f"after signing in at {issuer_host}, the browser lands on a signed-in console page "
                    "with a console session cookie",
                    actual=outcome.final_url,
                )
                assert landed, sign_in_failure(creds.provider, outcome, cookies, path)

            try:
                event = auth_log.wait_for(
                    lambda e: is_sso_login_of(e.raw, creds.user, started),
                    timeout_sec=run_context.event_poll_timeout_sec, description="SSO login auth_log row",
                    lookback_min=15,
                )
            except PollTimeout:
                event = None
            if event is not None:
                case.event_ids.append(event.event_id)
            row = event.raw if event is not None else {}
            case.record(
                Step.EVENT, ok=event is not None, kind=Kind.ASSERTION,
                detail=f"auth_log row {row.get('id')}: {row.get('auth_result')} {row.get('user_name')} at {row.get('time')}"
                if row else f"no {SSO_LOGIN_RESULT} row for the test account since {started}",
                expected=f"an auth_log row {SSO_LOGIN_RESULT} for the test IdP account after {started}",
            )
            assert event is not None, f"no {SSO_LOGIN_RESULT} auth_log row for the test IdP account since {started}"
            pass_case(case)
    except CleanupWarning as warning:
        cleanup_failed(case, warning)
