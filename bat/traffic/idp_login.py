"""테스트 IdP 계정으로 SSE 로그인 화면의 IdP 버튼을 눌러 로그인하는 브라우저 동작.

자격증명은 모든 스테이지가 같이 쓰는 `.env.idp`의 BAT_IDP_*에서 읽는다. MFA는 TOTP만 다룬다
(푸시 승인은 사람이 눌러야 한다). TOTP 코드는 RFC 6238(SHA-1, 30초, 6자리)로 직접 계산한다.
아이디·비밀번호·코드·쿠키 값은 기록에 남기지 않는다.

Okta(Identity Engine) 화면은 아이디 → 인증 수단 선택 → 코드 → 비밀번호 순서로 나올 수 있고
순서는 조직 정책마다 다르다. 그래서 순서를 가정하지 않고, 화면에 보이는 입력란을 보고 채운다.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import struct
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

IDP_ENV = {
    "provider": "BAT_IDP_PROVIDER",
    "issuer": "BAT_IDP_ISSUER",
    "client_id": "BAT_IDP_CLIENT_ID",
    "client_secret": "BAT_IDP_CLIENT_SECRET",
    "user": "BAT_IDP_USER",
    "password": "BAT_IDP_PASSWORD",
}
TOTP_ENV = "BAT_IDP_TOTP_SECRET"

# 로그인 흐름 중에 지나가는 콘솔 경로. 여기 머물러 있으면 아직 로그인이 끝나지 않은 것이다.
_CONSOLE_TRANSIT = ("/auth", "/callback", "/workspace", "/login")


@dataclass
class IdpCredentials:
    provider: str
    issuer: str
    client_id: str
    client_secret: str
    user: str
    password: str
    totp_secret: str = ""

    @classmethod
    def from_env(cls) -> tuple["IdpCredentials | None", list[str]]:
        """(자격증명, 빠진 변수 이름). 하나라도 빠지면 자격증명은 None."""
        values = {key: (os.environ.get(name) or "").strip() for key, name in IDP_ENV.items()}
        missing = [IDP_ENV[key] for key, value in values.items() if not value]
        if missing:
            return None, missing
        values["issuer"] = values["issuer"].rstrip("/")
        values["provider"] = values["provider"].upper()
        return cls(**values, totp_secret=(os.environ.get(TOTP_ENV) or "").strip()), []


def totp_code(secret: str, at: float | None = None, *, step_sec: int = 30, digits: int = 6) -> str:
    """base32 시크릿의 TOTP 코드(RFC 6238, HMAC-SHA1)."""
    clean = secret.replace(" ", "").upper()
    key = base64.b32decode(clean + "=" * (-len(clean) % 8))
    counter = int((time.time() if at is None else at) // step_sec)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 10 ** digits:0{digits}d}"


class TotpSource:
    """같은 30초 구간의 코드를 두 번 내지 않는다(IdP가 재사용을 거부한다). 필요하면 다음 구간까지 기다린다."""

    _last_window: int | None = None

    def __init__(self, secret: str, *, step_sec: int = 30) -> None:
        self.secret = secret
        self.step_sec = step_sec

    def next_code(self) -> str:
        while int(time.time() // self.step_sec) == TotpSource._last_window:
            time.sleep(1)
        now = time.time()
        TotpSource._last_window = int(now // self.step_sec)
        return totp_code(self.secret, now, step_sec=self.step_sec)


def check_idp_client(creds: IdpCredentials, *, verify: bool = True, timeout_sec: float = 15.0) -> tuple[str, str]:
    """브라우저 로그인 전에 IdP 쪽 설정을 확인한다. (실패 종류, 설명), 문제가 없으면 ("", "").

    - "issuer": 발급자 주소에서 OIDC 설정(/.well-known/openid-configuration)을 받을 수 없다
    - "client": 토큰 엔드포인트가 client_id/secret을 거부한다(401, invalid_client)

    client 확인은 client_credentials 요청으로 한다. 자격증명이 맞으면 IdP는 그 grant를 허용하지 않는다는
    오류(Okta: 400 unauthorized_client)를 주고, 틀리면 401 invalid_client를 준다(2026-11-20 Okta 실측).
    토큰을 받는 것이 목적이 아니라 자격증명이 거부되는지만 본다.
    """
    url = f"{creds.issuer}/.well-known/openid-configuration"
    try:
        response = httpx.get(url, verify=verify, timeout=timeout_sec, follow_redirects=True)
        token_endpoint = response.json().get("token_endpoint") if response.status_code == 200 else None
    except (httpx.HTTPError, ValueError) as exc:
        return "issuer", f"{url}: {type(exc).__name__}: {exc}"
    if not token_endpoint:
        return "issuer", f"{url} answered HTTP {response.status_code} without an OIDC token_endpoint"
    try:
        response = httpx.post(
            token_endpoint, data={"grant_type": "client_credentials", "scope": "openid"},
            auth=(creds.client_id, creds.client_secret), verify=verify, timeout=timeout_sec,
        )
    except httpx.HTTPError as exc:
        return "issuer", f"{token_endpoint}: {type(exc).__name__}: {exc}"
    try:
        error = response.json()
    except ValueError:
        error = {}
    if response.status_code == 401 or error.get("error") == "invalid_client":
        reason = error.get("error_description") or error.get("error") or f"HTTP {response.status_code}"
        return "client", f"{token_endpoint} rejected client_id {creds.client_id}: {reason}"
    return "", ""


# sign_in이 멈춘 이유. 앞의 둘은 IdP 쪽 설정 문제, 뒤의 둘은 SSE가 실패한 것이다.
IDP_ACCOUNT = "idp_account"      # IdP 로그인 화면이 계정(아이디·비밀번호·코드)을 거부
IDP_REQUEST = "idp_request"      # IdP가 인증 요청 자체를 거부(콜백 주소 미등록, client_id 등)
SSE_START = "sse_start"          # IdP 버튼을 눌렀는데 SSE가 IdP로 보내지 못함
SSE_CALLBACK = "sse_callback"    # IdP 로그인 뒤 SSE가 로그인을 마치지 못하고 로그인 화면으로 돌아옴
TIMED_OUT = "timed_out"


@dataclass
class IdpSignIn:
    """로그인 시도 결과. steps는 지나간 화면과 한 동작(값 없이). failure는 위의 종류 중 하나."""

    landed: bool = False
    final_url: str = ""
    failure: str = ""
    detail: str = ""
    steps: list[str] = field(default_factory=list)


def open_login_page(page, console_url: str, workspace: str, *, timeout_ms: int = 15_000) -> None:
    """브라우저처럼 워크스페이스를 입력해 그 워크스페이스의 로그인 화면(/auth/login)을 연다."""
    base = console_url.rstrip("/")
    page.goto(f"{base}/workspace")
    page.wait_for_load_state("networkidle")
    page.locator("input#workspace, input[name='workspace']").first.fill(workspace)
    _submit(page)
    page.wait_for_url("**/auth/login**", timeout=timeout_ms)
    page.wait_for_load_state("networkidle")


def idp_button(page, idp_index: str):
    """로그인 화면에서 그 SSO id(idpIndex)의 IdP 버튼 폼. 없으면 None."""
    form = page.locator(f'form.idp-auth-form:has(input[name="idpIndex"][value="{idp_index}"])')
    return form.first if form.count() else None


def sign_in(page, form, creds: IdpCredentials, console_url: str, *, timeout_sec: float = 120.0) -> IdpSignIn:
    """IdP 버튼을 눌러 IdP 화면을 채우고, 콘솔로 돌아와 로그인된 화면에 닿을 때까지 따라간다."""
    console_host = urlparse(console_url).hostname or ""
    idp_host = urlparse(creds.issuer).hostname or ""
    codes = TotpSource(creds.totp_secret) if creds.totp_secret else None
    result = IdpSignIn()

    button = form.locator("button, input[type=submit]")
    if button.count():
        button.first.click()
    else:
        form.evaluate("f => f.submit()")

    last = ""
    reached_idp = False
    stuck = 0
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            page.wait_for_load_state("domcontentloaded", timeout=10_000)
        except Exception:  # noqa: BLE001 - 화면 전환 중에는 기다림이 끊길 수 있다
            pass
        time.sleep(1.5)
        url = urlparse(page.url)
        seen = f"{url.netloc}{url.path}"
        if seen != last:
            result.steps.append(seen)
            last, stuck = seen, 0
        else:
            stuck += 1
        if url.hostname == console_host:
            if not url.path.startswith(_CONSOLE_TRANSIT):
                try:
                    page.wait_for_load_state("networkidle", timeout=15_000)
                except Exception:  # noqa: BLE001
                    pass
                result.landed = True
                break
            # 같은 화면에 두 번 넘게 머물면 그 화면이 결과다(전환 중인 화면은 곧 바뀐다).
            if stuck >= 2 and url.path.startswith("/auth/sso-login"):
                result.failure, result.detail = SSE_START, _page_text(page)
                break
            if stuck >= 2 and reached_idp and url.path.startswith("/auth/login"):
                result.failure, result.detail = SSE_CALLBACK, _dialog_text(page)
                break
            continue
        if url.hostname != idp_host:
            continue
        reached_idp = True

        error = _visible_text(page, ".o-form-has-errors .o-form-error-container, .okta-form-infobox-error")
        if error:
            result.failure, result.detail = IDP_ACCOUNT, error[:200]
            break
        if re.search(r"bad request|error", page.title(), re.I):
            result.failure, result.detail = IDP_REQUEST, _idp_error_page(page)
            break
        identifier = _visible(page, 'input[name="identifier"], #okta-signin-username')
        password = _visible(page, 'input[name="credentials.passcode"][type="password"], #okta-signin-password')
        code = _visible(page, 'input[name="credentials.passcode"]:not([type="password"]), input[name="answer"]')
        if identifier is not None and not identifier.input_value():
            identifier.fill(creds.user)
            if password is not None:
                password.fill(creds.password)
            result.steps.append("filled identifier" + (" and password" if password is not None else ""))
            _submit(page)
        elif password is not None and not password.input_value():
            password.fill(creds.password)
            result.steps.append("filled password")
            _submit(page)
        elif code is not None and not code.input_value():
            if codes is None:
                result.failure = IDP_ACCOUNT
                result.detail = f"the IdP asks for a one-time code but {TOTP_ENV} is not set in .env.idp"
                break
            code.fill(codes.next_code())
            result.steps.append("filled TOTP code")
            _submit(page)
        elif (choice := _visible(page, '[data-se="google_otp"] a, [data-se="google_otp"] button')) is not None:
            choice.click()
            result.steps.append("chose Google Authenticator")

    if not result.landed and not result.failure:
        result.failure, result.detail = TIMED_OUT, f"still at {last} after {timeout_sec:.0f}s"
    result.final_url = page.url.split("?", 1)[0]
    return result


def _page_text(page, limit: int = 200) -> str:
    try:
        return " ".join(page.inner_text("body").split())[:limit]
    except Exception:  # noqa: BLE001
        return ""


def _dialog_text(page) -> str:
    """로그인 화면에 뜬 알림 창의 문구. 못 찾으면 본문 끝부분(알림은 본문 뒤에 붙는다)."""
    text = _visible_text(page, "[role=dialog], [role=alertdialog], .modal, .swal2-popup, .alert")
    if text:
        return text[:200]
    body = _page_text(page, 2000)
    return body[-200:]


def _idp_error_page(page) -> str:
    """IdP 오류 화면의 이유. Okta는 'Error: ...'에 이유를 쓰고, client_id가 틀리면 이유 없이 400만 보여 준다."""
    body = _page_text(page, 1500)
    match = re.search(r"Error: (.+?)(?:: https?://| Go to Homepage|$)", body)
    reason = match.group(1).strip() if match else ""
    return f"{page.title()}: {reason}" if reason else f"{page.title()} without a reason (an unknown client_id looks like this)"


def _visible(page, selector: str):
    locator = page.locator(selector)
    try:
        return locator.first if locator.count() and locator.first.is_visible() else None
    except Exception:  # noqa: BLE001 - 화면이 바뀌는 중이면 없는 것으로 본다
        return None


def _visible_text(page, selector: str) -> str:
    element = _visible(page, selector)
    try:
        return " ".join(element.inner_text().split()) if element is not None else ""
    except Exception:  # noqa: BLE001
        return ""


def _submit(page) -> None:
    for selector in ('input[type="submit"]', 'button[type="submit"]', "#okta-signin-submit"):
        button = _visible(page, selector)
        if button is not None:
            button.click()
            return
    page.keyboard.press("Enter")
