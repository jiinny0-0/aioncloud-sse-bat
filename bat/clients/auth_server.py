"""SIA Auth Server(콘솔 웹 로그인 화면)로 콘솔 세션 쿠키를 받는 임시 로그인.

GraphQL `authorization.session.issuance`가 서버 쪽 사용자 검증 오류로 실패하는 스테이지에서
쓴다(real, 2026-11 "Database Error"). 브라우저 로그인과 같은 순서를 밟는다.

1. GET  <console>/workspace           CSRF 쿠키(_csrf)와 세션 쿠키를 받는다
2. POST <console>/workspace           form workspace=<이름>
3. GET  <console>/auth/publickey      RSA 공개키(PEM)
4. POST <console>/auth/login.prc      JSON {encryptpw, lang}. encryptpw는
                                      "<아이디>#_<비밀번호>"를 RSA-OAEP(SHA-256)로 암호화한 base64
5. 응답의 Set-Cookie 중 JWT 모양(sia_<stage>_console)이 콘솔 세션이다

암호화는 표준 라이브러리로 한다(새 의존성을 피하려고).
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
import re
from typing import Any

import httpx

from bat.clients.errors import AuthError
from bat.settings import Profile

log = logging.getLogger(__name__)


# -- RSA-OAEP(SHA-256, MGF1-SHA-256, 빈 label) -------------------------------


def _der_read(data: bytes, pos: int) -> tuple[int, bytes, int]:
    """DER TLV 하나를 읽어 (tag, value, 다음 위치)를 돌려준다."""
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    return tag, data[pos:pos + length], pos + length


def _rsa_public_numbers(pem: str) -> tuple[int, int]:
    """SubjectPublicKeyInfo PEM에서 (n, e)."""
    body = "".join(line for line in pem.strip().splitlines() if not line.startswith("-----"))
    der = base64.b64decode(body)
    _, spki, _ = _der_read(der, 0)                  # SEQUENCE
    _, _, pos = _der_read(spki, 0)                  # AlgorithmIdentifier
    tag, bits, _ = _der_read(spki, pos)             # BIT STRING
    if tag != 0x03:
        raise AuthError("Auth server public key is not an RSA SubjectPublicKeyInfo")
    _, rsa_key, _ = _der_read(bits[1:], 0)          # 첫 바이트는 남는 비트 수
    _, n_bytes, pos = _der_read(rsa_key, 0)
    _, e_bytes, _ = _der_read(rsa_key, pos)
    return int.from_bytes(n_bytes, "big"), int.from_bytes(e_bytes, "big")


def _mgf1(seed: bytes, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def rsa_oaep_encrypt(pem: str, message: bytes) -> bytes:
    """WebCrypto RSA-OAEP(hash SHA-256)과 같은 암호문을 만든다."""
    n, e = _rsa_public_numbers(pem)
    k = (n.bit_length() + 7) // 8
    h_len = hashlib.sha256().digest_size
    if len(message) > k - 2 * h_len - 2:
        raise AuthError("Login id and password are too long for the auth server key")
    l_hash = hashlib.sha256(b"").digest()
    db = l_hash + b"\x00" * (k - len(message) - 2 * h_len - 2) + b"\x01" + message
    seed = os.urandom(h_len)
    masked_db = bytes(a ^ b for a, b in zip(db, _mgf1(seed, k - h_len - 1)))
    masked_seed = bytes(a ^ b for a, b in zip(seed, _mgf1(masked_db, h_len)))
    encoded = b"\x00" + masked_seed + masked_db
    return pow(int.from_bytes(encoded, "big"), e, n).to_bytes(k, "big")


# -- 로그인 흐름 ----------------------------------------------------------------


def _jwt_cookie(cookies: httpx.Cookies) -> str:
    jwts = [(c.name, c.value) for c in cookies.jar if c.value and c.value.count(".") == 2]
    jwts.sort(key=lambda item: not item[0].endswith("_console"))
    return jwts[0][1] if jwts else ""


def login_via_auth_server(
    profile: Profile, workspace: str, login_id: str, password: str, *, timeout_sec: float = 30.0
) -> tuple[str, dict[str, Any]]:
    """Auth Server로 로그인해 (세션 JWT, 응답 요약)을 돌려준다. 비밀번호는 평문을 받는다."""
    with httpx.Client(verify=profile.verify_tls, follow_redirects=True, timeout=timeout_sec) as client:
        return _auth_login(client, profile.console_url.rstrip("/"), workspace, login_id, password)


def _auth_login(
    client: httpx.Client, base: str, workspace: str, login_id: str, password: str
) -> tuple[str, dict[str, Any]]:
    """열린 클라이언트로 로그인한다. 세션 쿠키는 그 클라이언트에 남는다."""
    client.get(f"{base}/workspace")
    csrf = {"X-CSRF-Token": client.cookies.get("_csrf") or ""}

    response = client.post(f"{base}/workspace", data={"workspace": workspace}, headers=csrf)
    step = _json(response, "workspace")
    if not step.get("success"):
        raise AuthError(f"Auth server rejected workspace {workspace}: {step.get('message')}")
    if step.get("use_sub_org"):
        raise AuthError(f"Workspace {workspace} needs a sub-organization, which this login does not send")
    # 브라우저처럼 로그인 화면을 연다. 건너뛰면 login.prc가 error-invalid-session으로 답한다.
    client.get(f"{base}{step.get('redirect_url') or '/auth/login'}")

    key = _json(client.get(f"{base}/auth/publickey"), "publickey").get("public_key") or ""
    if not key:
        raise AuthError("Auth server returned no public key")
    secret = rsa_oaep_encrypt(key, f"{login_id}#_{password}".encode("utf-8"))
    payload = {"email": "", "passwd": "", "encryptpw": base64.b64encode(secret).decode("ascii"), "lang": "en"}
    csrf = {"X-CSRF-Token": client.cookies.get("_csrf") or ""}
    result = _json(client.post(f"{base}/auth/login.prc", json=payload, headers=csrf), "login")

    summary = {
        key: result.get(key)
        for key in ("success", "message", "workspace", "cookie_session", "session_expire_at", "redirect_url")
        if key in result
    }
    if not result.get("success"):
        raise AuthError(f"Auth server login failed: {result.get('message') or result.get('redirect_url')}")
    token = _jwt_cookie(client.cookies)
    if not token:
        raise AuthError(
            f"Auth server login succeeded but set no session cookie "
            f"(cookies: {sorted(client.cookies.keys())}, response keys: {sorted(result)})"
        )
    return token, summary


# -- 로그인 화면의 IdP(SSO) 버튼 -------------------------------------------------

_IDP_FORM_RE = re.compile(r"<form[^>]*idp-auth-form.*?</form>", re.S | re.I)
_HIDDEN_RE = re.compile(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', re.I)


def parse_idp_forms(html: str) -> list[dict[str, str]]:
    """로그인 화면 HTML의 IdP 버튼(form.idp-auth-form)마다 hidden 필드({idpIndex, idpProvider,
    idpProtocol}). idpIndex는 그 SSO 설정의 id다."""
    return [dict(_HIDDEN_RE.findall(form)) for form in _IDP_FORM_RE.findall(html or "")]


def _login_page(client: httpx.Client, base: str, workspace: str) -> str:
    """로그인 화면까지 브라우저와 같은 순서로 가서 그 HTML을 돌려준다."""
    client.get(f"{base}/workspace")
    csrf = {"X-CSRF-Token": client.cookies.get("_csrf") or ""}
    step = _json(client.post(f"{base}/workspace", data={"workspace": workspace}, headers=csrf), "workspace")
    if not step.get("success"):
        raise AuthError(f"Auth server rejected workspace {workspace}: {step.get('message')}")
    page = client.get(f"{base}{step.get('redirect_url') or '/auth/login'}", follow_redirects=True)
    if page.status_code >= 400:
        raise AuthError(f"Auth server login page answered HTTP {page.status_code}")
    return page.text


def idp_buttons(profile: Profile, workspace: str, *, timeout_sec: float = 30.0) -> list[dict[str, str]]:
    """그 워크스페이스 로그인 화면에 보이는 IdP 버튼들(parse_idp_forms)."""
    base = profile.console_url.rstrip("/")
    with httpx.Client(verify=profile.verify_tls, timeout=timeout_sec) as client:
        return parse_idp_forms(_login_page(client, base, workspace))


def start_idp_login(
    profile: Profile, workspace: str, idp_index: str, *, timeout_sec: float = 30.0
) -> tuple[int, str, str]:
    """로그인 화면에서 그 IdP 버튼을 누른 것처럼 POST /auth/sso-login을 보낸다.

    (상태 코드, Location, 본문 앞부분). 정상이면 302와 IdP 인증 주소다. 리다이렉트는 따라가지
    않는다(IdP에 가지 않는다). 버튼이 화면에 없으면 AuthError.
    """
    base = profile.console_url.rstrip("/")
    with httpx.Client(verify=profile.verify_tls, timeout=timeout_sec) as client:
        forms = parse_idp_forms(_login_page(client, base, workspace))
        fields = next((form for form in forms if form.get("idpIndex") == str(idp_index)), None)
        if fields is None:
            raise AuthError(f"No IdP button with idpIndex={idp_index} on the login page ({forms})")
        csrf = {"X-CSRF-Token": client.cookies.get("_csrf") or ""}
        response = client.post(f"{base}/auth/sso-login", data=fields, headers=csrf, follow_redirects=False)
        return response.status_code, response.headers.get("location", ""), response.text[:300]


# -- 앱 런처 ---------------------------------------------------------------------
#
# 포털 타일을 누르면 콘솔이 하는 일과 같다.
# 1. POST <console>/app-launcher/ticket  JSON {redirect_url: 서비스 주소}, Auth Server 세션 쿠키로 → {success, ticket}
# 2. POST https://<APP_LAU_SERVER>/issue form {redirect_url, ticket} → app_launcher_token 쿠키(.<APP_LAU_DOMAIN>)와
#    서비스 주소로 넘기는 meta refresh
# 3. 서비스 주소를 열면 게이트웨이 뒤 서버의 페이지가 온다(커넥터 없이). 쿠키가 없으면 403
#
# 서비스 주소는 https://<서버 도메인(없으면 IP)의 .을 --로>-<포트>-<OrgID>.<APP_LAU_DOMAIN>이다.
# OrgID는 { Account { info { id } } }, APP_LAU_*는 콘솔 SPA의 env.js에 있다.

_REFRESH_RE = re.compile(r"""http-equiv=["']?refresh["']?[^>]*url=([^"'>\s]+)""", re.I)


def launcher_url(host: str, port: str | int, org_id: str | int, app_domain: str) -> str:
    return f"https://{host.replace('.', '--')}-{port}-{org_id}.{app_domain}"


def console_env(profile: Profile, keys: tuple[str, ...], *, timeout_sec: float = 15.0) -> dict[str, str]:
    """콘솔 SPA env.js의 값들. 콘솔 호스트의 기본 포트에서 먼저 찾고, 키가 다 있는 첫 파일을 쓴다."""
    url = httpx.URL(profile.console_url)
    origins = [f"{url.scheme}://{url.host}", f"{url.scheme}://{url.netloc.decode('ascii')}"]
    seen: list[str] = []
    with httpx.Client(verify=profile.verify_tls, follow_redirects=True, timeout=timeout_sec) as client:
        for origin in dict.fromkeys(origins):
            try:
                text = client.get(f"{origin}/env.js").text
            except httpx.HTTPError as exc:
                seen.append(f"{origin}/env.js: {type(exc).__name__}")
                continue
            found = {
                key: match.group(1)
                for key in keys
                if (match := re.search(rf"{key}\W+([^'\",\s]+)", text))
            }
            if len(found) == len(keys):
                return found
            seen.append(f"{origin}/env.js: no {'/'.join(k for k in keys if k not in found)}")
    raise LookupError(f"Console env.js settings not found ({'; '.join(seen)})")


def launcher_env(profile: Profile, *, timeout_sec: float = 15.0) -> tuple[str, str]:
    """콘솔 env.js의 (APP_LAU_DOMAIN, APP_LAU_SERVER)."""
    found = console_env(profile, ("APP_LAU_DOMAIN", "APP_LAU_SERVER"), timeout_sec=timeout_sec)
    return found["APP_LAU_DOMAIN"], found["APP_LAU_SERVER"]


class AppLauncherSession:
    """Auth Server로 로그인한 앱 런처 사용자.

    같은 계정의 다른 콘솔 세션(GraphQL)은 이 로그인으로 끊긴다("Duplicate login"). 그래서
    console_token을 돌려주니 호출한 쪽이 GraphQL 클라이언트에 바꿔 끼운다.
    """

    def __init__(
        self, profile: Profile, workspace: str, login_id: str, password: str, *, timeout_sec: float = 40.0
    ) -> None:
        self.profile = profile
        self.timeout_sec = timeout_sec
        self._base = profile.console_url.rstrip("/")
        self._auth = httpx.Client(verify=profile.verify_tls, follow_redirects=True, timeout=timeout_sec)
        self._launcher: httpx.Client | None = None
        try:
            self.console_token, _ = _auth_login(self._auth, self._base, workspace, login_id, password)
        except Exception:
            self._auth.close()
            raise

    def _client(self) -> httpx.Client:
        return httpx.Client(verify=self.profile.verify_tls, follow_redirects=True, timeout=self.timeout_sec)

    def open(self, url: str, app_server: str) -> httpx.Response:
        """타일을 누른 것처럼 티켓을 받아 서비스 주소를 연다. 티켓이 거부되면 AuthError."""
        csrf = {"X-CSRF-Token": self._auth.cookies.get("_csrf") or ""}
        response = self._auth.post(f"{self._base}/app-launcher/ticket", json={"redirect_url": url}, headers=csrf)
        if response.status_code == 401:
            raise AuthError("App launcher ticket: the auth server session expired (HTTP 401)")
        try:
            body = response.json()
        except ValueError:
            body = {}
        ticket = body.get("ticket") if isinstance(body, dict) else None
        if not ticket:
            message = ((body.get("error") or {}).get("message") if isinstance(body, dict) else "") or response.text[:120]
            raise AuthError(f"App launcher ticket refused for {url}: HTTP {response.status_code} {message}")

        if self._launcher is not None:
            self._launcher.close()
        self._launcher = self._client()
        issued = self._launcher.post(f"https://{app_server}/issue", data={"redirect_url": url, "ticket": ticket})
        match = _REFRESH_RE.search(issued.text)
        return self._launcher.get(match.group(1) if match else url)

    def again(self, url: str) -> httpx.Response:
        """마지막으로 받은 런처 쿠키로 다시 연다(새 티켓 없이)."""
        if self._launcher is None:
            raise RuntimeError("open() first")
        return self._launcher.get(url)

    def without_ticket(self, url: str) -> httpx.Response:
        """런처 쿠키 없이 연다. 리다이렉트는 따라가지 않는다(접근제어가 있으면 SSE 로그인 화면으로
        보내고, 없으면 403이다)."""
        with httpx.Client(verify=self.profile.verify_tls, follow_redirects=False, timeout=self.timeout_sec) as client:
            return client.get(url)

    def close(self) -> None:
        if self._launcher is not None:
            self._launcher.close()
        self._auth.close()

    def __enter__(self) -> "AppLauncherSession":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _json(response: httpx.Response, step: str) -> dict[str, Any]:
    if response.status_code >= 400:
        raise AuthError(f"Auth server {step} step answered HTTP {response.status_code}")
    try:
        data = response.json()
    except ValueError as exc:
        raise AuthError(f"Auth server {step} step did not answer JSON (HTTP {response.status_code})") from exc
    return data if isinstance(data, dict) else {}
