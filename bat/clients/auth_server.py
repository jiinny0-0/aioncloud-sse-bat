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
    base = profile.console_url.rstrip("/")
    with httpx.Client(verify=profile.verify_tls, follow_redirects=True, timeout=timeout_sec) as client:
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


def _json(response: httpx.Response, step: str) -> dict[str, Any]:
    if response.status_code >= 400:
        raise AuthError(f"Auth server {step} step answered HTTP {response.status_code}")
    try:
        data = response.json()
    except ValueError as exc:
        raise AuthError(f"Auth server {step} step did not answer JSON (HTTP {response.status_code})") from exc
    return data if isinstance(data, dict) else {}
