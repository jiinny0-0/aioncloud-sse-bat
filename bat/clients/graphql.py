"""REST OpenAPI 범위 밖의 모든 작업에 쓰는 콘솔 GraphQL 클라이언트다."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
from typing import Any

import httpx

from bat.clients.errors import ApiError, AuthError, SelfBlockedError
from bat.settings import Profile

log = logging.getLogger(__name__)

# JSON이 와야 할 자리에 HTML이 오면 API가 아니라 SSE가 응답한 것이다.
_BLOCK_PAGE_MARKERS = ("<!DOCTYPE html", "<html", "Your request / response has")


def _looks_like_block_page(response: Any) -> bool:
    if "json" in response.headers.get("content-type", "").lower():
        return False
    head = response.text[:400].lower()
    return any(marker.lower() in head for marker in _BLOCK_PAGE_MARKERS)

# 2026-11-04 콘솔 업데이트로 authorization.console이 없어졌다. 세션 토큰(JWT)은 이제 응답 본문이
# 아니라 Set-Cookie(예: sia_qastage_console)로 오고, 그 값을 Bearer로 보내면 이전과 같이 인증된다.
CONSOLE_LOGIN = """
mutation BatConsoleLogin($email: String!, $password: String!, $workspace: String!) {
  authorization {
    session {
      issuance(email: $email, password: $password, workspace: $workspace) {
        expire_at
      }
    }
  }
}
"""

def _session_cookie(cookies: httpx.Cookies) -> str:
    """로그인 응답이 남긴 세션 쿠키 값. 이름이 스테이지마다 달라(sia_<stage>_console) JWT 모양으로 찾는다."""
    jwts = [(c.name, c.value) for c in cookies.jar if c.value and c.value.count(".") == 2]
    jwts.sort(key=lambda item: not item[0].endswith("_console"))  # *_console을 먼저
    return jwts[0][1] if jwts else ""


def _jwt_claims(token: str) -> dict[str, Any]:
    """서명은 확인하지 않고 표시용 정보(role, exp 등)만 읽는다."""
    try:
        part = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except (IndexError, ValueError):
        return {}


MAKE_OPENAPI_TOKEN = """
mutation BatMakeOpenAPIToken($token_expiration: Int) {
  SIA { user { makeOpenAPIToken(token_expiration: $token_expiration) { token_value } } }
}
"""


class GraphQLClient:
    """콘솔 세션을 다루는 GraphQL 래퍼로, (profile, workspace)마다 하나씩 둔다."""

    def __init__(self, profile: Profile, workspace: str, timeout_sec: float = 30.0) -> None:
        self.profile = profile
        self.workspace = workspace
        self._token: str = ""
        self._client = httpx.Client(
            timeout=timeout_sec,
            verify=profile.verify_tls,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )

    # -- 세션 ---------------------------------------------------------

    @staticmethod
    def hash_password(password: str) -> str:
        """콘솔 로그인은 비밀번호를 소문자 hex sha256으로 받는다."""
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def login(self, login_id: str, password: str, *, pre_hashed: bool = False) -> dict[str, Any]:
        """GraphQL issuance로 로그인하고, 실패하면 Auth Server(웹 로그인 화면)로 다시 로그인한다.

        Auth Server 경로는 issuance가 서버 쪽 사용자 검증 오류로 실패하는 동안 쓰는 임시
        수단이다(real, 2026-11). 평문 비밀번호가 필요해서 pre_hashed면 쓰지 않는다.
        `session["via"]`가 어느 쪽으로 로그인했는지 알려 준다.
        """
        try:
            payload = self.execute(
                CONSOLE_LOGIN,
                {
                    "email": login_id,
                    "password": password if pre_hashed else self.hash_password(password),
                    "workspace": self.workspace,
                },
                authenticated=False,
            )
            issuance = ((payload.get("authorization") or {}).get("session") or {}).get("issuance") or {}
            token = _session_cookie(self._client.cookies)
            if not token:
                raise AuthError(f"Console login returned no session cookie for workspace {self.workspace}")
            expire_at, via = issuance.get("expire_at"), "graphql"
        except (ApiError, AuthError) as exc:
            if pre_hashed:
                raise
            from bat.clients.auth_server import login_via_auth_server

            log.warning(
                "Console login through GraphQL failed for workspace %s (%s); trying the auth server",
                self.workspace, str(exc)[:200],
            )
            try:
                token, summary = login_via_auth_server(self.profile, self.workspace, login_id, password)
            except AuthError as fallback:
                raise AuthError(
                    f"Console login failed both ways for workspace {self.workspace}: "
                    f"GraphQL: {str(exc)[:200]} / auth server: {fallback}"
                ) from fallback
            expire_at, via = summary.get("session_expire_at"), "auth-server"

        self._token = token
        claims = _jwt_claims(token)
        session = {
            "token_value": token,
            "user_name": claims.get("user_name") or login_id,
            "user_role": claims.get("role"),
            "workspace": self.workspace,
            "expire_at": expire_at or claims.get("exp"),
            "via": via,
        }
        log.info(
            "Console session established: workspace=%s role=%s via=%s",
            self.workspace, session["user_role"], via,
        )
        return session

    def make_openapi_token(self, expiration_sec: int | None = None) -> str:
        """REST OpenAPI 토큰을 발급한다. 호출자는 반드시 TokenBudget을 거쳐야 한다."""
        variables = {"token_expiration": expiration_sec} if expiration_sec else {}
        payload = self.execute(MAKE_OPENAPI_TOKEN, variables)
        token = (
            ((payload.get("SIA") or {}).get("user") or {})
            .get("makeOpenAPIToken", {})
            .get("token_value")
        )
        if not token:
            raise AuthError("makeOpenAPIToken returned no token")
        return token

    def use_token(self, token: str) -> None:
        """다시 로그인하지 않고 앞서 받은 세션을 쓴다."""
        self._token = token

    @property
    def token(self) -> str:
        if not self._token:
            raise AuthError("GraphQL client is not logged in")
        return self._token

    # -- 전송 -------------------------------------------------------

    def execute(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
        *,
        authenticated: bool = True,
        operation: str = "",
    ) -> dict[str, Any]:
        headers: dict[str, str] = {}
        if authenticated:
            headers["Authorization"] = f"Bearer {self._token}"

        body: dict[str, Any] = {"query": query, "variables": variables or {}}
        if operation:
            body["operationName"] = operation

        response = self._client.post(self.profile.graphql_url, json=body, headers=headers)
        if response.status_code >= 400:
            # API는 오류를 JSON으로 답하므로, HTML 본문은 요청이 도중에 막혔다는 뜻이다
            # (주로 본문에 비밀번호가 든 로그인 요청).
            if _looks_like_block_page(response):
                raise SelfBlockedError(
                    f"The GraphQL request was intercepted by an SSE block page "
                    f"(HTTP {response.status_code}), not answered by the console API.\n"
                    f"Requests carrying credentials are being inspected as user "
                    f"traffic. Disconnect the connector to confirm: if the same call "
                    f"then succeeds, SSE is blocking the suite's own sign-in."
                )
            raise ApiError(
                f"GraphQL HTTP {response.status_code}",
                status_code=response.status_code,
                body=response.text[:500],
            )

        data = response.json()
        if data.get("errors"):
            messages = "; ".join(str(e.get("message", e)) for e in data["errors"])
            if "duplicate login" in messages.lower():
                # 캐시된 콘솔 세션이 stale해졌다. 이렇게 알려 주지 않으면 스키마나
                # 권한 문제처럼 읽힌다.
                messages = (
                    f"{messages}\n"
                    f"The cached console session is stale. Run 'bat login' to "
                    f"replace it, then run this again."
                )
            raise ApiError(f"GraphQL errors: {messages}", body=messages[:500])
        return data.get("data") or {}

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "GraphQLClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
