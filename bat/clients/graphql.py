"""REST OpenAPI 범위 밖의 모든 작업에 쓰는 콘솔 GraphQL 클라이언트다."""
from __future__ import annotations

import hashlib
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

CONSOLE_LOGIN = """
mutation BatConsoleLogin($email: String!, $password: String!, $workspace: String!) {
  authorization {
    console(email: $email, password: $password, workspace: $workspace) {
      token_value
      user_name
      user_role
      admin_level
      workspace
      expire_at
    }
  }
}
"""

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
        payload = self.execute(
            CONSOLE_LOGIN,
            {
                "email": login_id,
                "password": password if pre_hashed else self.hash_password(password),
                "workspace": self.workspace,
            },
            authenticated=False,
        )
        console = (payload.get("authorization") or {}).get("console") or {}
        token = console.get("token_value")
        if not token:
            raise AuthError(f"Console login returned no token for workspace {self.workspace}")
        self._token = token
        log.info(
            "Console session established: workspace=%s role=%s",
            console.get("workspace"),
            console.get("user_role"),
        )
        return console

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
