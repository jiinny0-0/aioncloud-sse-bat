"""문서화된 SIA OpenAPI 범위(/sia/v1/**)용 REST 클라이언트다.

SWG 웹 정책, DLP 정책, 설정 그룹, 차단 페이지, 시그니처 모듈, 접근/보안 웹
로그를 다룬다. 이 목록 밖의 것은 전부 콘솔 GraphQL API에 있다.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from bat.clients.errors import ApiError, SelfBlockedError
from bat.settings import Profile

log = logging.getLogger(__name__)

OK_STATUSES = frozenset({200, 201, 204})

# API 오류는 JSON이고 SSE 차단 페이지는 HTML이라, "API가 거부함"과
# "API에 아예 도달하지 못함"을 구분할 수 있다.
_BLOCK_PAGE_MARKERS = ("<!DOCTYPE html", "<html", "Your request / response has")


def _looks_like_block_page(response: Any) -> bool:
    content_type = response.headers.get("content-type", "").lower()
    if "json" in content_type:
        return False
    head = response.text[:400]
    return any(marker.lower() in head.lower() for marker in _BLOCK_PAGE_MARKERS)


class RestClient:
    def __init__(self, profile: Profile, token: str, timeout_sec: float = 30.0) -> None:
        if not token.lower().startswith("bearer "):
            token = f"Bearer {token}"
        self.profile = profile
        self._client = httpx.Client(
            base_url=profile.rest_base_url.rstrip("/"),
            timeout=timeout_sec,
            verify=profile.verify_tls,
            headers={
                "Authorization": token,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
        expect: frozenset[int] | set[int] = OK_STATUSES,
    ) -> Any:
        response = self._client.request(method, path, json=json, params=params)
        if response.status_code not in expect:
            if _looks_like_block_page(response):
                raise SelfBlockedError(
                    f"{method} {path} was intercepted by an SSE block page, not the API.\n"
                    f"The runner's own traffic goes through the connector, so a broad "
                    f"BLOCK policy can cut off management access — including the request "
                    f"that would delete that policy.\n"
                    f"Recover by stopping the connector, running 'bat sweep --delete', "
                    f"then starting it again."
                )
            # 서버 메시지를 포함한다. 거부된 필드 이름이 거기 나온다.
            detail = response.text.strip()[:300].replace("\n", " ")
            raise ApiError(
                f"{method} {path} -> HTTP {response.status_code}"
                + (f": {detail}" if detail else ""),
                status_code=response.status_code,
                body=response.text[:500],
            )
        if response.status_code == 204 or not response.content:
            return {}
        try:
            return response.json()
        except ValueError:
            return {"_raw": response.text}

    def get(self, path: str, **kwargs: Any) -> Any:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> Any:
        return self.request("POST", path, **kwargs)

    def put(self, path: str, **kwargs: Any) -> Any:
        return self.request("PUT", path, **kwargs)

    def patch(self, path: str, **kwargs: Any) -> Any:
        return self.request("PATCH", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> Any:
        return self.request("DELETE", path, **kwargs)

    def health(self) -> bool:
        """비용이 적은 인증 확인 요청이다."""
        try:
            self.get("/sia/v1/user/group/list", params={"offset": 1, "limit": 1})
            return True
        except ApiError as exc:
            log.warning("REST health probe failed: %s", exc)
            return False

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "RestClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def pick_id(payload: Any, *id_keys: str) -> str | None:
    """응답 본문에서 처음 나오는 그럴듯한 리소스 id를 꺼낸다.

    생성된 객체는 엔드포인트에 따라 그대로, 리스트 안에, 또는 컨테이너 키 아래로
    돌아오므로 모든 형태를 시도한다.
    """
    keys = id_keys or ("id", "policy_id")

    def from_mapping(item: dict) -> str | None:
        for key in keys:
            value = item.get(key)
            if isinstance(value, (int, str)) and str(value).strip():
                return str(value)
        return None

    if isinstance(payload, dict):
        found = from_mapping(payload)
        if found:
            return found
        for container in ("data", "policy", "policies", "items", "list", "result"):
            nested = payload.get(container)
            if nested is not None:
                found = pick_id(nested, *keys)
                if found:
                    return found
    elif isinstance(payload, list):
        for item in payload:
            found = pick_id(item, *keys)
            if found:
                return found
    return None
