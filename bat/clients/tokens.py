"""스스로 정한 엄격한 상한 아래에서 OpenAPI 토큰을 발급한다.

토큰은 makeOpenAPIToken으로 발급해 워크스페이스별로 캐시하고, 만료가 가까울 때만
다시 발급한다. 예산은 한 실행이 발급할 수 있는 개수를 제한한다.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

from bat.clients.errors import BudgetExceeded
from bat.clients.graphql import GraphQLClient

log = logging.getLogger(__name__)

DEFAULT_EXPIRATION_SEC = 6 * 60 * 60
REISSUE_MARGIN_SEC = 5 * 60


@dataclass
class IssuedToken:
    value: str
    workspace: str
    issued_at: float
    expires_at: float

    @property
    def near_expiry(self) -> bool:
        return time.time() >= (self.expires_at - REISSUE_MARGIN_SEC)


class TokenBudget:
    """발급한 OpenAPI 토큰을 프로세스 전체에서 기록하는 장부다."""

    def __init__(self, budget: int) -> None:
        self._budget = budget
        self._issued = 0
        self._cache: dict[str, IssuedToken] = {}
        self._lock = threading.Lock()

    @property
    def issued(self) -> int:
        return self._issued

    @property
    def remaining(self) -> int:
        return max(self._budget - self._issued, 0)

    def token_for(
        self,
        gql: GraphQLClient,
        workspace: str,
        expiration_sec: int = DEFAULT_EXPIRATION_SEC,
    ) -> str:
        with self._lock:
            cached = self._cache.get(workspace)
            if cached and not cached.near_expiry:
                return cached.value

            if self._issued >= self._budget:
                if cached:
                    # 예산 소진: 실패하는 대신 캐시된 토큰을 계속 쓴다.
                    log.warning(
                        "Token budget exhausted (%d); reusing the existing token for %s",
                        self._budget,
                        workspace,
                    )
                    return cached.value
                raise BudgetExceeded(
                    f"OpenAPI token budget of {self._budget} is exhausted and no cached "
                    f"token exists for workspace {workspace}"
                )

            value = gql.make_openapi_token(expiration_sec)
            self._issued += 1
            now = time.time()
            self._cache[workspace] = IssuedToken(
                value=value,
                workspace=workspace,
                issued_at=now,
                expires_at=now + expiration_sec,
            )
            log.info(
                "Minted OpenAPI token for %s (%d/%d used)",
                workspace,
                self._issued,
                self._budget,
            )
            return value

    def summary(self) -> dict[str, int | list[str]]:
        return {
            "budget": self._budget,
            "issued": self._issued,
            "remaining": self.remaining,
            "workspaces": sorted(self._cache),
        }


# --- 콘솔 세션 캐시 ---------------------------------------------
#
# 커넥터가 켜져 있으면 SSE가 로그인 본문(비밀번호가 들어 있다)을 차단할 수 있어서,
# 터널을 내린 상태에서 세션을 한 번 받아 재사용한다. 이 파일에는 비밀번호가 아니라
# 세션 토큰만 들어 있고, 커밋하지 않는다.

import json
from pathlib import Path


def _cache_path() -> Path:
    from bat.settings import ROOT

    return ROOT / ".console-session.json"


def save_console_token(workspace: str, token: str, expires_at: int | None = None) -> Path:
    path = _cache_path()
    data: dict[str, dict] = {}
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}

    data[workspace] = {
        "token": token,
        "expires_at": expires_at or int(time.time() + 8 * 60 * 60),
        "saved_at": int(time.time()),
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:  # pragma: no cover - Windows는 POSIX 권한 모드를 무시한다
        pass
    log.info("Console session for %s cached until %s", workspace, data[workspace]["expires_at"])
    return path


def load_console_token(workspace: str) -> str:
    """캐시된 세션 토큰을 반환하고, 없으면 빈 문자열을 반환한다."""
    path = _cache_path()
    if not path.exists():
        return ""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""

    entry = data.get(workspace) or {}
    token = entry.get("token", "")
    expires_at = entry.get("expires_at", 0)
    if not token:
        return ""
    if expires_at and time.time() >= expires_at - REISSUE_MARGIN_SEC:
        log.info("Cached console session for %s has expired", workspace)
        return ""
    return token
