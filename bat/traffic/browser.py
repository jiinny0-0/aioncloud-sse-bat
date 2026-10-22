"""사용자에게 보이는 결과가 핵심인 케이스를 위한, 브라우저로 하는 사용자 동작이다."""
from __future__ import annotations

import logging
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from bat.models import TrafficResult
from bat.settings import Profile
from bat.traffic.http import is_delivered_status

log = logging.getLogger(__name__)

NAV_TIMEOUT_MS = 30_000
SETTLE_MS = 1_500


class BrowserSession:
    """Playwright 브라우저 컨텍스트 하나를 감싼다. 한 레인의 케이스들이 재사용한다."""

    def __init__(self, profile: Profile, headed: bool = False, artifacts_dir: Path | None = None):
        self.profile = profile
        self.headed = headed
        self.artifacts_dir = artifacts_dir or Path("reports/artifacts")
        self._playwright = None
        self._browser = None
        self._context = None

    def start(self) -> "BrowserSession":
        from playwright.sync_api import sync_playwright  # noqa: PLC0415

        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch(headless=not self.headed)
        self._context = self._browser.new_context(ignore_https_errors=True)
        self._context.set_default_navigation_timeout(NAV_TIMEOUT_MS)
        log.info("Browser session started (headed=%s)", self.headed)
        return self

    def stop(self) -> None:
        for closer in (self._context, self._browser):
            try:
                if closer:
                    closer.close()
            except Exception as exc:  # pragma: no cover - 정리는 가능한 만큼만 한다
                log.debug("Browser teardown warning: %s", exc)
        if self._playwright:
            self._playwright.stop()
        log.info("Browser session stopped")

    @property
    def context(self):
        if not self._context:
            raise RuntimeError("Browser session is not started")
        return self._context

    @contextmanager
    def page(self) -> Iterator["object"]:
        page = self.context.new_page()
        try:
            yield page
        finally:
            if not page.is_closed():
                page.close()

    def visit(self, url: str, case_id: str = "") -> TrafficResult:
        """페이지를 열고 SSE가 요청을 차단했는지 판단한다.

        차단은 차단 페이지 마커로 알아본다. 탐색 오류는 차단도 전달도 아니다.
        `delivered`는 탐색이 성공하고 상태 코드가 전달로 인정돼야 참이다
        (is_delivered_status 참조).
        """
        with self.page() as page:
            nav_error = ""
            response = None
            try:
                response = page.goto(url, wait_until="domcontentloaded")
            except Exception as exc:
                nav_error = str(exc)[:200]
                log.warning("Navigation error for %s: %s", url, nav_error)

            page.wait_for_timeout(SETTLE_MS)
            marker = self.profile.block_page_marker
            blocked = page.get_by_text(marker).is_visible(timeout=2000) if not nav_error else False
            artifact = self.screenshot(page, case_id or "visit", url) if blocked or nav_error else ""
            status = response.status if response is not None and not nav_error else None
            delivered = not nav_error and not blocked and is_delivered_status(status)

            if nav_error:
                detail = nav_error
            elif blocked:
                detail = "block page marker matched"
            elif delivered:
                detail = f"page rendered (HTTP {status})"
            else:
                detail = f"no block page, but no usable response either (HTTP {status})"

            return TrafficResult(
                url=url,
                status_code=status,
                blocked=bool(blocked),
                via="browser",
                detail=detail,
                artifact=artifact,
                delivered=delivered,
            )

    def visit_for_isolation(self, url: str, case_id: str = "") -> TrafficResult:
        """페이지를 열고 RBI가 격리를 거쳐 페이지를 렌더링했는지 판단한다.

        격리된 방문은 배포의 격리 호스트로 리다이렉트되므로, 최종 URL이 요청한
        호스트와 다른 호스트에 닿았는지로 판별한다. 직접 렌더링과 SSE 차단 페이지는
        같은 호스트에 머문다.
        """
        from urllib.parse import urlparse

        target_host = urlparse(url).hostname or ""

        with self.page() as page:
            nav_error = ""
            response = None
            try:
                response = page.goto(url, wait_until="load")
            except Exception as exc:
                nav_error = str(exc)[:200]
                log.warning("Navigation error for %s: %s", url, nav_error)

            page.wait_for_timeout(SETTLE_MS)
            final_url = page.url if not nav_error else url
            final_host = urlparse(final_url).hostname or ""
            isolated = bool(final_host) and final_host != target_host
            status = response.status if response is not None and not nav_error else None
            # 직접 렌더링도 긍정 근거로 확인한다. 탐색이 실패해도 "같은 호스트에
            # 머물기" 때문에, 격리되지 않았다는 것만으로는 아무것도 증명하지 못한다.
            direct = not nav_error and not isolated and is_delivered_status(status)

            return TrafficResult(
                url=url,
                status_code=status,
                blocked=False,
                via="browser",
                detail=nav_error if nav_error else f"landed on {final_host} (HTTP {status})",
                isolated=isolated,
                delivered=direct,
            )

    def screenshot(self, page, case_id: str, label: str = "") -> str:
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        safe = "".join(ch if ch.isalnum() or ch in "-._" else "-" for ch in f"{case_id}-{label}")
        path = self.artifacts_dir / f"{safe[:120]}.png"
        try:
            page.screenshot(path=str(path), full_page=True)
            return str(path)
        except Exception as exc:  # pragma: no cover - 스크린샷은 가능한 만큼만 찍는다
            log.debug("Screenshot failed: %s", exc)
            return ""
