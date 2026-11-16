"""이벤트 폴링.

이벤트는 비동기로 도착하므로, 케이스는 고정 시간 동안 sleep하지 않고 지수 백오프와
상한이 있는 타임아웃으로 폴링한다.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Callable, TypeVar

log = logging.getLogger(__name__)

T = TypeVar("T")

INITIAL_INTERVAL_SEC = 1.0
MAX_INTERVAL_SEC = 4.0
BACKOFF_FACTOR = 1.6


class PollTimeout(Exception):
    def __init__(self, description: str, timeout_sec: float, attempts: int) -> None:
        super().__init__(
            f"{description} did not appear within {timeout_sec:.0f}s ({attempts} attempts)"
        )
        self.description = description
        self.timeout_sec = timeout_sec
        self.attempts = attempts


@dataclass
class PollOutcome:
    value: object
    attempts: int
    elapsed_sec: float


def poll_until(
    probe: Callable[[], T | None],
    *,
    timeout_sec: float = 30.0,
    description: str = "condition",
    initial_interval: float = INITIAL_INTERVAL_SEC,
) -> T:
    """probe()가 truthy 값을 반환하거나 타임아웃이 지날 때까지 호출한다.

    probe()는 대상이 없는 동안 None을 반환하고 진짜 오류일 때만 예외를 던지므로,
    API 실패는 재시도되지 않고 그대로 드러난다.
    """
    deadline = time.monotonic() + timeout_sec
    interval = initial_interval
    attempts = 0

    while True:
        attempts += 1
        result = probe()
        if result:
            elapsed = timeout_sec - max(deadline - time.monotonic(), 0)
            log.info(
                "Poll satisfied: %s after %d attempt(s), %.1fs", description, attempts, elapsed
            )
            return result

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PollTimeout(description, timeout_sec, attempts)

        time.sleep(min(interval, remaining))
        interval = min(interval * BACKOFF_FACTOR, MAX_INTERVAL_SEC)
