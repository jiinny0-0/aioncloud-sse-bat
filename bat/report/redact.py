"""리포트 파일에 들어가는 모든 것의 비밀 마스킹.

자격증명처럼 보이는 것은 실패 본문 안에 있더라도 절대 밖으로 쓰지 않는다.
"""
from __future__ import annotations

import re
from typing import Any

SENSITIVE_KEY_HINTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "authorization",
    "cookie",
    "private",
    "credential",
    "monsterkey",
    "webhook",
)

_BEARER_RE = re.compile(r"(Bearer\s+)[A-Za-z0-9._\-]{10,}", re.IGNORECASE)
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")
_MONSTER_KEY_RE = re.compile(r"mon-[0-9a-f]{8}-[0-9a-f-]{20,}", re.IGNORECASE)
_WEBHOOK_RE = re.compile(r"https://discord\.com/api/webhooks/\S+", re.IGNORECASE)

MASK = "***REDACTED***"


def is_sensitive_key(key: str) -> bool:
    lowered = key.lower().replace("-", "").replace("_", "")
    return any(hint.replace("_", "") in lowered for hint in SENSITIVE_KEY_HINTS)


def redact_text(text: str) -> str:
    if not text:
        return text
    for pattern in (_BEARER_RE, _JWT_RE, _MONSTER_KEY_RE, _WEBHOOK_RE):
        text = pattern.sub(
            lambda m: (m.group(1) + MASK) if m.re is _BEARER_RE and m.groups() else MASK,
            text,
        )
    return text


def redact(value: Any, key_hint: str = "") -> Any:
    if isinstance(value, dict):
        return {k: redact(v, key_hint=k) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item, key_hint=key_hint) for item in value]
    if isinstance(value, str):
        if key_hint and is_sensitive_key(key_hint):
            return MASK
        return redact_text(value)
    return value
