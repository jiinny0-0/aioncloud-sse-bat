"""API 클라이언트가 함께 쓰는 예외 타입이다."""
from __future__ import annotations


class BatError(Exception):
    """스위트가 의도적으로 발생시키는 모든 오류의 기반 클래스다."""


class ApiError(BatError):
    def __init__(self, message: str, status_code: int | None = None, body: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class AuthError(BatError):
    """로그인 또는 토큰 발급에 실패했다."""


class BudgetExceeded(BatError):
    """실행이 스스로 정한 OpenAPI 토큰 상한에 도달했다."""


class EndpointError(BatError):
    """테스트 단말에서 원격 명령 실행에 실패했다."""


class SelfBlockedError(BatError):
    """스위트 자신의 API 호출이 SSE 차단 페이지에 가로막혔다.

    러너는 테스트 대상 트래픽과 같은 커넥터 뒤에 있어서, 넓은 BLOCK 정책은 관리
    접근을 끊을 수 있고 그 정책 자신을 지우는 요청도 예외가 아니다.
    """
