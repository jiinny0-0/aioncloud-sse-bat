"""SIA Open API 명세의 정책 enum.

이 문자열에 오타가 있으면 일반적인 validation 오류로만 돌아오므로, 케이스마다
리터럴로 흩어 쓰지 않고 여기서 한 번만 선언한다.
출처: components.schemas.WebPolicyRule / DLPPRule.
"""
from __future__ import annotations


class Subject:
    """WebPolicyRule.subject"""

    # 네트워크
    SOURCE_IP = "SOURCE_IP"
    SOURCE_IP_GEO = "SOURCE_IP_GEO"
    DESTINATION_IP = "DESTINATION_IP"
    DESTINATION_IP_GEO = "DESTINATION_IP_GEO"

    # HTTP 요청
    HTTP_CATEGORY = "HTTP_CATEGORY"
    HTTP_BROWSER = "HTTP_BROWSER"
    HTTP_HOST = "HTTP_HOST"
    HTTP_URL = "HTTP_URL"
    HTTP_PATH = "HTTP_PATH"
    HTTP_METHOD = "HTTP_METHOD"
    HTTP_HEADER = "HTTP_HEADER"
    HTTP_VERSION = "HTTP_VERSION"
    HTTP_GET_QUERY = "HTTP_GET_QUERY"
    HTTP_POST_PAYLOAD = "HTTP_POST_PAYLOAD"
    HTTP_CONTENT_LENGTH = "HTTP_CONTENT_LENGTH"
    HTTP_GET_QUERY_VALUE_LENGTH = "HTTP_GET_QUERY_VALUE_LENGTH"
    HTTP_POST_PAYLOAD_VALUE_LENGTH = "HTTP_POST_PAYLOAD_VALUE_LENGTH"

    # 파일 전송 — DLP 케이스가 걸리는 지점
    HTTP_UPLOADFILE_CONTENT = "HTTP_UPLOADFILE_CONTENT"
    HTTP_UPLOADFILE_EXTENSION = "HTTP_UPLOADFILE_EXTENSION"
    HTTP_DOWNLOADFILE_CONTENT = "HTTP_DOWNLOADFILE_CONTENT"
    HTTP_DOWNLOADFILE_EXTENSION = "HTTP_DOWNLOADFILE_EXTENSION"

    # 보안 모듈 — 값 목록이 없고 subject 자체가 스위치다
    BLOCK_CNC_TRAFFIC = "BLOCK_CNC_TRAFFIC"
    BLOCK_PUBLIC_PROXY = "BLOCK_PUBLIC_PROXY"
    BLOCK_RISKY_WEBSITES = "BLOCK_RISKY_WEBSITES"
    BLOCK_ATP = "BLOCK_ATP"
    BLOCK_MALICIOUS_RESPONSE = "BLOCK_MALICIOUS_RESPONSE"
    ANTI_VIRUS = "ANTI_VIRUS"

    # DLP 정책을 웹 정책에 연결하는 방법
    DLP_POLICY = "DLP_POLICY"


class Condition:
    """WebPolicyRule.condition"""

    IS = "IS"
    IS_NOT = "IS_NOT"
    IN = "IN"
    IN_NOT = "IN_NOT"
    IN_LIST = "IN_LIST"
    IN_LIST_NOT = "IN_LIST_NOT"
    MATCH_REGEX = "MATCH_REGEX"
    MATCH_REGEX_NOT = "MATCH_REGEX_NOT"
    MORE_THAN = "MORE_THAN"
    BELOW_THAN = "BELOW_THAN"
    EQUAL = "EQUAL"
    EQUAL_NOT = "EQUAL_NOT"


class ActionType:
    """web.CreateWebPolicyRequest.action_type"""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REWRITE = "REWRITE"


class RiskLevel:
    CRITICAL = "Critical"
    MAJOR = "Major"
    MINOR = "Minor"
    INFO = "Info"


class DlpRuleType:
    """DLPPRule.type"""

    PREDEFINED = "PREDEFINED"
    REGEX = "REGEX"
    KEYWORD = "KEYWORD"


class LogAction:
    """log.WebSecurityLogRecord.action"""

    BLOCK = "BLOCK"
    LOGGING = "LOGGING"
    REWRITE = "REWRITE"


SUBJECTS = frozenset(
    value for name, value in vars(Subject).items() if not name.startswith("_")
)
CONDITIONS = frozenset(
    value for name, value in vars(Condition).items() if not name.startswith("_")
)


def validate_rule(subject: str, condition: str) -> None:
    """서버 쪽 400 대신 읽기 쉬운 메시지로 바로 실패한다."""
    if subject not in SUBJECTS:
        raise ValueError(f"Unknown web policy subject {subject!r}")
    if condition not in CONDITIONS:
        raise ValueError(f"Unknown web policy condition {condition!r}")
