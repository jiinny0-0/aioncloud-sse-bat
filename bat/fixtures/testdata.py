"""합성 테스트 데이터와 트래픽 대상.

실제 고객 데이터, 개인정보, 악성코드는 쓰지 않는다. 모든 값은 이 스위트를 위해
지어낸 것이고 그렇다는 것을 알아볼 수 있어서, 남은 탐지 이벤트를 BAT까지
추적할 수 있다.
"""
from __future__ import annotations

import uuid

# 관리 API 호스트. 러너는 테스트 트래픽과 같은 커넥터를 거쳐 API에 닿으므로,
# 이 호스트까지 덮을 만큼 넓은 BLOCK 정책은 그 정책을 지우는 호출까지 포함해
# 스위트 전체를 끊는다.
MANAGEMENT_HOST_HINTS = ("aioncloud.com", "monitorapp")

# 트래픽 대상: 실제 업무와 무관한 안정적인 테스트 사이트.
BLOCK_TARGET_HOST = "httpbin.org"
BLOCK_TARGET_URL = "https://httpbin.org/get"
POST_TARGET_URL = "https://httpbin.org/post"
ALLOW_TARGET_URL = "https://www.iana.org/"
SECOND_HOST = "example.com"
SECOND_URL = "https://example.com/"
# BLOCK_TARGET_HOST와 다른 나라에 호스팅돼 있을 것으로 보는 목적지로, 음성
# 대조에 쓴다. 실제 국가는 케이스가 로그 행에서 읽는다.
OTHER_COUNTRY_HOST = "www.korea.kr"
OTHER_COUNTRY_URL = "https://www.korea.kr/"

# public-proxy 시그니처 케이스용 공개 HTTP 프록시 실시간 목록. 무료 프록시는
# 계속 바뀌므로 후보는 실행 시점에 가져온다(bat.traffic.http.find_live_proxies).
# JSON에 anonymity 필드가 들어 있다.
PUBLIC_PROXY_LIST_URL = (
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.json"
)

# CASB SaaS 앱 카탈로그 id. API는 목록을 주지 않으며, 이 값은 CASB 보안로그의
# in_app_service { id name }에서 얻었다. `1`은 앱 하나가 아니라 "전체 앱"
# 센티널이라 뺐다.
CASB_SAAS_APPS = {
    "Notion": 3,
    "Discord": 9,
    "Intercom": 128,
    "Spring": 363,
    "GitHub": 380,
    "Cloudflare": 474,
    "Chat GPT": 529,
    "Atlassian": 767,
    "LinkedIn": 1112,
}

# CASB 대상 앱. Notion은 (Cloudflare와 달리) 범위가 좁고 스위트의 다른 곳에서
# 쓰지 않는다. CASB 앱 인식에는 실제 브라우저 방문이 필요하고, curl은 안정적으로
# 인식되지 않는다.
CASB_SAAS_APP_NAME = "Notion"
# 모든 SaaS 앱을 덮는 In-App Control `application` 입력(`saas_desc_id: 1`이
# "전체" 센티널)과, 콘솔이 그 입력에 쓰는 function 값.
CASB_IN_APP_ALL_APPS = [{"id": 1, "saas_desc_id": 1, "function": [2, 6, 5, 7]}]
# 콘솔이 쓰는 형태 그대로의 "모든 요청 토픽" GenAI rule.
# GenAIPolicyFactory.create()의 기본값이다.
GENAI_TOPIC_ALL_RULES = [[{"id": 1, "subject": "GENAI_REQUEST_TOPIC", "condition": "IN", "value": ["all"]}]]
CASB_SAAS_APP_ID = CASB_SAAS_APPS[CASB_SAAS_APP_NAME]
CASB_SAAS_HOST = "www.notion.so"
CASB_SAAS_URL = f"https://{CASB_SAAS_HOST}/"

# 카탈로그에 있는 두 번째 앱. 앱 하나로 좁힌 정책이 다른 앱은 건드리지 않음을
# 보이는 데 쓴다.
CASB_OTHER_APP_NAME = "GitHub"
CASB_OTHER_APP_URL = "https://github.com/"


def marker(case_id: str, run_id: str) -> str:
    """실제 트래픽에는 나타날 수 없는 DLP 키워드."""
    return f"BATSENSITIVE{case_id.replace('-', '')}{run_id.replace('-', '')[:12]}"


def keyword_payload(token: str) -> str:
    return f"note=quarterly review&secret={token}&owner=bat-suite"


def clean_payload() -> str:
    return "note=quarterly review&owner=bat-suite&secret=nothing-to-see-here"


# 형식만 맞춘 지어낸 값. 누구에게도 발급되지 않았고 숫자가 국가 체크섬을
# 통과하지 않으므로 실제 번호와 겹칠 수 없다.
SYNTHETIC_RRN = "990101-1234567"
SYNTHETIC_CARD = "4111-1111-1111-1111"  # 표준 테스트 카드 번호

CUSTOM_REGEX = r"BATCODE-[0-9]{4}-[A-Z]{3}"


def regex_sample() -> str:
    return f"BATCODE-{uuid.uuid4().int % 10000:04d}-ZZZ"


def upload_file_body(token: str) -> str:
    return (
        "BAT synthetic document\n"
        "This file exists only to exercise DLP upload detection.\n"
        f"marker: {token}\n"
    )


# 표준 백신 테스트 문자열(eicar.org). 악성코드가 아니며, 백신 엔진이 일부러
# 탐지하도록 만든 것이다. ANTI_VIRUS 케이스가 쓴다.
EICAR_STRING = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

# 시그니처 모듈(C&C, ATP, Proxy Server, Risky Website)은 콘솔 Signature
# Management 목록에 등록된 URL/IP/SHA256 항목만 매칭하고, Anti-Virus와 Malware는
# 대신 엔진을 쓴다. BAT는 케이스가 도는 동안 이 호스트를 C&C와 Risky Website
# deny 목록에 넣고 끝나면 뺀다. 목록은 워크스페이스 전체에 걸리고 mutation이
# 목록을 통째로 바꾸므로, SignaturePatternList는 기존 항목을 전부 유지한 채
# 다시 쓴다. 이 호스트를 쓰는 다른 케이스가 없어서 `bat sweep`이 남은 BAT
# 항목을 가려낼 수 있다.
SIGNATURE_TARGET_HOST = "www.example.org"
SIGNATURE_DENYLIST_URL = f"http://{SIGNATURE_TARGET_HOST}/"
