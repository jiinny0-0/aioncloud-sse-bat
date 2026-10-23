"""테스트 단말에서 트래픽을 발생시킨다.

요청은 단말에서 실행되므로 커넥터 터널을 지난다.
"""
from __future__ import annotations

import logging
import re
from urllib.parse import urlsplit

from bat.clients.errors import EndpointError
from bat.endpoint.base import Executor
from bat.models import TrafficResult

log = logging.getLogger(__name__)

BLOCK_STATUS_CODES = frozenset({403, 451})
_STATUS_RE = re.compile(r"(\d{3})\s*$")


def is_delivered_status(status_code: int | None) -> bool:
    """HTTP 상태 코드가 요청이 실제로 통과했다는 근거인지 판단한다.

    차단 코드와 5xx(중간 프록시가 낸 것일 수 있다)는 인정하지 않는다. 0(curl은 연결
    실패를 "000"으로 보고한다)과 None은 응답이 없는 것이다.
    """
    return (
        status_code is not None
        and 100 <= status_code < 500
        and status_code not in BLOCK_STATUS_CODES
    )


def curl_status(
    executor: Executor,
    url: str,
    *,
    method: str = "GET",
    proxy: str = "",
    data: str = "",
    headers: dict[str, str] | None = None,
    timeout_sec: int = 30,
    pin_ip: str = "",
) -> TrafficResult:
    """단말에서 URL을 요청하고 HTTP 상태 코드만 보고한다.

    본문은 버린다. `pin_ip`는 연결을 그 주소로 강제해서, A 레코드가 여러 개인 호스트도
    IP로 좁힌 정책이 대상으로 삼은 그 IP로 접속하게 한다.
    """
    parts = ["curl", "-k", "-s", "-o", "NUL", "-w", '"%{http_code}"', "-X", method]
    if proxy:
        parts += ["-x", proxy]
    if pin_ip:
        target = urlsplit(url)
        port = target.port or (443 if target.scheme == "https" else 80)
        parts += ["--resolve", f"{target.hostname}:{port}:{pin_ip}"]
    for key, value in (headers or {}).items():
        parts += ["-H", f'"{key}: {value}"']
    if data:
        parts += ["--data", f'"{data}"']
    parts += ["--max-time", str(timeout_sec), f'"{url}"']

    result = executor.run(" ".join(parts), timeout_sec=timeout_sec + 10)
    match = _STATUS_RE.search(result.stdout.strip().strip('"'))
    status_code = int(match.group(1)) if match else None
    blocked = status_code in BLOCK_STATUS_CODES if status_code else False

    log.info("curl %s %s -> %s (blocked=%s)", method, url, status_code, blocked)
    return TrafficResult(
        url=url,
        status_code=status_code,
        blocked=blocked,
        via="curl",
        detail=result.stderr.strip()[:200],
        delivered=is_delivered_status(status_code),
    )


def post_payload(
    executor: Executor,
    url: str,
    payload: str,
    *,
    content_type: str = "application/x-www-form-urlencoded",
    timeout_sec: int = 30,
) -> TrafficResult:
    """단말에서 본문을 POST한다(DLP 케이스가 합성 데이터를 이렇게 보낸다)."""
    return curl_status(
        executor,
        url,
        method="POST",
        data=payload,
        headers={"Content-Type": content_type},
        timeout_sec=timeout_sec,
    )


def find_live_proxies(
    executor: Executor,
    probe_url: str,
    *,
    list_url: str,
    max_found: int = 8,
    max_candidates: int = 60,
    probe_timeout_sec: int = 5,
) -> list[str]:
    """지금 실제로 트래픽을 중계하는 공개 HTTP 프록시를 찾는다.

    공개 프록시 목록은 계속 바뀌므로, 후보를 `list_url`(`proxy`와 `anonymity` 항목이
    있는 JSON 피드)에서 매번 새로 받아 단말을 통해 시도하고, transparent 프록시는
    마지막에 시도한다. `probe_url`은 평문 http://여야 한다. 목록에 있는 프록시 대부분이
    CONNECT 터널을 쓰는 HTTPS를 중계하지 못한다.

    처음 시도한 max_candidates개 중 동작하는 프록시를 최대 max_found개 반환한다.
    중계가 된다고 BLOCK_PUBLIC_PROXY가 그 프록시를 잡는다는 뜻은 아니므로, 호출자가
    정책에 대고 시도해 본다.
    """
    import httpx

    try:
        response = httpx.get(list_url, timeout=10)
        response.raise_for_status()
        entries = response.json()
        candidates = [
            e["proxy"] for e in sorted(entries, key=lambda e: e.get("anonymity") == "transparent")
            if isinstance(e, dict) and e.get("proxy")
        ]
    except Exception as exc:
        log.warning("Could not fetch/parse live proxy list from %s: %s", list_url, exc)
        return []

    found: list[str] = []
    for candidate in candidates[:max_candidates]:
        result = curl_status(executor, probe_url, proxy=candidate, timeout_sec=probe_timeout_sec)
        if result.status_code:
            found.append(candidate)
            if len(found) >= max_found:
                break

    log.info(
        "Found %d live proxies (of %d tried) from %s", len(found), max_candidates, list_url
    )
    return found


_DNS_ANSWER_RE = re.compile(r"address(?:es)?:\s*[0-9a-f]")
# DNS Firewall 차단 페이지의 문구(lguplus에서 확인). 웹 정책 차단 페이지("blocked by a web security
# policy")와 구분해야, 웹 정책이 막은 호스트를 DNS 차단으로 잘못 보지 않는다.
DNS_BLOCK_PAGE_TEXT = "blocked by DNS FireWall"
# {ip: 차단 페이지인가} — 같은 실행 안에서 한 주소는 한 번만 확인한다.
_BLOCK_PAGE_IPS: dict[str, bool] = {}


def _serves_block_page(executor: Executor, domain: str, ip: str) -> bool:
    """`ip`가 `domain` 대신 차단 페이지를 내주는 주소인가(DNS Firewall이 차단 페이지 주소로 답하는 망)."""
    if ip not in _BLOCK_PAGE_IPS:
        result = executor.run(f'curl -s -m 5 --resolve {domain}:80:{ip} "http://{domain}/"', timeout_sec=15)
        _BLOCK_PAGE_IPS[ip] = DNS_BLOCK_PAGE_TEXT.lower() in f"{result.stdout}".lower()
        log.info("%s for %s %s the block page", ip, domain, "is" if _BLOCK_PAGE_IPS[ip] else "is not")
    return _BLOCK_PAGE_IPS[ip]


def dns_lookup(executor: Executor, domain: str, timeout_sec: int = 20) -> TrafficResult:
    """DNS Firewall 케이스를 위해 단말에서 이름을 조회한다.

    `blocked`는 차단이다: 해석이 거부됐거나, 돌아온 주소가 차단 페이지를 내주는 주소다
    (lguplus의 U+SASE는 해석을 실패시키지 않고 차단 페이지 주소로 답한다). `delivered`는 응답 섹션(마지막 "Name:" 줄 뒤.
    nslookup은 그 앞에 자신이 쓰는 리졸버 주소를 출력한다)에 주소가 있어야 참이다.
    타임아웃은 둘 다 아니다.
    """
    result = executor.run(f"nslookup {domain}", timeout_sec=timeout_sec)
    output = f"{result.stdout}\n{result.stderr}".lower()
    failed = any(
        marker in output
        for marker in ("non-existent domain", "can't find", "server failed", "no answer")
    )
    answer = output.rsplit("name:", 1)[-1] if "name:" in output else ""
    addresses = sorted(set(_IPV4_RE.findall(answer)))
    if not failed and addresses and _serves_block_page(executor, domain, addresses[0]):
        failed = True  # 차단 페이지 주소로 바꿔 답한 것
    resolved = not failed and bool(_DNS_ANSWER_RE.search(answer))
    log.info("nslookup %s -> refused=%s resolved=%s", domain, failed, resolved)
    return TrafficResult(
        url=domain,
        status_code=None,
        blocked=failed,
        via="dns",
        detail=result.stdout.strip()[:300],
        delivered=resolved,
    )


_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def resolve_ip(executor: Executor, domain: str, timeout_sec: int = 20) -> str:
    """IP로 좁힌 정책을 만들기 위해 이름을 IPv4 주소 하나로 해석한다.

    nslookup이 그 앞에 리졸버 주소를 출력하므로 응답 섹션(마지막 "Name:" 뒤)만
    찾는다.
    """
    result = executor.run(f"nslookup {domain}", timeout_sec=timeout_sec)
    output = result.stdout
    answer = output.rsplit("Name:", 1)[-1] if "Name:" in output else ""
    match = _IPV4_RE.search(answer)
    if not match:
        raise EndpointError(f"Could not resolve {domain} to an IPv4 address: {output[:300]}")
    return match.group(0)


def upload_file(
    executor,
    url: str,
    *,
    remote_path: str,
    field: str = "file",
    timeout_sec: int = 40,
) -> TrafficResult:
    """단말에서 파일을 multipart/form-data로 POST한다.

    파일은 러너가 아니라 단말에 있어야 하므로, 호출자가 먼저 write_temp_file()로
    거기에 쓴다.
    """
    command = (
        f'curl -k -s -o NUL -w "%{{http_code}}" -X POST '
        f'-F "{field}=@{remote_path}" --max-time {timeout_sec} "{url}"'
    )
    result = executor.run(command, timeout_sec=timeout_sec + 10)
    match = _STATUS_RE.search(result.stdout.strip().strip('"'))
    status_code = int(match.group(1)) if match else None
    blocked = status_code in BLOCK_STATUS_CODES if status_code else False

    log.info("upload %s -> %s (blocked=%s)", url, status_code, blocked)
    return TrafficResult(
        url=url,
        status_code=status_code,
        blocked=blocked,
        via="curl",
        detail=result.stderr.strip()[:200],
        delivered=is_delivered_status(status_code),
    )


def upload_content(
    executor,
    url: str,
    content: str,
    *,
    filename: str,
    field: str = "file",
    timeout_sec: int = 40,
) -> TrafficResult:
    """upload_file()과 같지만, 디코딩한 내용을 디스크에 쓰지 않는다.

    단말의 실시간 백신은 EICAR이 든 파일을 쓰는 시점에 조용히 비우므로, 내용을
    base64에서 디코딩해 대신 curl의 stdin으로 흘려보낸다. 명령의 따옴표와 세미콜론이
    cmd.exe 아래의 인라인 `-Command` 인용을 견디지 못해, 명령은 .ps1 스크립트를
    `-File`로 실행한다.
    """
    # PowerShell은 [byte[]]를 네이티브 exe에 파이프할 때 줄마다 10진수 값 하나씩
    # 보내므로, 먼저 문자열로 디코딩한다. 여기서 보내는 페이로드는 ASCII 텍스트다.
    script = (
        f"$bytes = [Convert]::FromBase64String('{_b64(content)}')\n"
        f"$text = [System.Text.Encoding]::UTF8.GetString($bytes)\n"
        f'$text | & curl.exe -k -s -o NUL -w "%{{http_code}}" -X POST '
        f'-F "{field}=@-;filename={filename}" --max-time {timeout_sec} "{url}"\n'
    )
    script_path = write_temp_file(executor, script, f"upload-{filename}.ps1")
    try:
        command = f'powershell -NoProfile -NonInteractive -File "{script_path}"'
        result = executor.run(command, timeout_sec=timeout_sec + 10)
    finally:
        remove_temp_file(executor, script_path)

    match = _STATUS_RE.search(result.stdout.strip().strip('"'))
    status_code = int(match.group(1)) if match else None
    blocked = status_code in BLOCK_STATUS_CODES if status_code else False

    log.info("upload (in-memory) %s -> %s (blocked=%s)", url, status_code, blocked)
    return TrafficResult(
        url=url,
        status_code=status_code,
        blocked=blocked,
        via="curl",
        detail=result.stderr.strip()[:200],
        delivered=is_delivered_status(status_code),
    )


def _b64(content: str) -> str:
    import base64

    return base64.b64encode(content.encode("utf-8")).decode("ascii")


def write_temp_file(executor, content: str, name: str) -> str:
    """단말에 파일을 만들고 그 경로를 반환한다.

    내용은 base64로 전달되므로 원격 셸의 인용 처리나 코드 페이지가 내용을 바꿀 수
    없다. 파일은 단말의 임시 디렉터리 아래에 만든다.
    """
    import base64

    safe = "".join(ch if ch.isalnum() or ch in "-._" else "-" for ch in name)
    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
    script = (
        f"$p = Join-Path $env:TEMP '{safe}'; "
        f"[IO.File]::WriteAllBytes($p, [Convert]::FromBase64String('{encoded}')); "
        f"Write-Output $p"
    )
    result = executor.run_powershell(script).require_ok()
    path = result.stdout.strip().splitlines()[-1].strip() if result.stdout.strip() else ""
    if not path:
        raise EndpointError(
            f"Wrote {safe} to the endpoint but the shell returned no path: "
            f"{result.stderr[:200]}"
        )
    return path


def remove_temp_file(executor, path: str) -> None:
    executor.run_powershell(f"Remove-Item -Force -ErrorAction SilentlyContinue '{path}'")
