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
    block_text: str = "",
) -> TrafficResult:
    """단말에서 URL을 요청하고 HTTP 상태 코드를 보고한다.

    `block_text`가 없으면 본문은 버리고 403/451을 차단으로 본다. 있으면 본문을 받아,
    403/451이면서 본문에 그 문구(대소문자 무시)가 있어야 차단이다. 문구 없는 403/451은
    원 서버나 중간 프록시의 거부일 수 있어 차단도 전달도 아니다. `pin_ip`는 연결을 그
    주소로 강제해서, A 레코드가 여러 개인 호스트도 IP로 좁힌 정책이 대상으로 삼은 그 IP로
    접속하게 한다.
    """
    output = ["-w", '"\\n%{http_code}"'] if block_text else ["-o", "NUL", "-w", '"%{http_code}"']
    parts = ["curl", "-k", "-s", *output, "-X", method]
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
    stdout = result.stdout.strip()
    body, _, code = stdout.rpartition("\n") if block_text else ("", "", stdout)
    match = _STATUS_RE.search(code.strip().strip('"'))
    status_code = int(match.group(1)) if match else None
    return _curl_result(url, method, status_code, body, block_text, result.stderr)


def _curl_result(
    url: str, method: str, status_code: int | None, body: str, block_text: str, stderr: str
) -> TrafficResult:
    """curl_status의 판정. 차단 페이지 문구를 요구하면 문구 없는 403/451은 판단 불가다."""
    refused = status_code in BLOCK_STATUS_CODES if status_code else False
    page = block_text.lower() in body.lower() if block_text else None
    blocked = refused and page is not False
    detail = stderr.strip()[:200]
    if refused and page is False:
        detail = f"HTTP {status_code} without the block page text {block_text!r}: {' '.join(body.split())[:150]}"
    elif blocked and page:
        detail = f"HTTP {status_code} block page ({block_text!r})"
    log.info("curl %s %s -> %s (blocked=%s)", method, url, status_code, blocked)
    return TrafficResult(
        url=url,
        status_code=status_code,
        blocked=blocked,
        via="curl",
        detail=detail,
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


class UploadFileRemoved(EndpointError):
    """업로드할 파일을 단말에 쓰지 못했거나, 쓴 직후 사라졌다(단말 백신이 지우거나 막음).

    요청을 보내지 못한 것이므로 제품이 막았는지 아닌지와 무관하다.
    """


# 업로드 스크립트가 파일을 쓰지 못했을 때 맨 앞에 출력하는 표지.
_UPLOAD_FILE_MISSING = "BAT_UPLOAD_FILE_MISSING"


def upload_content(
    executor,
    url: str,
    content: str,
    *,
    filename: str,
    field: str = "file",
    timeout_sec: int = 40,
) -> TrafficResult:
    """content를 바이트 그대로 multipart/form-data로 POST한다.

    단말의 실시간 백신이 EICAR이 든 파일을 지울 수 있어서, 파일 쓰기·확인·업로드·삭제를
    스크립트 하나에서 곧바로 한다. 파일을 쓰지 못했거나 쓴 직후 사라졌으면
    UploadFileRemoved를 낸다. 명령의 따옴표와 세미콜론이 cmd.exe 아래의 인라인
    `-Command` 인용을 견디지 못해, 명령은 .ps1 스크립트를 `-File`로 실행한다.
    """
    traffic, _ = _upload_bytes(executor, url, content, filename, field, timeout_sec, keep_body=False)
    return traffic


def upload_content_echoed(
    executor,
    url: str,
    content: str,
    *,
    filename: str,
    field: str = "file",
    timeout_sec: int = 40,
) -> tuple[TrafficResult, bool | None, str]:
    """upload_content()처럼 보내고, 에코 서버(httpbin /post)가 받은 파일 내용이 보낸 것과
    바이트까지 같은지도 돌려준다: (결과, intact, 바뀐 내용 설명). intact가 True면 그대로
    전달됐고, False면 바뀌었고(설명에 어떻게), None이면 확인할 수 없다(에코 JSON이 아님).
    응답 본문은 돌려주지도 기록하지도 않는다(EICAR가 들어 있다).
    """
    traffic, body = _upload_bytes(executor, url, content, filename, field, timeout_sec, keep_body=True)
    if not traffic.delivered:
        return traffic, None, ""
    return traffic, echoed_file_intact(body, content, field), echo_change(body, content, field)


def _echoed_file(body: str, field: str) -> str | None:
    import json

    try:
        files = json.loads(body).get("files")
    except (ValueError, AttributeError):
        return None
    if not isinstance(files, dict) or field not in files:
        return None
    return str(files[field])


def echoed_file_intact(body: str, content: str, field: str = "file") -> bool | None:
    """httpbin /post 응답의 files[field]가 보낸 content와 정확히 같은가(앞뒤 공백·BOM 포함)."""
    received = _echoed_file(body, field)
    return None if received is None else received == content


def echo_change(body: str, content: str, field: str = "file") -> str:
    """에코가 보낸 내용과 다를 때 어떻게 다른지. 같거나 읽을 수 없으면 빈 문자열."""
    received = _echoed_file(body, field)
    if received is None or received == content:
        return ""
    notes = []
    if received.startswith("\ufeff"):
        notes.append("a byte order mark (U+FEFF) was prepended")
        received = received[1:]
    if received != content and received.rstrip("\r\n") == content:
        notes.append("a line break was appended")
        received = content
    if received != content:
        notes.append(f"the content differs ({len(received)} characters received, {len(content)} sent)")
    return "the transport changed the file: " + "; ".join(notes)


def _upload_script(url: str, content: str, filename: str, field: str, timeout_sec: int, *, keep_body: bool) -> str:
    """파일을 바이트로 쓰고, 그대로 있는지 확인하고, curl로 올리고, 지우는 PowerShell 스크립트.

    내용은 파이프로 넘기지 않는다(PowerShell이 앞에 BOM을, 뒤에 줄바꿈을 붙인다). 임시 폴더
    경로에 ASCII가 아닌 문자(사용자 이름)가 있을 수 있어, 그 폴더로 옮겨 가 파일 이름만 넘긴다.
    """
    safe = "".join(ch if ch.isalnum() or ch in "-._" else "-" for ch in filename)
    local = f"bat-upload-{safe}"
    size = len(content.encode("utf-8"))
    output = '-w "`n%{http_code}"' if keep_body else '-o NUL -w "%{http_code}"'
    lines = [
        "Set-Location -LiteralPath ([IO.Path]::GetTempPath())",
        f"$name = '{local}'",
        "try {",
        f"    [IO.File]::WriteAllBytes((Join-Path (Get-Location) $name), [Convert]::FromBase64String('{_b64(content)}'))",
        "} catch {",
        f'    Write-Output "{_UPLOAD_FILE_MISSING} could not write the file: $($_.Exception.Message)"',
        "    exit 0",
        "}",
        "$item = Get-Item -LiteralPath $name -ErrorAction SilentlyContinue",
        f"if (-not $item -or $item.Length -ne {size}) {{",
        "    $found = if ($item) { \"$($item.Length) bytes\" } else { 'no file' }",
        f'    Write-Output "{_UPLOAD_FILE_MISSING} the file was gone or changed right after writing '
        f'({size} bytes written, $found)"',
        "    Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $name",
        "    exit 0",
        "}",
        "try {",
        f'    & curl.exe -k -s {output} -X POST -F "{field}=@$name;filename={filename}" '
        f'--max-time {timeout_sec} "{url}"',
        "} finally {",
        "    Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $name",
        "}",
    ]
    return "\n".join(lines) + "\n"


def _upload_bytes(
    executor, url: str, content: str, filename: str, field: str, timeout_sec: int, *, keep_body: bool
) -> tuple[TrafficResult, str]:
    script = _upload_script(url, content, filename, field, timeout_sec, keep_body=keep_body)
    script_path = write_temp_file(executor, script, f"upload-{filename}.ps1")
    try:
        command = f'powershell -NoProfile -NonInteractive -File "{script_path}"'
        result = executor.run(command, timeout_sec=timeout_sec + 10)
    finally:
        remove_temp_file(executor, script_path)

    stdout = result.stdout.strip()
    if stdout.startswith(_UPLOAD_FILE_MISSING):
        raise UploadFileRemoved(
            f"Upload of {filename} to {url} was not sent: "
            f"{stdout[len(_UPLOAD_FILE_MISSING):].strip()[:200]}"
        )
    body, _, code = stdout.rpartition("\n") if keep_body else ("", "", stdout)
    match = _STATUS_RE.search(code.strip().strip('"'))
    status_code = int(match.group(1)) if match else None
    blocked = status_code in BLOCK_STATUS_CODES if status_code else False

    log.info("upload (bytes) %s -> %s (blocked=%s)", url, status_code, blocked)
    traffic = TrafficResult(
        url=url,
        status_code=status_code,
        blocked=blocked,
        via="curl",
        detail=result.stderr.strip()[:200],
        delivered=is_delivered_status(status_code),
    )
    # PowerShell이 curl 출력의 줄을 CRLF로 이어 붙이므로, 상태 코드 줄 앞의 \r만 뗀다.
    return traffic, body.rstrip("\r")


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
