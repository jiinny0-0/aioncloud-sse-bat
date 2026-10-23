"""테스트 단말을 제어한다.

단말은 AIConnector 클라이언트가 돌아가는 Windows 머신이다. 머신 하나에 커넥터를
하나만 설치할 수 있어서, 단말은 실행 내내 워크스페이스 하나(따라서 사용자 신원
하나)에 고정된다.
"""
from __future__ import annotations

import logging
import shlex
import subprocess
from dataclasses import dataclass
from typing import Protocol

from bat.clients.errors import EndpointError
from bat.settings import Endpoint

log = logging.getLogger(__name__)

# 기본 커넥터는 "AIConnector for Client" 프로세스다(AIZtnaSvc 서비스는 커넥터가 아니다).
# 스테이지마다 다를 수 있어 environments.yaml의 connector_process로 바꾼다(lguplus 계열은 U+SASE).
# 프로세스가 떠 있다고 워크스페이스에 로그인돼 있다는 뜻은 아니다. 그건 bat run의 preflight가 본다.
CONNECTOR_PROCESS = "AIConnector for Client"
# EDR 에이전트 서비스다.
EDR_SERVICE = "monster"
CONNECTOR_LOG_DIR = r"C:\ProgramData\Monitorapp\AIConnector for Client\log"


def _decode(raw: bytes | None) -> str:
    """예외를 던지지 않고 콘솔 출력을 디코딩한다.

    Windows 콘솔은 시스템 코드 페이지로 출력한다(한국어 설치에서는 cp949).
    """
    if not raw:
        return ""
    for encoding in ("utf-8", "cp949", "cp1252"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


@dataclass
class CommandResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    def require_ok(self) -> "CommandResult":
        if not self.ok:
            # 두 스트림 중 어느 쪽이든 비어 있을 수 있다.
            detail = (self.stderr or self.stdout or "(no output)").strip()[:400]
            raise EndpointError(f"Command failed ({self.exit_code}): {self.command}\n{detail}")
        return self


class Executor(Protocol):
    def run(self, command: str, timeout_sec: int = 60) -> CommandResult: ...
    def run_powershell(self, script: str, timeout_sec: int = 60) -> CommandResult: ...


class LocalExecutor:
    """테스트 러너가 도는 머신에서 명령을 실행한다."""

    def __init__(self, endpoint: Endpoint) -> None:
        self.endpoint = endpoint

    def run(self, command: str, timeout_sec: int = 60) -> CommandResult:
        log.debug("[%s] local: %s", self.endpoint.name, command)
        try:
            # 바이트로 받아 여기서 디코딩한다. subprocess의 UTF-8 디코딩은
            # 현지화된 콘솔의 코드 페이지에서 실패한다.
            completed = subprocess.run(
                command if isinstance(command, str) else shlex.join(command),
                shell=True,
                capture_output=True,
                timeout=timeout_sec,
            )
        except subprocess.TimeoutExpired as exc:
            raise EndpointError(f"Timeout after {timeout_sec}s: {command}") from exc

        return CommandResult(
            command,
            completed.returncode,
            _decode(completed.stdout),
            _decode(completed.stderr),
        )

    def run_powershell(self, script: str, timeout_sec: int = 60) -> CommandResult:
        return self.run(
            f'powershell -NoProfile -NonInteractive -Command "{script}"',
            timeout_sec=timeout_sec,
        )


class WinRmExecutor:
    """WinRM으로 원격 Windows 단말에서 명령을 실행한다."""

    def __init__(self, endpoint: Endpoint, username: str, password: str) -> None:
        try:
            # 선택 의존성이며, 원격 단말에만 필요하다.
            import winrm  # type: ignore[import-not-found]  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover - 설치한 extras에 따라 다르다
            raise EndpointError(
                "pywinrm is not installed. Install the 'winrm' extra or set "
                "transport: local for this endpoint."
            ) from exc
        self.endpoint = endpoint
        self._session = winrm.Session(
            endpoint.host,
            auth=(username, password),
            transport="ntlm",
            server_cert_validation="ignore",
        )

    def run(self, command: str, timeout_sec: int = 60) -> CommandResult:
        log.debug("[%s] winrm: %s", self.endpoint.name, command)
        response = self._session.run_cmd(command)
        return CommandResult(
            command,
            response.status_code,
            response.std_out.decode("utf-8", "replace"),
            response.std_err.decode("utf-8", "replace"),
        )

    def run_powershell(self, script: str, timeout_sec: int = 60) -> CommandResult:
        response = self._session.run_ps(script)
        return CommandResult(
            script,
            response.status_code,
            response.std_out.decode("utf-8", "replace"),
            response.std_err.decode("utf-8", "replace"),
        )


def build_executor(endpoint: Endpoint, username: str = "", password: str = "") -> Executor:
    if endpoint.is_local:
        return LocalExecutor(endpoint)
    if not username or not password:
        raise EndpointError(
            f"Endpoint {endpoint.name} needs WinRM credentials "
            f"(BAT_ENDPOINT_USER / BAT_ENDPOINT_PASSWORD)"
        )
    return WinRmExecutor(endpoint, username, password)


def service_state(executor: Executor, service: str) -> str:
    """Running / Stopped / NotFound 중 하나를 반환한다."""
    result = executor.run_powershell(
        f"(Get-Service -Name '{service}' -ErrorAction SilentlyContinue).Status"
    )
    state = result.stdout.strip()
    return state or "NotFound"


def process_state(executor: Executor, process: str) -> str:
    """Running(프로세스가 하나 이상 있음) / NotRunning 중 하나를 반환한다."""
    result = executor.run_powershell(
        f"if (Get-Process -Name '{process}' -ErrorAction SilentlyContinue) {{ 'Running' }} else {{ 'NotRunning' }}"
    )
    return result.stdout.strip() or "NotRunning"


def connector_state(executor: Executor, process: str = CONNECTOR_PROCESS) -> str:
    return process_state(executor, process)


def connector_running(executor: Executor, process: str = CONNECTOR_PROCESS) -> bool:
    return connector_state(executor, process).lower() == "running"


def edr_agent_running(executor: Executor) -> bool:
    return service_state(executor, EDR_SERVICE).lower() == "running"


def edr_agent_version(executor: Executor) -> str:
    """설치된 Monster 에이전트 버전을 서비스 바이너리에서 읽는다."""
    script = (
        "$svc = Get-CimInstance Win32_Service -Filter \"Name='monster'\";"
        "if ($svc) {"
        "  $path = $svc.PathName.Trim('\"');"
        "  (Get-Item $path).VersionInfo.ProductVersion"
        "}"
    )
    return executor.run_powershell(script).stdout.strip()
