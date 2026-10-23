"""BAT 스위트의 실행 설정.

이 저장소에는 비밀이 없다. 자격증명은 환경변수(또는 커밋하지 않는 로컬 .env)에서
오고, YAML 파일에는 구조만 담는다.
"""
from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = ROOT / "config"
REPORTS_DIR = ROOT / "reports"


def _stage_env_file(profile_name: str) -> Path:
    """스테이지의 자격증명이 들어 있는 dotenv 파일을 돌려준다.

    config/environments.yaml의 스테이지 블록이 `env_file:`로 지정할 수 있고,
    없으면 `.env.<profile>`로 본다. dotenv 파일을 읽기 전에 불러도 안전하다.
    """
    try:
        block = _load_environments().get(profile_name) or {}
    except FileNotFoundError:
        block = {}
    override = block.get("env_file")
    return ROOT / override if override else ROOT / f".env.{profile_name}"


def _load_dotenv(stage_file: Path) -> None:
    """스테이지의 dotenv 파일을 읽고, 이어서 공용 `.env`를 읽는다.

    먼저 읽은 값이 이기므로(`override=False`) 스테이지 파일이 `.env`보다 우선한다.
    python-dotenv가 없어도 오류가 아니다.
    """
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    if stage_file.exists():
        load_dotenv(stage_file, override=False)
    shared_file = ROOT / ".env"
    if shared_file.exists():
        load_dotenv(shared_file, override=False)


def env(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


def env_int(name: str, default: int) -> int:
    raw = env(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc


def require_env(name: str) -> str:
    value = env(name)
    if not value:
        raise RuntimeError(
            f"Missing required environment variable {name}. "
            f"Copy .env.example to .env and fill it in."
        )
    return value


@dataclass(frozen=True)
class Profile:
    """같은 제품의 네트워크 스테이지 하나(qa/test/real = 사내망,
    lguplus = 통신사망)."""

    name: str
    console_url: str
    graphql_url: str
    rest_base_url: str
    block_page_marker: str
    verify_tls: bool = False
    # 이 스테이지 단말에서 도는 커넥터 프로세스 이름(lguplus 계열은 U+SASE).
    connector_process: str = "AIConnector for Client"

    @property
    def console_origin(self) -> str:
        return self.console_url.rstrip("/").removesuffix("/workspace")


@dataclass(frozen=True)
class Workspace:
    """BAT 실행이 정책을 만들고 지울 수 있는 테넌트."""

    name: str
    lane: str
    admin_env_user: str = "BAT_CONSOLE_USER"
    admin_env_password: str = "BAT_CONSOLE_PASSWORD"

    @property
    def login_id(self) -> str:
        return require_env(self.admin_env_user)

    @property
    def password(self) -> str:
        return require_env(self.admin_env_password)

    @property
    def has_console_credentials(self) -> bool:
        return bool(env(self.admin_env_user) and env(self.admin_env_password))

    @property
    def openapi_token(self) -> str:
        """콘솔에서 수동으로 발급한 토큰. 워크스페이스별 키가 공용 키보다 우선한다.

        Open API 서버에는 토큰 발급 엔드포인트가 없다.
        """
        return env(f"BAT_OPENAPI_TOKEN_{self.name.upper()}") or env("BAT_OPENAPI_TOKEN")


@dataclass(frozen=True)
class Endpoint:
    """AIConnector 클라이언트가 도는 Windows 단말.

    단말 하나에 커넥터가 하나라서, 단말은 실행 내내 정확히 한 워크스페이스에
    고정된다.
    """

    name: str
    lane: str
    transport: str  # "winrm" | "local"
    host: str = ""
    os: str = "windows"
    connector_user_env: str = ""
    device_id: str = ""
    browser: bool = True

    @property
    def is_local(self) -> bool:
        return self.transport == "local"


@dataclass
class RunContext:
    """BAT 실행 한 번의 식별 정보와 예산."""

    run_id: str
    profile: Profile
    started_at: datetime
    token_budget: int
    event_poll_timeout_sec: int
    policy_propagation_timeout_sec: int
    workspaces: list[Workspace] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)

    @property
    def report_dir(self) -> Path:
        return REPORTS_DIR / self.started_at.strftime("%Y-%m-%d") / self.run_id

    def workspace_for_lane(self, lane: str) -> Workspace:
        for workspace in self.workspaces:
            if workspace.lane == lane:
                return workspace
        raise LookupError(f"No workspace assigned to lane {lane!r}")

    def endpoint_for_lane(self, lane: str) -> Endpoint:
        for endpoint in self.endpoints:
            if endpoint.lane == lane:
                return endpoint
        raise LookupError(f"No endpoint assigned to lane {lane!r}")


def _read_yaml(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(
            f"Missing config file {path}. Copy the matching .example.yaml and edit it."
        )
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


@lru_cache(maxsize=1)
def _load_environments() -> dict[str, dict]:
    """스테이지당 블록 하나: URL, 워크스페이스, 단말. 자격증명은 dotenv 파일에 둔다."""
    raw = _read_yaml(CONFIG_DIR / "environments.yaml")
    environments = raw.get("environments") or {}
    if not environments:
        raise ValueError("config/environments.yaml defines no environments")
    return environments


def _build_profile(name: str, item: dict) -> Profile:
    return Profile(
        name=name,
        console_url=item["console_url"],
        graphql_url=item["graphql_url"],
        rest_base_url=item["rest_base_url"],
        block_page_marker=item.get("block_page_marker", "Your request / response has"),
        verify_tls=bool(item.get("verify_tls", False)),
        connector_process=str(item.get("connector_process") or "AIConnector for Client"),
    )


def _build_workspaces(item: dict) -> list[Workspace]:
    return [
        Workspace(
            name=row["name"],
            lane=row["lane"],
            admin_env_user=row.get("admin_env_user", "BAT_CONSOLE_USER"),
            admin_env_password=row.get("admin_env_password", "BAT_CONSOLE_PASSWORD"),
        )
        for row in (item.get("workspaces") or [])
    ]


def _build_endpoints(item: dict) -> list[Endpoint]:
    return [
        Endpoint(
            name=row["name"],
            lane=row["lane"],
            transport=row.get("transport", "winrm"),
            host=row.get("host", ""),
            os=row.get("os", "windows"),
            connector_user_env=row.get("connector_user_env", ""),
            device_id=row.get("device_id", ""),
            browser=bool(row.get("browser", True)),
        )
        for row in (item.get("endpoints") or [])
    ]


def load_environment(name: str) -> tuple[Profile, list[Workspace], list[Endpoint]]:
    """스테이지 이름을 config/environments.yaml에서 찾아 풀어낸다."""
    environments = _load_environments()
    if name not in environments:
        raise KeyError(
            f"Unknown stage {name!r}. Available: {', '.join(sorted(environments))} "
            f"(see config/environments.yaml)"
        )
    item = environments[name]
    return _build_profile(name, item), _build_workspaces(item), _build_endpoints(item)


def new_run_id() -> str:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{stamp}-{uuid.uuid4().hex[:6]}"


def build_run_context(profile_name: str = "", run_id: str = "") -> RunContext:
    # OS 환경에서만 읽는다(dotenv 파일에서는 읽지 않음). 그래야 dotenv 파일을
    # 하나도 읽기 전에 스테이지의 dotenv 파일을 고를 수 있다.
    profile_name = profile_name or env("BAT_PROFILE", "qa")
    _load_dotenv(_stage_env_file(profile_name))
    profile, workspaces, endpoints = load_environment(profile_name)
    return RunContext(
        run_id=run_id or env("BAT_RUN_ID") or new_run_id(),
        profile=profile,
        started_at=datetime.now(),
        # 실행 한 번에 발급하는 OpenAPI 토큰의 상한.
        token_budget=env_int("BAT_TOKEN_BUDGET", 10),
        # 케이스 하나만 돌면 6~20초 안에 이벤트가 보이지만, 한 테넌트에서 레인이
        # 동시에 돌면 60초를 훌쩍 넘긴다. 그래서 기본값을 크게 잡았다.
        event_poll_timeout_sec=env_int("BAT_EVENT_TIMEOUT_SEC", 90),
        policy_propagation_timeout_sec=env_int("BAT_POLICY_TIMEOUT_SEC", 20),
        workspaces=workspaces,
        endpoints=endpoints,
    )
