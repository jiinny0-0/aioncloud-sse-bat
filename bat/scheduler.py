"""레인 스케줄링.

병렬도는 CPU가 아니라 단말이 정한다. 단말 하나에 커넥터가 하나이므로, 단말 하나는
한 번에 한 워크스페이스로만 동작한다. 그래서 케이스를 레인으로 묶고, 레인마다
(단말, 워크스페이스) 쌍을 고정하고, pytest-xdist에 레인 하나를 워커 하나에서만
돌리도록 지시한다.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass

from bat.settings import Endpoint, RunContext, Workspace

log = logging.getLogger(__name__)

API_LANE = "api"


@dataclass(frozen=True)
class Lane:
    """직렬로 실행되는 트랙 하나."""

    name: str
    workspace: Workspace
    endpoint: Endpoint | None
    products: tuple[str, ...]

    @property
    def needs_endpoint(self) -> bool:
        return self.endpoint is not None

    @property
    def xdist_group(self) -> str:
        return f"lane-{self.name}"


# 단말이 모자랄 때 어떤 제품끼리 레인을 공유하는지. 제품마다 필요한 단말 시간
# 순으로 늘어놓아서, 병합은 부담이 적은 쪽부터 일어난다.
LANE_PRODUCTS: dict[str, tuple[str, ...]] = {
    "api": (),
    "b": ("basic", "swg", "fwaas", "cross"),
    "c": ("dlp", "rbi"),
    "d": ("casb", "genai"),
    "e": ("ztna", "edr"),
}


def build_lanes(context: RunContext) -> list[Lane]:
    """레인에 워크스페이스와 단말을 배정한다.

    단말이 레인보다 적으면 단말이 필요한 레인을 목록 끝에서부터 병합한다. 그러면
    가장 무거운 레인(casb/genai)이 최대한 오래 자기 워커를 따로 쓴다.
    """
    endpoint_lanes = [name for name in LANE_PRODUCTS if name != API_LANE]
    available = [e for e in context.endpoints]

    if not available:
        raise RuntimeError("No endpoints configured for this stage; see config/environments.yaml")

    merged: dict[str, list[str]] = {name: list(LANE_PRODUCTS[name]) for name in endpoint_lanes}
    while len(merged) > len(available):
        victim = endpoint_lanes[-1]
        endpoint_lanes = endpoint_lanes[:-1]
        target = endpoint_lanes[-1]
        merged[target].extend(merged.pop(victim))
        log.info("Merged lane %s into %s (only %d endpoints)", victim, target, len(available))

    lanes: list[Lane] = []
    workspaces = list(context.workspaces)
    if len(workspaces) < len(endpoint_lanes) + 1:
        raise RuntimeError(
            f"Need at least {len(endpoint_lanes) + 1} workspaces, "
            f"config/environments.yaml defines {len(workspaces)} for this stage"
        )

    lanes.append(
        Lane(
            name=API_LANE,
            workspace=workspaces[0],
            endpoint=None,
            products=tuple(LANE_PRODUCTS[API_LANE]),
        )
    )
    for index, lane_name in enumerate(endpoint_lanes):
        lanes.append(
            Lane(
                name=lane_name,
                workspace=workspaces[index + 1],
                endpoint=available[index],
                products=tuple(merged[lane_name]),
            )
        )
    return lanes


def concurrency_group(lanes: list[Lane], product: str) -> str:
    """제품의 케이스가 도는 xdist 그룹. 워크스페이스마다 하나다.

    BAT 정책은 전부 그 워크스페이스의 모든 사용자에게 걸리므로(`users: [0]`), 한
    워크스페이스를 쓰는 두 레인은 어느 단말이 트래픽을 보내든 서로의 정책을 맞는다.
    """
    return f"ws-{lane_for_product(lanes, product).workspace.name}"


def parallel_slots(lanes: list[Lane]) -> int:
    """워크스페이스를 공유하지 않고 돌 수 있는 워커 수."""
    return max(1, len({lane.workspace.name for lane in lanes if lane.endpoint}))


def lane_for_product(lanes: list[Lane], product: str) -> Lane:
    for lane in lanes:
        if product in lane.products:
            return lane
    return lanes[0]


def estimate_runtime(lanes: list[Lane], case_durations: dict[str, float]) -> dict[str, float]:
    """대략적인 실제 소요 시간 추정. 가장 느린 레인이 전체 시간이 된다.

    case_durations는 case_id -> 예상 초를 매핑한다. 제품은 케이스 id 접두사에서
    알아낸다.
    """
    per_lane: dict[str, float] = defaultdict(float)
    for case_id, seconds in case_durations.items():
        product = _product_of(case_id)
        lane = lane_for_product(lanes, product)
        per_lane[lane.name] += seconds

    per_lane_minutes = {name: round(total / 60, 1) for name, total in per_lane.items()}
    per_lane_minutes["_total_wall_clock"] = max(per_lane_minutes.values(), default=0.0)
    return per_lane_minutes


_PRODUCT_BY_PREFIX = {
    "BASIC": "basic",
    "SWG": "swg",
    "DLP": "dlp",
    "FW": "fwaas",
    "RBI": "rbi",
    "CASB": "casb",
    "GEN": "genai",
    "ZTNA": "ztna",
    "EDR": "edr",
    "X": "cross",
}


def _product_of(case_id: str) -> str:
    parts = case_id.split("-")
    if len(parts) < 2:
        return "swg"
    return _PRODUCT_BY_PREFIX.get(parts[1].upper(), "swg")
