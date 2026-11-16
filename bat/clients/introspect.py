"""콘솔 스키마에서 문서화되지 않은 부분을 읽기 위한 스키마 introspection 헬퍼다."""
from __future__ import annotations

import logging
from typing import Any

from bat.clients.graphql import GraphQLClient

log = logging.getLogger(__name__)

TYPE_FIELDS = """
query BatIntrospectType($name: String!) {
  __type(name: $name) {
    name
    kind
    description
    fields {
      name
      description
      args { name defaultValue type { ...TypeRef } }
      type { ...TypeRef }
    }
    inputFields { name defaultValue type { ...TypeRef } }
    enumValues { name }
  }
}
fragment TypeRef on __Type {
  kind name
  ofType { kind name ofType { kind name ofType { kind name } } }
}
"""

ROOT_NAMES = """
query BatIntrospectRoots {
  __schema {
    queryType { name }
    mutationType { name }
  }
}
"""


def render_type(node: dict | None) -> str:
    """TypeRef를 [Int]!나 String처럼 읽기 쉬운 형태로 펼친다."""
    if not node:
        return "?"
    kind = node.get("kind")
    if kind == "NON_NULL":
        return f"{render_type(node.get('ofType'))}!"
    if kind == "LIST":
        return f"[{render_type(node.get('ofType'))}]"
    return node.get("name") or "?"


def describe_type(gql: GraphQLClient, type_name: str) -> dict[str, Any]:
    data = gql.execute(TYPE_FIELDS, {"name": type_name}, authenticated=True)
    return data.get("__type") or {}


def format_type(node: dict[str, Any]) -> list[str]:
    """GraphQL 타입 하나를 바로 출력할 수 있게 평평한 줄들로 렌더링한다."""
    if not node:
        return ["  (type not found)"]

    lines = [f"{node.get('name')}  [{node.get('kind')}]"]
    if node.get("description"):
        lines.append(f"  {node['description']}")

    for field in node.get("fields") or []:
        args = ", ".join(
            f"{a['name']}: {render_type(a.get('type'))}"
            + (f" = {a['defaultValue']}" if a.get("defaultValue") else "")
            for a in field.get("args") or []
        )
        signature = f"  {field['name']}({args})" if args else f"  {field['name']}"
        lines.append(f"{signature} -> {render_type(field.get('type'))}")

    for field in node.get("inputFields") or []:
        lines.append(f"  {field['name']}: {render_type(field.get('type'))}")

    enum_values = [v["name"] for v in node.get("enumValues") or []]
    if enum_values:
        lines.append(f"  values: {', '.join(enum_values)}")

    return lines


def walk_domain(gql: GraphQLClient, root_type: str, domain: str) -> list[str]:
    """SIARootMutation -> <domain> -> 그 타입 자신의 필드를 따라간다.

    콘솔은 모든 것을 두 단계 깊이로 중첩하므로, 쓸모 있는 작업 목록은 루트가
    아니라 도메인 필드가 반환하는 타입에 있다.
    """
    root = describe_type(gql, root_type)
    target = None
    for field in root.get("fields") or []:
        if field["name"].lower() == domain.lower():
            target = render_type(field.get("type")).strip("[]!")
            break

    if not target:
        available = sorted(f["name"] for f in root.get("fields") or [])
        return [
            f"No domain {domain!r} on {root_type}.",
            f"Available: {', '.join(available)}",
        ]

    return format_type(describe_type(gql, target))


def root_type_names(gql: GraphQLClient) -> tuple[str, str]:
    data = gql.execute(ROOT_NAMES, authenticated=True)
    schema = data.get("__schema") or {}
    return (
        (schema.get("queryType") or {}).get("name", "Query"),
        (schema.get("mutationType") or {}).get("name", "Mutation"),
    )
