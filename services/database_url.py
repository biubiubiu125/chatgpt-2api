from __future__ import annotations

import os
from typing import Any
from urllib.parse import quote, unquote, urlsplit

from sqlalchemy import text


APP_DATABASE_NAME = "chatgpt_2api_app"
APP_DATABASE_ROLE = "app"
DATABASE_ROLE_MARKER_TABLE = "chatgpt_2api_database_role"
SUPPORTED_POSTGRES_SCHEMES = frozenset({"postgresql", "postgresql+psycopg2"})


def normalize_postgres_url(url: object) -> str:
    value = str(url or "").strip()
    if value.lower().startswith("postgres://"):
        return f"postgresql://{value[len('postgres://'):]}"
    return value


def build_postgres_url(
    *,
    username: object,
    password: object,
    host: object,
    port: object,
    database: object,
    scheme: str = "postgresql",
) -> str:
    username_text = quote(str(username or "").strip(), safe="")
    password_text = quote(str(password or "").strip(), safe="")
    host_text = str(host or "").strip()
    database_text = str(database or "").strip().lstrip("/")
    return f"{scheme}://{username_text}:{password_text}@{host_text}:{int(port)}{('/' + database_text) if database_text else ''}"


def build_postgres_url_from_env(
    database: object,
    *,
    default_host: str = "postgres",
    default_port: int = 5432,
    scheme: str = "postgresql+psycopg2",
) -> str:
    username = str(os.getenv("POSTGRES_USER") or "").strip()
    password = str(os.getenv("POSTGRES_PASSWORD") or "").strip()
    if not username or not password:
        return ""
    host = str(os.getenv("POSTGRES_HOST") or default_host).strip() or default_host
    try:
        port = int(str(os.getenv("POSTGRES_PORT") or default_port).strip() or default_port)
    except (TypeError, ValueError):
        port = default_port
    return build_postgres_url(
        username=username,
        password=password,
        host=host,
        port=port,
        database=database,
        scheme=scheme,
    )


def is_postgres_url(url: object) -> bool:
    value = normalize_postgres_url(url)
    if ":" not in value:
        return False
    scheme = value.split(":", 1)[0].lower()
    return scheme in SUPPORTED_POSTGRES_SCHEMES


def postgres_database_name(url: object) -> str:
    parsed = urlsplit(normalize_postgres_url(url))
    path = unquote(parsed.path or "").strip("/")
    return path.rsplit("/", 1)[-1] if path else ""


def validate_named_postgres_database(url: object, expected_name: str, *, role: str) -> str:
    normalized = normalize_postgres_url(url)
    if not normalized:
        return ""
    if not is_postgres_url(normalized):
        raise ValueError(
            f"{_database_role_label(role)}必须使用 PostgreSQL 地址"
            "（postgresql:// 或 postgresql+psycopg2://）"
        )
    actual_name = postgres_database_name(normalized)
    if actual_name != expected_name:
        raise ValueError(
            f"{_database_role_label(role)}必须使用数据库名 {expected_name}"
        )
    return normalized


def select_named_postgres_database(
    *,
    dedicated_url: object,
    fallback_url: object,
    expected_name: str,
    role: str,
) -> str:
    dedicated = normalize_postgres_url(dedicated_url)
    if dedicated:
        return validate_named_postgres_database(dedicated, expected_name, role=role)
    fallback = normalize_postgres_url(fallback_url)
    if fallback:
        return validate_named_postgres_database(fallback, expected_name, role=role)
    return ""


def _normalize_database_role(value: object) -> str:
    role = str(value or "").strip().lower().replace("-", "_")
    aliases = {
        "application": APP_DATABASE_ROLE,
        "runtime": APP_DATABASE_ROLE,
    }
    return aliases.get(role, role)


def _database_role_label(role: object) -> str:
    raw = str(role or "").strip()
    key = _normalize_database_role(raw)
    if key == APP_DATABASE_ROLE:
        return "应用数据库"
    return f"{raw}数据库" if raw else "数据库"


def _marker_table_sql() -> str:
    return (
        f"CREATE TABLE IF NOT EXISTS {DATABASE_ROLE_MARKER_TABLE} ("
        "id VARCHAR(64) PRIMARY KEY, "
        "role VARCHAR(64) NOT NULL, "
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, "
        "updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ")"
    )


def _is_missing_marker_table_error(exc: Exception) -> bool:
    detail = f"{type(exc).__name__}: {exc}".lower()
    table = DATABASE_ROLE_MARKER_TABLE.lower()
    return (
        ("no such table" in detail and table in detail)
        or ("does not exist" in detail and table in detail)
        or ("undefinedtable" in detail and table in detail)
    )


def read_database_role_marker(connection: Any) -> dict[str, str]:
    try:
        row = connection.execute(
            text(f"SELECT role, created_at, updated_at FROM {DATABASE_ROLE_MARKER_TABLE} WHERE id = :id"),
            {"id": "default"},
        ).mappings().first()
    except Exception as exc:
        if _is_missing_marker_table_error(exc):
            return {}
        raise ValueError(f"无法读取数据库角色标记：{exc}") from exc
    if not row:
        return {}
    return {
        "role": str(row.get("role") or ""),
        "created_at": str(row.get("created_at") or ""),
        "updated_at": str(row.get("updated_at") or ""),
    }


def ensure_database_role_marker(
    connection: Any,
    expected_role: object,
    *,
    create_if_missing: bool = True,
) -> dict[str, str]:
    expected = _normalize_database_role(expected_role)
    if expected not in {APP_DATABASE_ROLE}:
        raise ValueError(f"不支持的数据库角色：{expected_role}")
    if create_if_missing:
        connection.execute(text(_marker_table_sql()))
    marker = read_database_role_marker(connection)
    if not marker:
        if not create_if_missing:
            raise ValueError(
                f"数据库角色标记缺失，期望 {_database_role_label(expected)}"
            )
        connection.execute(
            text(
                f"INSERT INTO {DATABASE_ROLE_MARKER_TABLE} "
                "(id, role, created_at, updated_at) "
                "VALUES (:id, :role, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            ),
            {"id": "default", "role": expected},
        )
        marker = read_database_role_marker(connection)
    return validate_database_role_marker(connection, expected)


def validate_database_role_marker(connection: Any, expected_role: object) -> dict[str, str]:
    expected = _normalize_database_role(expected_role)
    marker = read_database_role_marker(connection)
    actual = _normalize_database_role(marker.get("role") if marker else "")
    if not actual:
        raise ValueError(
            f"数据库角色标记缺失，期望 {_database_role_label(expected)}"
        )
    if actual != expected:
        raise ValueError(
            f"数据库角色不匹配：期望 {_database_role_label(expected)}，"
            f"实际 {_database_role_label(actual)}"
        )
    return {**marker, "role": actual}
