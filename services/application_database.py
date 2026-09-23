from __future__ import annotations

import os
import threading
from pathlib import Path

from sqlalchemy import Boolean, DateTime, Float, Integer, JSON, MetaData, Numeric, SmallInteger, Text, create_engine, event, inspect, make_url, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.pool import NullPool


ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_DATA_DIR = ROOT_DIR / "data"
DatabaseBase = declarative_base()

_engines: dict[str, Engine] = {}
_engines_lock = threading.Lock()
_schema_lock = threading.Lock()


def resolve_database_url(data_dir: Path = DEFAULT_DATA_DIR) -> str:
    configured = os.getenv("DATABASE_URL", "").strip()
    if configured:
        if configured.startswith("postgres://"):
            return "postgresql+psycopg2://" + configured.removeprefix("postgres://")
        if configured.startswith("postgresql://"):
            return "postgresql+psycopg2://" + configured.removeprefix("postgresql://")
        return configured

    database_path = (data_dir / "chatgpt2api.db").resolve().as_posix()
    return f"sqlite:///{database_path}"


def database_backend_name(database_url: str) -> str:
    return make_url(database_url).get_backend_name()


def is_postgresql_url(database_url: str) -> bool:
    return database_backend_name(database_url) == "postgresql"


def display_database_url(database_url: str) -> str:
    try:
        return make_url(database_url).render_as_string(hide_password=True)
    except Exception:
        return "invalid-database-url"


def _database_cache_key(database_url: str) -> str:
    return make_url(database_url).render_as_string(hide_password=False)


def create_database_engine(database_url: str, *, shared: bool = True) -> Engine:
    cache_key = _database_cache_key(database_url)
    if not shared:
        return _build_database_engine(database_url)
    with _engines_lock:
        engine = _engines.get(cache_key)
        if engine is None:
            engine = _build_database_engine(database_url)
            _engines[cache_key] = engine
        return engine


def dispose_database_engine(database_url: str) -> None:
    """Remove one shared engine from the cache and close its connection pool."""
    cache_key = _database_cache_key(database_url)
    with _engines_lock:
        engine = _engines.pop(cache_key, None)
    if engine is not None:
        engine.dispose()


def dispose_all_database_engines() -> None:
    """Close every shared engine. Intended for process shutdown and test cleanup."""
    with _engines_lock:
        engines = tuple(_engines.values())
        _engines.clear()
    for engine in engines:
        engine.dispose()


_SCHEMA_MIGRATION_TABLE = "chatgpt_2api_application_schema_migrations"
_SCHEMA_VERSION = 1


def _quoted_identifier(connection, value: str) -> str:
    return connection.dialect.identifier_preparer.quote(str(value))


def _column_add_default(column, connection) -> str:
    """Return a constant SQL default that can backfill a new non-null column."""

    column_type = column.type
    dialect_name = connection.dialect.name
    if isinstance(column_type, (Boolean,)):
        return "FALSE" if dialect_name == "postgresql" else "0"
    if isinstance(column_type, (Integer, SmallInteger, Float, Numeric)):
        return "0"
    if isinstance(column_type, (JSON,)):
        return "'{}'::jsonb" if dialect_name == "postgresql" else "'{}'"
    if isinstance(column_type, DateTime):
        # A constant is accepted by SQLite's ADD COLUMN implementation.  The
        # application only needs a non-null historical marker; new writes use
        # the normal UTC timestamp supplied by the repository.
        return "'1970-01-01 00:00:00'"
    if isinstance(column_type, Text) or getattr(column_type, "length", None) is not None:
        return "''"
    return ""


def _add_missing_column(connection, table, column) -> None:
    table_name = _quoted_identifier(connection, table.name)
    column_name = _quoted_identifier(connection, column.name)
    type_sql = column.type.compile(dialect=connection.dialect)
    nullable = bool(column.nullable)
    default_sql = _column_add_default(column, connection) if not nullable else ""
    if not nullable and not default_sql:
        raise RuntimeError(
            f"application schema cannot add non-null column "
            f"{table.name}.{column.name} without a safe default"
        )

    if nullable:
        connection.execute(
            text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {type_sql}"),
        )
        return

    if connection.dialect.name == "sqlite":
        connection.execute(
            text(
                f"ALTER TABLE {table_name} ADD COLUMN {column_name} "
                f"{type_sql} NOT NULL DEFAULT {default_sql}"
            ),
        )
        return

    connection.execute(
        text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {type_sql}"),
    )
    connection.execute(
        text(
            f"UPDATE {table_name} SET {column_name} = {default_sql} "
            f"WHERE {column_name} IS NULL"
        ),
    )
    connection.execute(
        text(
            f"ALTER TABLE {table_name} ALTER COLUMN {column_name} SET NOT NULL"
        ),
    )


def synchronize_application_metadata(connection, metadata: MetaData) -> None:
    """Apply additive metadata changes without requiring a migration package.

    The project historically used ``create_all`` only, which creates missing
    tables but silently leaves existing tables at an older shape.  This
    synchronizer intentionally handles only safe additive changes: missing
    tables, columns, and indexes.  Destructive changes and primary-key/type
    changes remain explicit migration work rather than being guessed at
    startup.
    """

    migration_table = _quoted_identifier(connection, _SCHEMA_MIGRATION_TABLE)
    connection.execute(
        text(
            f"CREATE TABLE IF NOT EXISTS {migration_table} ("
            "version INTEGER PRIMARY KEY, "
            "applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
            ")"
        ),
    )

    existing_tables = set(inspect(connection).get_table_names())
    for table in metadata.sorted_tables:
        if table.name not in existing_tables:
            table.create(connection, checkfirst=True)
            existing_tables.add(table.name)
            continue

        inspector = inspect(connection)
        existing_columns = {
            str(item.get("name") or "")
            for item in inspector.get_columns(table.name)
        }
        missing_primary_keys = [
            column.name
            for column in table.primary_key.columns
            if column.name not in existing_columns
        ]
        if missing_primary_keys:
            raise RuntimeError(
                f"application schema table {table.name} is missing primary-key "
                f"columns: {', '.join(missing_primary_keys)}"
            )
        for column in table.columns:
            if column.name not in existing_columns:
                _add_missing_column(connection, table, column)
                inspector = inspect(connection)
                existing_columns = {
                    str(item.get("name") or "")
                    for item in inspector.get_columns(table.name)
                }

    for table in metadata.sorted_tables:
        for index in table.indexes:
            index.create(connection, checkfirst=True)

    applied = connection.execute(
        text(
            f"SELECT version FROM {migration_table} "
            "WHERE version = :version"
        ),
        {"version": _SCHEMA_VERSION},
    ).first()
    if applied is None:
        connection.execute(
            text(
                f"INSERT INTO {migration_table} (version, applied_at) "
                "VALUES (:version, CURRENT_TIMESTAMP)"
            ),
            {"version": _SCHEMA_VERSION},
        )


def initialize_application_database(database_url: str) -> Engine:
    """Create the current application schema."""
    engine = create_database_engine(database_url)
    with _schema_lock:
        DatabaseBase.metadata.create_all(engine)
    return engine


def _positive_float(name: str, default: float) -> float:
    try:
        return max(1.0, float(os.getenv(name, str(default)) or default))
    except (TypeError, ValueError):
        return default


def _nonnegative_int(name: str, default: int, *, minimum: int = 0) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default)) or default))
    except (TypeError, ValueError):
        return default


def _build_database_engine(database_url: str) -> Engine:
    backend = database_backend_name(database_url)
    if backend not in {"sqlite", "postgresql"}:
        raise ValueError(
            f"unsupported application database backend: {backend or 'unknown'}"
        )
    kwargs: dict[str, object] = {
        "pool_pre_ping": True,
        "pool_recycle": 3600,
    }
    if backend == "sqlite":
        timeout_seconds = _positive_float("SQLITE_BUSY_TIMEOUT_SECONDS", 30.0)
        kwargs["connect_args"] = {"timeout": timeout_seconds}
        kwargs["poolclass"] = NullPool
    else:
        kwargs.update({
            "pool_size": _nonnegative_int("DATABASE_POOL_SIZE", 10, minimum=1),
            "max_overflow": _nonnegative_int("DATABASE_MAX_OVERFLOW", 20),
            "pool_timeout": _nonnegative_int(
                "DATABASE_POOL_TIMEOUT_SECONDS",
                30,
                minimum=1,
            ),
        })

    engine = create_engine(database_url, **kwargs)
    if backend == "sqlite":
        busy_timeout_ms = int(
            _positive_float("SQLITE_BUSY_TIMEOUT_SECONDS", 30.0) * 1000
        )

        @event.listens_for(engine, "connect")
        def _configure_sqlite(dbapi_connection, _connection_record) -> None:
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
            finally:
                cursor.close()

    return engine
