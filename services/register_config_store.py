from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from sqlalchemy import Column, DateTime, String, Text, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import declarative_base, sessionmaker
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from services.application_database import (
    create_database_engine,
    resolve_database_url,
    synchronize_application_metadata,
)
from services.database_url import (
    APP_DATABASE_NAME,
    APP_DATABASE_ROLE,
    ensure_database_role_marker,
    is_postgres_url,
    validate_named_postgres_database,
)
from services.json_file import read_json_object, write_json_file
from services.register.provider_catalog import sanitize_legacy_provider_entries


Base = declarative_base()
_REGISTER_CONFIG_FORMAT_PREFIX = "CHATGPT-2API-REGISTER-CONFIG-V1:"
_REGISTER_CONFIG_ASSOCIATED_DATA = b"chatgpt-2api/register-config"


def validate_register_config_for_storage(value: Mapping[str, Any]) -> None:
    """Validate that configuration can be sanitized and encrypted before writing."""
    _encode_config_data(_sanitize_database_config(dict(value)))


class RegisterConfigModel(Base):
    __tablename__ = "register_config"

    key = Column(String(64), primary_key=True)
    data = Column(Text, nullable=False)


class RegisterRuntimeLeaseModel(Base):
    __tablename__ = "register_runtime_lease"

    key = Column(String(64), primary_key=True)
    owner_id = Column(String(128), nullable=False, default="")
    run_id = Column(String(128), nullable=False, default="")
    state = Column(String(32), nullable=False, default="idle")
    heartbeat_at = Column(DateTime(timezone=True), nullable=False)
    lease_expires_at = Column(DateTime(timezone=True), nullable=False)
    stop_requested_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False)


class FileRegisterConfigStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> dict[str, Any]:
        data = read_json_object(self.path, name="register.json")
        runtime = data.get("runtime") if isinstance(data, dict) else None
        if isinstance(runtime, dict):
            data["runtime"] = _normalize_runtime(runtime)
        return data

    def save(self, value: dict[str, Any]) -> None:
        write_json_file(self.path, value)

    def update_stats(self, updates: Mapping[str, Any]) -> dict[str, Any]:
        data = self.load()
        stats = data.get("stats") if isinstance(data.get("stats"), dict) else {}
        stats.update(dict(updates))
        data["stats"] = stats
        self.save(data)
        return data

    def info(self) -> dict[str, str]:
        return {"type": "file", "path": str(self.path)}

    def load_runtime_lease(self) -> dict[str, Any]:
        data = self.load()
        runtime = data.get("runtime") if isinstance(data, dict) else {}
        return runtime if isinstance(runtime, dict) else {}

    def try_acquire_runtime_lease(
        self,
        owner_id: str,
        run_id: str,
        *,
        state: str = "running",
        lease_seconds: int = 30,
    ) -> bool:
        data = self.load()
        runtime = _normalize_runtime(data.get("runtime") if isinstance(data, dict) else {})
        now = _now()
        active = _lease_active(runtime, now)
        if active and str(runtime.get("owner_id") or "") not in {"", owner_id}:
            return False
        data["runtime"] = _runtime_payload(owner_id, run_id, state=state, lease_seconds=lease_seconds, now=now)
        self.save(data)
        return True

    def touch_runtime_lease(
        self,
        owner_id: str,
        run_id: str,
        *,
        state: str | None = None,
        lease_seconds: int = 30,
    ) -> bool:
        data = self.load()
        runtime = _normalize_runtime(data.get("runtime") if isinstance(data, dict) else {})
        if not runtime or str(runtime.get("owner_id") or "") != owner_id or str(runtime.get("run_id") or "") != run_id:
            return False
        now = _now()
        if not _lease_active(runtime, now):
            return False
        data["runtime"] = _runtime_payload(
            owner_id,
            run_id,
            state=state or str(runtime.get("state") or "running"),
            lease_seconds=lease_seconds,
            now=now,
        )
        self.save(data)
        return True

    def release_runtime_lease(self, owner_id: str, run_id: str) -> bool:
        data = self.load()
        runtime = _normalize_runtime(data.get("runtime") if isinstance(data, dict) else {})
        if not runtime or str(runtime.get("owner_id") or "") != owner_id or str(runtime.get("run_id") or "") != run_id:
            return False
        now = _now()
        data["runtime"] = {
            **runtime,
            "state": "idle",
            "heartbeat_at": now.isoformat(),
            "lease_expires_at": now.isoformat(),
            "updated_at": now.isoformat(),
        }
        self.save(data)
        return True


class DatabaseRegisterConfigStore:
    def __init__(self, database_url: str, *, legacy_path: Path | None = None) -> None:
        normalized_database_url = str(database_url or "").strip()
        postgres = is_postgres_url(normalized_database_url)
        if postgres:
            normalized_database_url = validate_named_postgres_database(
                normalized_database_url,
                APP_DATABASE_NAME,
                role="app",
            )
        self.database_url = normalized_database_url
        self.engine = create_database_engine(self.database_url)
        with self.engine.begin() as connection:
            ensure_database_role_marker(
                connection,
                APP_DATABASE_ROLE,
                create_if_missing=True,
            )
            synchronize_application_metadata(connection, Base.metadata)
        self.Session = sessionmaker(bind=self.engine)
        self._lock = threading.RLock()
        if legacy_path is not None:
            self._import_legacy_file(legacy_path)

    def load(self) -> dict[str, Any]:
        session = self.Session()
        try:
            row = session.get(RegisterConfigModel, "default")
            data, legacy_plaintext = _config_data_from_row_with_format(row)
            sanitized = _sanitize_database_config(data)
            if row is not None and (legacy_plaintext or sanitized != data):
                row.data = _encode_config_data(sanitized)
                session.commit()
                data = sanitized
            runtime_row = session.get(RegisterRuntimeLeaseModel, "default")
            if runtime_row is not None:
                data["runtime"] = _row_to_runtime(runtime_row)
            return data
        finally:
            session.close()

    def has_config(self) -> bool:
        """Return whether the Application Database owns the config row.

        ``load()`` intentionally returns an empty mapping for both an empty
        configuration and a missing row. Migration needs to distinguish those
        states so it never replaces an explicitly saved empty configuration.
        """
        session = self.Session()
        try:
            return session.get(RegisterConfigModel, "default") is not None
        finally:
            session.close()

    def import_legacy_config_once(self, value: Mapping[str, Any]) -> bool:
        """Persist sanitized legacy configuration only when no row exists."""
        payload_value = _sanitize_database_config(dict(value))
        if not payload_value:
            return False
        with self._lock:
            session = self.Session()
            try:
                if self.engine.dialect.name == "sqlite":
                    session.execute(text("BEGIN IMMEDIATE"))
                row = session.execute(
                    select(RegisterConfigModel)
                    .where(RegisterConfigModel.key == "default")
                    .with_for_update()
                ).scalar_one_or_none()
                if row is not None:
                    session.rollback()
                    return False
                session.add(
                    RegisterConfigModel(
                        key="default",
                        data=_encode_config_data(payload_value),
                    )
                )
                session.commit()
                return True
            except IntegrityError:
                session.rollback()
                return False
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()

    def save(self, value: dict[str, Any]) -> None:
        with self._lock:
            session = self.Session()
            try:
                payload_value = _sanitize_database_config(value)
                if self.engine.dialect.name == "sqlite":
                    session.execute(text("BEGIN IMMEDIATE"))
                row = session.execute(
                    select(RegisterConfigModel)
                    .where(RegisterConfigModel.key == "default")
                    .with_for_update()
                ).scalar_one_or_none()
                payload_data = _merge_config_preserving_newer_stats(
                    _config_data_from_row(row),
                    payload_value,
                )
                payload = _encode_config_data(payload_data)
                if row is None:
                    session.add(RegisterConfigModel(key="default", data=payload))
                else:
                    row.data = payload
                session.commit()
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()

    def update_stats(self, updates: Mapping[str, Any]) -> dict[str, Any]:
        with self._lock:
            session = self.Session()
            try:
                if self.engine.dialect.name == "sqlite":
                    session.execute(text("BEGIN IMMEDIATE"))
                row = session.execute(
                    select(RegisterConfigModel)
                    .where(RegisterConfigModel.key == "default")
                    .with_for_update()
                ).scalar_one_or_none()
                data = _config_data_from_row(row)
                stats = data.get("stats") if isinstance(data.get("stats"), dict) else {}
                stats.update(dict(updates))
                data["stats"] = stats
                payload = _encode_config_data(data)
                if row is None:
                    session.add(RegisterConfigModel(key="default", data=payload))
                else:
                    row.data = payload
                session.commit()
                return data
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()

    def info(self) -> dict[str, str]:
        return {"type": "database", "database_url": _mask_password(self.database_url)}

    def _import_legacy_file(self, path: Path) -> None:
        if not path.exists() and not path.with_suffix(path.suffix + ".bak").exists():
            return
        legacy = read_json_object(path, name="register.json")
        self.import_legacy_config_once(legacy)

    def load_runtime_lease(self) -> dict[str, Any]:
        session = self.Session()
        try:
            row = session.get(RegisterRuntimeLeaseModel, "default")
            return _row_to_runtime(row) if row is not None else {}
        finally:
            session.close()

    def try_acquire_runtime_lease(
        self,
        owner_id: str,
        run_id: str,
        *,
        state: str = "running",
        lease_seconds: int = 30,
    ) -> bool:
        now = _now()
        session = self.Session()
        try:
            with session.begin():
                initial_row = {
                    "key": "default",
                    "owner_id": "",
                    "run_id": "",
                    "state": "idle",
                    "heartbeat_at": now,
                    "lease_expires_at": now,
                    "created_at": now,
                    "updated_at": now,
                }
                if self.engine.dialect.name == "postgresql":
                    from sqlalchemy.dialects.postgresql import insert as dialect_insert

                    session.execute(
                        dialect_insert(RegisterRuntimeLeaseModel)
                        .values(**initial_row)
                        .on_conflict_do_nothing(
                            index_elements=[RegisterRuntimeLeaseModel.key]
                        )
                    )
                elif self.engine.dialect.name == "sqlite":
                    from sqlalchemy.dialects.sqlite import insert as dialect_insert

                    session.execute(
                        dialect_insert(RegisterRuntimeLeaseModel)
                        .values(**initial_row)
                        .on_conflict_do_nothing(
                            index_elements=[RegisterRuntimeLeaseModel.key]
                        )
                    )
                else:
                    try:
                        with session.begin_nested():
                            session.add(RegisterRuntimeLeaseModel(**initial_row))
                            session.flush()
                    except IntegrityError:
                        pass
                row = session.execute(
                    select(RegisterRuntimeLeaseModel).where(RegisterRuntimeLeaseModel.key == "default").with_for_update()
                ).scalar_one_or_none()
                if row is not None:
                    active = _lease_active(_row_to_runtime(row), now)
                    if active and str(row.owner_id or "") not in {"", owner_id}:
                        return False
                if row is None:
                    raise RuntimeError("register runtime lease row could not be initialized")
                _apply_runtime_lease_row(row, owner_id, run_id, state=state, lease_seconds=lease_seconds, now=now)
                return True
        finally:
            session.close()

    def touch_runtime_lease(
        self,
        owner_id: str,
        run_id: str,
        *,
        state: str | None = None,
        lease_seconds: int = 30,
    ) -> bool:
        now = _now()
        session = self.Session()
        try:
            with session.begin():
                row = session.execute(
                    select(RegisterRuntimeLeaseModel).where(RegisterRuntimeLeaseModel.key == "default").with_for_update()
                ).scalar_one_or_none()
                if row is None or str(row.owner_id or "") != owner_id or str(row.run_id or "") != run_id:
                    return False
                if not _lease_active(_row_to_runtime(row), now):
                    return False
                _apply_runtime_lease_row(row, owner_id, run_id, state=state or str(row.state or "running"), lease_seconds=lease_seconds, now=now)
                return True
        finally:
            session.close()

    def release_runtime_lease(self, owner_id: str, run_id: str) -> bool:
        now = _now()
        session = self.Session()
        try:
            with session.begin():
                row = session.execute(
                    select(RegisterRuntimeLeaseModel).where(RegisterRuntimeLeaseModel.key == "default").with_for_update()
                ).scalar_one_or_none()
                if row is None or str(row.owner_id or "") != owner_id or str(row.run_id or "") != run_id:
                    return False
                _apply_runtime_lease_row(row, owner_id, run_id, state="idle", lease_seconds=0, now=now)
                row.lease_expires_at = now
                row.stop_requested_at = None
                return True
        finally:
            session.close()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _register_config_secret() -> str:
    secret = str(
        os.getenv("CHATGPT2API_REGISTER_CONFIG_KEY")
        or os.getenv("CHATGPT2API_REGISTER_RECOVERY_KEY")
        or os.getenv("CHATGPT2API_AUTH_KEY")
        or ""
    ).strip()
    if not secret:
        try:
            from services.config import config

            secret = str(config.auth_key or "").strip()
        except Exception:
            secret = ""
    if not secret:
        raise RuntimeError(
            "register config encryption key is not configured"
        )
    return secret


def _register_config_key() -> bytes:
    return hashlib.sha256(
        b"chatgpt-2api/register-config/aes-gcm/v1\0"
        + _register_config_secret().encode("utf-8")
    ).digest()


def _encode_config_data(value: dict[str, Any]) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    nonce = os.urandom(12)
    encrypted = AESGCM(_register_config_key()).encrypt(
        nonce,
        payload,
        _REGISTER_CONFIG_ASSOCIATED_DATA,
    )
    encoded = base64.urlsafe_b64encode(nonce + encrypted).decode("ascii")
    return f"{_REGISTER_CONFIG_FORMAT_PREFIX}{encoded}"


def _decode_config_data(raw: object) -> tuple[dict[str, Any], bool]:
    text_value = str(raw or "{}")
    if not text_value.startswith(_REGISTER_CONFIG_FORMAT_PREFIX):
        try:
            data = json.loads(text_value)
        except json.JSONDecodeError as exc:
            raise ValueError("register config database contains invalid JSON") from exc
        if not isinstance(data, dict):
            raise ValueError("register config database must contain a JSON object")
        return data, True
    encoded = text_value[len(_REGISTER_CONFIG_FORMAT_PREFIX):]
    try:
        encrypted = base64.urlsafe_b64decode(encoded.encode("ascii"))
        if len(encrypted) <= 12:
            raise ValueError("register config database payload is truncated")
        payload = AESGCM(_register_config_key()).decrypt(
            encrypted[:12],
            encrypted[12:],
            _REGISTER_CONFIG_ASSOCIATED_DATA,
        )
        data = json.loads(payload.decode("utf-8"))
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError, InvalidTag) as exc:
        raise ValueError(
            "register config database cannot be decrypted with the configured key"
        ) from exc
    if not isinstance(data, dict):
        raise ValueError("register config database must contain a JSON object")
    return data, False


def _config_data_from_row_with_format(
    row: RegisterConfigModel | None,
) -> tuple[dict[str, Any], bool]:
    if row is None:
        return {}, False
    return _decode_config_data(row.data)


def _config_data_from_row(row: RegisterConfigModel | None) -> dict[str, Any]:
    return _config_data_from_row_with_format(row)[0]


def _sanitize_database_config(value: object) -> dict[str, Any]:
    data = dict(value) if isinstance(value, Mapping) else {}
    mail = data.get("mail")
    if isinstance(mail, Mapping):
        normalized_mail = dict(mail)
        normalized_mail["providers"] = sanitize_legacy_provider_entries(
            normalized_mail.get("providers")
        )
        data["mail"] = normalized_mail
    data.pop("runtime", None)
    return data


def _merge_config_preserving_newer_stats(
    existing: Mapping[str, Any],
    incoming: Mapping[str, Any],
) -> dict[str, Any]:
    merged = dict(incoming)
    existing_stats = existing.get("stats") if isinstance(existing.get("stats"), dict) else {}
    incoming_stats = incoming.get("stats") if isinstance(incoming.get("stats"), dict) else {}
    existing_updated_at = _parse_datetime(existing_stats.get("updated_at"))
    incoming_updated_at = _parse_datetime(incoming_stats.get("updated_at"))
    if existing_stats and existing_updated_at and (
        incoming_updated_at is None or existing_updated_at > incoming_updated_at
    ):
        merged["stats"] = dict(existing_stats)
    return merged


def _parse_datetime(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _normalize_runtime(runtime: object) -> dict[str, Any]:
    data = runtime if isinstance(runtime, dict) else {}
    normalized = {
        "owner_id": str(data.get("owner_id") or "").strip(),
        "run_id": str(data.get("run_id") or "").strip(),
        "state": str(data.get("state") or "idle").strip() or "idle",
        "heartbeat_at": _parse_datetime(data.get("heartbeat_at")),
        "lease_expires_at": _parse_datetime(data.get("lease_expires_at")),
        "stop_requested_at": _parse_datetime(data.get("stop_requested_at")),
        "created_at": _parse_datetime(data.get("created_at")),
        "updated_at": _parse_datetime(data.get("updated_at")),
    }
    return {key: (value.isoformat() if isinstance(value, datetime) else value) for key, value in normalized.items() if value is not None or key in {"owner_id", "run_id", "state"}}


def _runtime_payload(
    owner_id: str,
    run_id: str,
    *,
    state: str,
    lease_seconds: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = now or _now()
    lease_expires_at = current + timedelta(seconds=max(1, int(lease_seconds or 0)))
    payload = {
        "owner_id": owner_id,
        "run_id": run_id,
        "state": state,
        "heartbeat_at": current.isoformat(),
        "lease_expires_at": lease_expires_at.isoformat(),
        "updated_at": current.isoformat(),
    }
    if state == "stopping":
        payload["stop_requested_at"] = current.isoformat()
    return payload


def _apply_runtime_lease_row(
    row: RegisterRuntimeLeaseModel,
    owner_id: str,
    run_id: str,
    *,
    state: str,
    lease_seconds: int,
    now: datetime | None = None,
) -> None:
    current = now or _now()
    row.owner_id = owner_id
    row.run_id = run_id
    row.state = state
    row.heartbeat_at = current
    row.lease_expires_at = current + timedelta(seconds=max(1, int(lease_seconds or 0)))
    row.updated_at = current
    row.stop_requested_at = current if state == "stopping" else None
    if row.created_at is None:
        row.created_at = current


def _row_to_runtime(row: RegisterRuntimeLeaseModel | None) -> dict[str, Any]:
    if row is None:
        return {}
    runtime = {
        "owner_id": row.owner_id,
        "run_id": row.run_id,
        "state": row.state,
        "heartbeat_at": row.heartbeat_at.isoformat() if row.heartbeat_at else "",
        "lease_expires_at": row.lease_expires_at.isoformat() if row.lease_expires_at else "",
        "stop_requested_at": row.stop_requested_at.isoformat() if row.stop_requested_at else "",
        "created_at": row.created_at.isoformat() if row.created_at else "",
        "updated_at": row.updated_at.isoformat() if row.updated_at else "",
    }
    return runtime


def _lease_active(runtime: Mapping[str, Any], now: datetime | None = None) -> bool:
    expires_at = _parse_datetime(runtime.get("lease_expires_at")) if isinstance(runtime, dict) else None
    state = str(runtime.get("state") or "") if isinstance(runtime, dict) else ""
    return bool(expires_at and expires_at > (now or _now()) and state in {"running", "stopping"})


def create_register_config_store(path: Path):
    return DatabaseRegisterConfigStore(
        resolve_database_url(path.parent),
        legacy_path=path,
    )


def _mask_password(url: str) -> str:
    return str(url or "")
