from __future__ import annotations

import json
from copy import deepcopy

from sqlalchemy import JSON, Column, String, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import sessionmaker

from services.application_database import (
    DatabaseBase,
    initialize_application_database,
    resolve_database_url,
)


class ImageTaskModel(DatabaseBase):
    __tablename__ = "image_tasks"

    owner_id = Column(String(256), primary_key=True)
    task_id = Column(String(160), primary_key=True)
    status = Column(String(24), nullable=False, index=True)
    updated_at = Column(String(64), nullable=False, index=True)
    payload = Column(JSON().with_variant(JSONB, "postgresql"), nullable=False)


class ImageTaskRepository:
    """Image task state lives in the application database, not image_tasks.json."""

    def __init__(self, database_url: str | None = None) -> None:
        self.database_url = database_url or resolve_database_url()
        self.engine = initialize_application_database(self.database_url)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)

    def _lock_write(self, session) -> None:
        if self.engine.dialect.name == "sqlite":
            session.execute(text("BEGIN IMMEDIATE"))
            return
        session.execute(text("LOCK TABLE image_tasks IN EXCLUSIVE MODE"))

    def load_payloads(self) -> list[dict]:
        session = self.Session()
        try:
            rows = session.query(ImageTaskModel).all()
            payloads: list[dict] = []
            for row in rows:
                if isinstance(row.payload, dict):
                    payloads.append(deepcopy(row.payload))
            return payloads
        finally:
            session.close()

    def replace_all(self, tasks: list[dict]) -> None:
        incoming: dict[tuple[str, str], dict] = {}
        for task in tasks:
            if not isinstance(task, dict):
                continue
            owner_id = str(task.get("owner_id") or "").strip()
            task_id = str(task.get("id") or "").strip()
            if not owner_id or not task_id:
                continue
            incoming[(owner_id, task_id)] = json.loads(
                json.dumps(task, ensure_ascii=False)
            )
        session = self.Session()
        try:
            self._lock_write(session)
            rows = session.query(ImageTaskModel).all()
            seen: set[tuple[str, str]] = set()
            for row in rows:
                key = (str(row.owner_id), str(row.task_id))
                payload = incoming.get(key)
                if payload is None:
                    session.delete(row)
                    continue
                row.status = str(payload.get("status") or "")
                row.updated_at = str(payload.get("updated_at") or "")
                row.payload = payload
                seen.add(key)
            for key, payload in incoming.items():
                if key in seen:
                    continue
                session.add(ImageTaskModel(
                    owner_id=key[0],
                    task_id=key[1],
                    status=str(payload.get("status") or ""),
                    updated_at=str(payload.get("updated_at") or ""),
                    payload=payload,
                ))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
