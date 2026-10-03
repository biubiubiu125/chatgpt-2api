from __future__ import annotations

import hashlib
import io
import logging
import time
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from threading import Lock
from typing import Iterator
from urllib.parse import quote, urlparse
from uuid import uuid4

from curl_cffi import requests
from fastapi import HTTPException
from PIL import Image, ImageOps

from services.config import DATA_DIR, config
from services.image_failure import ImageFailureError, image_failure
from services.json_file import read_json_object, write_json_file
from services.storage.file_lock import interprocess_lock
from utils.timezone import beijing_datetime_from_timestamp, beijing_now, beijing_now_str

IMAGE_INDEX_FILE = DATA_DIR / "image_index.json"
IMAGE_INDEX_LOCK = Lock()
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp"}
IMAGE_SYNC_MERGE_BATCH_SIZE = 64
IMAGE_MUTATION_BATCH_SIZE = 16


class ImageStorageError(RuntimeError):
    pass


class ImageBatchDeleteError(RuntimeError):
    def __init__(self, cause: Exception, completed_rels: set[str]) -> None:
        super().__init__(str(cause))
        self.cause = cause
        self.completed_rels = frozenset(completed_rels)


@dataclass(frozen=True)
class StoredImage:
    rel: str
    url: str
    storage: str
    size: int


@dataclass(frozen=True)
class LocalCopyRemoval:
    rel: str
    size: int
    remote_remains: bool


@dataclass(frozen=True)
class DeleteMutationResult:
    completed: bool
    removed: bool
    retry_remote: bool = False


def _clean(value: object) -> str:
    return str(value or "").strip()


def _raise_if_save_deadline_elapsed(deadline_monotonic: float | None) -> None:
    if (
        deadline_monotonic is not None
        and deadline_monotonic > 0
        and time.monotonic() >= deadline_monotonic
    ):
        raise ImageFailureError(
            "image request deadline exceeded before asset storage",
            failure=image_failure("task_interrupted"),
        )


def _now_iso() -> str:
    return beijing_now_str()


def _mtime_date(path: Path) -> str:
    return beijing_datetime_from_timestamp(path.stat().st_mtime).strftime("%Y-%m-%d")


def _mtime_datetime(path: Path) -> str:
    return beijing_datetime_from_timestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")


def image_media_mount_url(
    resource_path: str,
    mount: str,
    *,
    base_url: str = "",
    public_base_url: str | None = None,
) -> str:
    """Build an app media URL. ``public_base_url`` only changes the public host.

    The path always stays on ``/images/`` or ``/image-thumbnails/`` so the
    signature check on this service still runs. A prefix that already ends in
    ``/images`` is not doubled.
    """

    resource_path = str(resource_path or "").strip().lstrip("/")
    mount_name = str(mount or "").strip().strip("/")
    if public_base_url is None:
        public_base_url = str(config.get_image_storage_settings().get("public_base_url") or "")
    prefix = str(public_base_url or "").strip().rstrip("/")
    if prefix:
        parsed = urlparse(prefix)
        path = (parsed.path or "").rstrip("/")
        origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else prefix
        if path == "/images" or path.endswith("/images"):
            parent = path[: -len("/images")]
            root = f"{origin}{parent}/{mount_name}"
        else:
            root = f"{prefix}/{mount_name}"
    else:
        root = f"{str(base_url or config.base_url).strip().rstrip('/')}/{mount_name}"
    return f"{root}/{resource_path}" if resource_path else root


def normalize_image_relative_path(path: str) -> str:
    raw = str(path or "").strip()
    value = raw.replace("\\", "/")
    windows_path = PureWindowsPath(raw)
    if (
        not value
        or value.startswith("/")
        or bool(windows_path.drive)
        or bool(windows_path.root)
        or any(ord(char) < 32 for char in value)
    ):
        raise HTTPException(status_code=404, detail="image not found")
    parts = value.split("/")
    if any(part in {"", ".", ".."} or ":" in part for part in parts):
        raise HTTPException(status_code=404, detail="image not found")
    return PurePosixPath(*parts).as_posix()


def _image_dimensions(payload: bytes) -> tuple[int, int] | None:
    try:
        with Image.open(io.BytesIO(payload)) as image:
            return image.size
    except Exception:
        return None


def _is_image_rel(path: str) -> bool:
    try:
        safe_rel = normalize_image_relative_path(path)
    except HTTPException:
        return False
    return Path(safe_rel).suffix.lower() in IMAGE_EXTENSIONS


def image_local_path(relative_path: str, *, require_file: bool = False) -> Path:
    rel = normalize_image_relative_path(relative_path)
    root = config.images_dir.resolve()
    path = (root / rel).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="image not found") from exc
    if require_file and not path.is_file():
        raise HTTPException(status_code=404, detail="image not found")
    return path


def _read_json_object(path: Path) -> dict[str, object]:
    data = read_json_object(path, name=path.name)
    return data if isinstance(data, dict) else {}


def _write_json_object(path: Path, data: dict[str, object]) -> None:
    write_json_file(path, data)


class WebDAVClient:
    def __init__(self, settings: dict[str, object]):
        self.url = _clean(settings.get("webdav_url")).rstrip("/")
        self.username = _clean(settings.get("webdav_username"))
        self.password = _clean(settings.get("webdav_password"))
        self.root_path = _clean(settings.get("webdav_root_path")).strip("/")
        self.session = requests.Session()

    def _auth_kwargs(self) -> dict[str, object]:
        return {"auth": (self.username, self.password)} if self.username or self.password else {}

    def _request(self, method: str, url: str, **kwargs):
        response = self.session.request(method, url, timeout=30, **self._auth_kwargs(), **kwargs)
        if response.status_code >= 400 and not (method == "MKCOL" and response.status_code in {405}):
            raise ImageStorageError(f"WebDAV {method} failed: HTTP {response.status_code}")
        return response

    def remote_url(self, rel: str = "") -> str:
        parts = [
            part
            for part in [
                self.root_path,
                normalize_image_relative_path(rel) if rel else "",
            ]
            if part
        ]
        encoded = "/".join(quote(part, safe="") for item in parts for part in item.split("/") if part)
        return f"{self.url}/{encoded}" if encoded else self.url

    def ensure_dirs(self, rel: str) -> None:
        parts = [
            part
            for part in [
                self.root_path,
                Path(normalize_image_relative_path(rel)).parent.as_posix(),
            ]
            if part and part != "."
        ]
        current = self.url
        for item in "/".join(parts).split("/"):
            if not item:
                continue
            current = f"{current}/{quote(item, safe='')}"
            response = self.session.request("MKCOL", current, timeout=30, **self._auth_kwargs())
            if response.status_code in {201, 405}:
                continue
            if response.status_code >= 400:
                raise ImageStorageError(f"WebDAV MKCOL failed: HTTP {response.status_code}")

    def put(self, rel: str, payload: bytes, content_type: str = "image/png") -> str:
        self.ensure_dirs(rel)
        url = self.remote_url(rel)
        self._request("PUT", url, data=payload, headers={"Content-Type": content_type})
        return url

    def get(self, rel: str) -> bytes:
        response = self._request("GET", self.remote_url(rel))
        return bytes(response.content)

    def delete(self, rel: str) -> bool:
        response = self.session.request("DELETE", self.remote_url(rel), timeout=30, **self._auth_kwargs())
        if response.status_code in {200, 202, 204, 404}:
            return response.status_code != 404
        raise ImageStorageError(f"WebDAV DELETE failed: HTTP {response.status_code}")

    def test(self) -> dict[str, object]:
        if not self.url:
            return {"ok": False, "status": 0, "error": "WebDAV URL is required"}
        if urlparse(self.url).scheme not in {"http", "https"}:
            return {"ok": False, "status": 0, "error": "invalid WebDAV URL"}
        test_rel = ".chatgpt2api_webdav_test.txt"
        try:
            self.put(test_rel, b"chatgpt2api webdav test\n", content_type="text/plain")
            self.delete(test_rel)
            return {"ok": True, "status": 200, "error": None}
        except ImageStorageError as exc:
            return {"ok": False, "status": 0, "error": str(exc)}
        except Exception as exc:
            return {"ok": False, "status": 0, "error": str(exc) or exc.__class__.__name__}
        finally:
            self.session.close()


class ImageStorageService:
    def __init__(self, index_file: Path = IMAGE_INDEX_FILE):
        self.index_file = index_file
        self._index_lock = IMAGE_INDEX_LOCK
        self._index_file_lock = index_file.with_suffix(index_file.suffix + ".lock")
        self._item_lock_dir = index_file.with_suffix(index_file.suffix + ".item-locks")
        self._sync_file_lock = index_file.with_suffix(index_file.suffix + ".sync.lock")
        self._remote_delete_file = index_file.with_suffix(index_file.suffix + ".remote-deletes.json")

    @contextmanager
    def _index_guard(self) -> Iterator[None]:
        with self._index_lock:
            with interprocess_lock(self._index_file_lock):
                yield

    def _item_lock_path(self, rel: str) -> Path:
        safe_rel = normalize_image_relative_path(rel)
        stripe = hashlib.sha256(safe_rel.encode("utf-8")).hexdigest()[:2]
        return self._item_lock_dir / f"{stripe}.lock"

    @contextmanager
    def _item_guard(self, rel: str) -> Iterator[None]:
        with interprocess_lock(self._item_lock_path(rel)):
            yield

    @contextmanager
    def _item_guards(self, rels: list[str] | dict[str, object]) -> Iterator[None]:
        lock_paths = sorted({self._item_lock_path(rel) for rel in rels}, key=str)
        with ExitStack() as stack:
            for lock_path in lock_paths:
                stack.enter_context(interprocess_lock(lock_path))
            yield

    def settings(self) -> dict[str, object]:
        return config.get_image_storage_settings()

    def mode(self) -> str:
        return _clean(self.settings().get("mode")) or "local"

    def _load_index(self) -> dict[str, dict[str, object]]:
        raw = _read_json_object(self.index_file)
        items = raw.get("items")
        if not isinstance(items, dict):
            return {}
        return {str(key): value for key, value in items.items() if isinstance(value, dict)}

    def _load_clean_index(self) -> dict[str, dict[str, object]]:
        items = self._load_index()
        clean: dict[str, dict[str, object]] = {}
        for rel, item in items.items():
            if not _is_image_rel(rel):
                continue
            storage = _clean(item.get("storage"))
            item = dict(item)
            if "local" not in item and storage in {"local", "both"}:
                item["local"] = True
            if "webdav" not in item and storage in {"webdav", "both"}:
                item["webdav"] = True
            clean[rel] = item
        return clean

    def _save_index(self, items: dict[str, dict[str, object]]) -> None:
        _write_json_object(self.index_file, {"items": items})

    @staticmethod
    def _new_generation() -> str:
        return uuid4().hex

    @staticmethod
    def _item_generation(item: dict[str, object] | None) -> str:
        return _clean((item or {}).get("generation"))

    @staticmethod
    def _tombstone_matches(
        current: dict[str, object] | None,
        expected: dict[str, object],
    ) -> bool:
        return bool(
            isinstance(current, dict)
            and _clean(current.get("op_id"))
            and _clean(current.get("op_id")) == _clean(expected.get("op_id"))
        )

    @classmethod
    def _asset_generation_matches(
        cls,
        current: dict[str, object] | None,
        tombstone: dict[str, object],
        *,
        allow_missing: bool,
    ) -> bool:
        if current is None:
            return allow_missing
        return cls._item_generation(current) == _clean(tombstone.get("generation"))

    @staticmethod
    def _delete_tombstone(
        *,
        generation: str,
        scope: str,
        remote: bool,
        r2_key: str = "",
        webdav: bool = False,
    ) -> dict[str, object]:
        tombstone: dict[str, object] = {
            "op_id": uuid4().hex,
            "generation": generation,
            "scope": scope,
            "remote": remote,
            "requested_at": _now_iso(),
        }
        if r2_key:
            tombstone["r2_key"] = r2_key
        if webdav:
            tombstone["webdav"] = True
        return tombstone

    @staticmethod
    def _tombstone_r2_key(item: dict[str, object] | None) -> str:
        if not isinstance(item, dict):
            return ""
        return _clean(item.get("r2_key"))

    @classmethod
    def _tombstone_needs_webdav(cls, tombstone: dict[str, object]) -> bool:
        if tombstone.get("webdav"):
            return True
        return bool(tombstone.get("remote")) and not cls._tombstone_r2_key(tombstone)

    @staticmethod
    def _orphan_r2_rel(r2_key: str) -> str:
        digest = hashlib.sha256(r2_key.encode("utf-8")).hexdigest()
        return f"r2-orphans/{digest}.png"

    def _detach_pending_r2_key_locked(
        self,
        pending: dict[str, dict[str, object]],
        rel: str,
        new_key: str,
    ) -> str:
        """Move a different pending key off this image path.

        The caller holds the index lock and must save ``pending`` in the same
        transaction as the new catalog row. The object is not deleted here.
        """
        existing = pending.get(rel)
        if not isinstance(existing, dict):
            return ""
        old_key = self._tombstone_r2_key(existing)
        if old_key and old_key != new_key:
            self._stage_orphan_r2_locked(
                pending,
                old_key,
                _clean(existing.get("generation")) or self._new_generation(),
            )
        pending.pop(rel, None)
        return old_key if old_key != new_key else ""

    def _pending_r2_key_is_stale(
        self,
        item: dict[str, object],
        tombstone: dict[str, object],
    ) -> bool:
        """A tombstone for a replaced object must not delete the current row."""
        key = self._tombstone_r2_key(tombstone)
        if not key:
            return False
        if not self._asset_generation_matches(item, tombstone, allow_missing=False):
            return True
        item_key = self._tombstone_r2_key(item)
        return bool(item_key) and item_key != key

    def _stage_orphan_r2_locked(
        self,
        pending: dict[str, dict[str, object]],
        r2_key: str,
        generation: str,
    ) -> None:
        key = _clean(r2_key)
        if not key:
            return
        orphan_rel = self._orphan_r2_rel(key)
        current = pending.get(orphan_rel)
        if not isinstance(current, dict) or self._tombstone_r2_key(current) != key:
            pending[orphan_rel] = self._delete_tombstone(
                generation=_clean(generation),
                scope="asset",
                remote=True,
                r2_key=key,
            )

    def _remember_orphan_r2(self, r2_key: str, generation: str) -> None:
        key = _clean(r2_key)
        if not key:
            return
        with self._index_guard():
            pending = self._load_remote_delete_pending()
            self._stage_orphan_r2_locked(pending, key, generation)
            self._save_remote_delete_pending(pending)

    def _stage_detached_r2_key(
        self,
        pending: dict[str, dict[str, object]],
        item: dict[str, object],
        generation: str,
    ) -> str:
        """Remove an R2 key from a row that is now a WebDAV copy.

        The caller holds the index lock and must save ``pending``. The key is
        tombstoned first so a failed bucket delete can be retried without
        leaving the WebDAV URL labeled as R2.
        """
        key = self._tombstone_r2_key(item)
        item.pop("r2_key", None)
        if not key:
            return ""
        self._stage_orphan_r2_locked(pending, key, generation)
        return key

    def _finish_detached_r2_keys(self, keys: list[str]) -> None:
        if not keys:
            return
        from services.image_r2 import delete_image_object

        settings = self.settings()
        for key in keys:
            try:
                delete_image_object(settings, key)
            except Exception:
                logging.getLogger(__name__).exception(
                    "failed to delete replaced r2 object %s",
                    key,
                )
                continue
            orphan_rel = self._orphan_r2_rel(key)
            with self._index_guard():
                pending = self._load_remote_delete_pending()
                if self._tombstone_r2_key(pending.get(orphan_rel)) != key:
                    continue
                pending.pop(orphan_rel, None)
                self._save_remote_delete_pending(pending)

    def _replaced_catalog_r2_key(
        self,
        item: dict[str, object] | None,
        new_key: str,
    ) -> str:
        key = self._tombstone_r2_key(item)
        if not key or key == new_key:
            return ""
        return key

    def _stage_replaced_r2_keys_locked(
        self,
        pending: dict[str, dict[str, object]],
        rel: str,
        previous: dict[str, object] | None,
        new_key: str,
    ) -> list[str]:
        """Tombstone R2 objects this catalog row is about to stop naming.

        The caller holds the index lock and must save ``pending`` before
        returning. Objects are deleted only after that save.
        """
        keys: list[str] = []
        previous_key = self._replaced_catalog_r2_key(previous, new_key)
        if previous_key:
            generation = ""
            if isinstance(previous, dict):
                generation = self._item_generation(previous)
            self._stage_orphan_r2_locked(
                pending,
                previous_key,
                generation or self._new_generation(),
            )
            keys.append(previous_key)
        if rel in pending:
            pending_key = self._detach_pending_r2_key_locked(pending, rel, new_key)
            if pending_key and pending_key not in keys:
                keys.append(pending_key)
        return keys

    def _preserve_replaced_r2_key(self, rel: str, previous_key: str) -> None:
        """Keep a catalog key that was overwritten if the pending save failed.

        The new row is already committed, so the replaced object must be
        tombstoned and deleted. A key the catalog still names is left alone.
        An unreadable index is also left alone.
        """
        key = _clean(previous_key)
        if not key:
            return
        try:
            with self._index_guard():
                current = self._tombstone_r2_key(self._load_clean_index().get(rel))
                if current == key:
                    return
                try:
                    pending = self._load_remote_delete_pending()
                    orphan_rel = self._orphan_r2_rel(key)
                    if self._tombstone_r2_key(pending.get(orphan_rel)) != key:
                        self._stage_orphan_r2_locked(pending, key, self._new_generation())
                        self._save_remote_delete_pending(pending)
                except Exception:
                    logging.getLogger(__name__).exception(
                        "failed to record replaced r2 object %s",
                        key,
                    )
        except Exception:
            logging.getLogger(__name__).exception(
                "failed to read image index for replaced r2 object %s",
                key,
            )
            return
        try:
            self._finish_detached_r2_keys([key])
        except Exception:
            logging.getLogger(__name__).exception(
                "failed to delete replaced r2 object %s",
                key,
            )

    def _load_remote_delete_pending(self) -> dict[str, dict[str, object]]:
        raw = _read_json_object(self._remote_delete_file)
        values = raw.get("items")
        if not isinstance(values, dict):
            return {}
        pending: dict[str, dict[str, object]] = {}
        for value, tombstone in values.items():
            try:
                safe_rel = normalize_image_relative_path(str(value or ""))
            except HTTPException:
                continue
            if not _is_image_rel(safe_rel) or not isinstance(tombstone, dict):
                continue
            op_id = _clean(tombstone.get("op_id"))
            scope = _clean(tombstone.get("scope"))
            if not op_id or scope not in {"asset", "remote"}:
                continue
            loaded = {
                "op_id": op_id,
                "generation": _clean(tombstone.get("generation")),
                "scope": scope,
                "remote": bool(tombstone.get("remote")),
                "requested_at": _clean(tombstone.get("requested_at")),
            }
            r2_key = _clean(tombstone.get("r2_key"))
            if r2_key:
                loaded["r2_key"] = r2_key
            if tombstone.get("webdav"):
                loaded["webdav"] = True
            pending[safe_rel] = loaded
        return pending

    def _save_remote_delete_pending(self, items: dict[str, dict[str, object]]) -> None:
        _write_json_object(
            self._remote_delete_file,
            {"items": {rel: items[rel] for rel in sorted(items)}},
        )

    def _sync_item(
        self,
        path: Path,
        rel: str,
        item: dict[str, object],
        payload: bytes,
        remote_url: str,
    ) -> dict[str, object]:
        dimensions = _image_dimensions(payload)
        return {
            "rel": rel,
            "path": rel,
            "name": path.name,
            "date": "-".join(rel.split("/")[:3]) if len(rel.split("/")) >= 4 else _mtime_date(path),
            "size": len(payload),
            "created_at": str(item.get("created_at") or _mtime_datetime(path)),
            "storage": "both",
            "local": True,
            "webdav": True,
            "remote_url": remote_url,
            "generation": self._item_generation(item) or self._new_generation(),
            "_content_sha256": hashlib.sha256(payload).hexdigest(),
            **({"width": dimensions[0], "height": dimensions[1]} if dimensions else {}),
        }

    def _public_url(self, rel: str, base_url: str | None = None) -> str:
        from services.media_access import with_media_access

        resource_path = normalize_image_relative_path(rel)
        settings = self.settings()
        url = image_media_mount_url(
            resource_path,
            "images",
            base_url=base_url or config.base_url,
            public_base_url=_clean(settings.get("public_base_url")),
        )
        return with_media_access(url, resource_path)

    def make_relative_path(self, image_data: bytes) -> str:
        file_hash = hashlib.md5(image_data).hexdigest()
        filename = f"{int(time.time())}_{file_hash}.png"
        now = beijing_now()
        relative_dir = Path(now.strftime("%Y"), now.strftime("%m"), now.strftime("%d"))
        return f"{relative_dir.as_posix()}/{filename}"

    def save(
        self,
        image_data: bytes,
        base_url: str | None = None,
        *,
        deadline_monotonic: float | None = None,
    ) -> StoredImage:
        _raise_if_save_deadline_elapsed(deadline_monotonic)
        rel = self.make_relative_path(image_data)
        with self._item_guard(rel):
            # Once the physical mutation starts, finish the catalog commit so a
            # deadline cannot leave an unindexed local or remote asset behind.
            _raise_if_save_deadline_elapsed(deadline_monotonic)
            mode = self.mode()
            if mode == "r2":
                return self._save_r2_image(image_data, rel, base_url)
            if mode not in {"local", "webdav", "both"}:
                mode = "local"
            stored_local = False
            stored_webdav = False
            remote_url = ""

            if mode in {"local", "both"}:
                path = image_local_path(rel)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(image_data)
                stored_local = True

            if mode in {"webdav", "both"}:
                client = WebDAVClient(self.settings())
                try:
                    remote_url = client.put(rel, image_data)
                    stored_webdav = True
                finally:
                    client.session.close()

            dimensions = _image_dimensions(image_data)
            item = {
                "rel": rel,
                "path": rel,
                "name": Path(rel).name,
                "date": "-".join(rel.split("/")[:3]),
                "size": len(image_data),
                "created_at": _now_iso(),
                "storage": "both" if stored_local and stored_webdav else ("webdav" if stored_webdav else "local"),
                "local": stored_local,
                "webdav": stored_webdav,
                "remote_url": remote_url,
                "generation": self._new_generation(),
            }
            if dimensions:
                item["width"], item["height"] = dimensions
            previous_key = ""
            old_keys: list[str] = []
            try:
                with self._index_guard():
                    items = self._load_clean_index()
                    previous = items.get(rel)
                    previous_key = self._replaced_catalog_r2_key(
                        previous if isinstance(previous, dict) else None,
                        "",
                    )
                    items[rel] = item
                    self._save_index(items)
                    pending = self._load_remote_delete_pending()
                    had_pending = rel in pending
                    old_keys = self._stage_replaced_r2_keys_locked(
                        pending,
                        rel,
                        previous if isinstance(previous, dict) else None,
                        "",
                    )
                    if previous_key or had_pending:
                        self._save_remote_delete_pending(pending)
            except Exception:
                self._preserve_replaced_r2_key(rel, previous_key)
                raise
            if old_keys:
                self._finish_detached_r2_keys(old_keys)
            self._store_thumbnail(rel, image_data)
        return StoredImage(rel=rel, url=self._public_url(rel, base_url), storage=str(item["storage"]), size=len(image_data))

    def get_bytes(self, rel: str) -> bytes:
        safe_rel = normalize_image_relative_path(rel)
        if not _is_image_rel(safe_rel):
            raise HTTPException(status_code=404, detail="image not found")
        # File paths are not an authorization boundary: only assets registered
        # in the Gallery index may be read through this service.
        with self._index_guard():
            item = self._load_clean_index().get(safe_rel)
        if not isinstance(item, dict):
            raise HTTPException(status_code=404, detail="image not found")
        path = image_local_path(safe_rel)
        if bool(item.get("local")) and path.is_file():
            return path.read_bytes()
        if bool(item.get("webdav")):
            client = WebDAVClient(self.settings())
            try:
                try:
                    return client.get(safe_rel)
                except Exception:
                    # An older sync could leave both a WebDAV copy and an R2
                    # key. A WebDAV miss must not hide the bucket object.
                    if not self._tombstone_r2_key(item):
                        raise
            finally:
                client.session.close()
        r2_key = self._tombstone_r2_key(item)
        if r2_key:
            from services.backup_service import BackupError
            from services.image_r2 import ImageObjectNotFound, read_image_object

            try:
                return read_image_object(self.settings(), r2_key)
            except ImageObjectNotFound as exc:
                raise HTTPException(status_code=404, detail="image not found") from exc
            except BackupError as exc:
                raise HTTPException(status_code=502, detail="image storage is unavailable") from exc
        raise HTTPException(status_code=404, detail="image not found")

    def record_genbox_push(self, rel: str, *, status: str, sha256: str, updated_at: str) -> dict[str, str]:
        safe_rel = normalize_image_relative_path(rel)
        if not _is_image_rel(safe_rel):
            raise HTTPException(status_code=404, detail="image not found")
        with self._item_guard(safe_rel), self._index_guard():
            items = self._load_clean_index()
            item = items.get(safe_rel)
            if item is None:
                raise HTTPException(status_code=404, detail="image not found")
            item["genbox_push"] = {
                "status": status,
                "sha256": sha256,
                "updated_at": updated_at,
            }
            items[safe_rel] = item
            self._save_index(items)
        return dict(item["genbox_push"])

    def get_genbox_push_state(self, rel: str) -> dict[str, str] | None:
        safe_rel = normalize_image_relative_path(rel)
        if not _is_image_rel(safe_rel):
            return None
        with self._index_guard():
            items = self._load_clean_index()
            raw = items.get(safe_rel, {}).get("genbox_push")
        if not isinstance(raw, dict):
            return None
        status = _clean(raw.get("status"))
        sha256 = _clean(raw.get("sha256"))
        updated_at = _clean(raw.get("updated_at"))
        if not status or not sha256 or not updated_at:
            return None
        return {"status": status, "sha256": sha256, "updated_at": updated_at}

    def exists(self, rel: str) -> bool:
        return bool(self.existing_paths([rel]))

    def existing_paths(self, rels: list[str]) -> set[str]:
        safe_rels = list(dict.fromkeys(
            safe_rel
            for rel in rels
            if _is_image_rel(safe_rel := normalize_image_relative_path(rel))
        ))
        existing = {
            safe_rel
            for safe_rel in safe_rels
            if image_local_path(safe_rel).is_file()
        }
        remote_rels = [safe_rel for safe_rel in safe_rels if safe_rel not in existing]
        if not remote_rels:
            return existing

        items = self._load_clean_index()
        existing.update(
            safe_rel
            for safe_rel in remote_rels
            if items.get(safe_rel, {}).get("webdav")
            or self._tombstone_r2_key(items.get(safe_rel))
        )
        return existing

    def has_local(self, rel: str) -> bool:
        safe_rel = normalize_image_relative_path(rel)
        with self._index_guard():
            item = self._load_clean_index().get(safe_rel)
        return bool(isinstance(item, dict) and item.get("local")) and image_local_path(safe_rel).is_file()

    @staticmethod
    def _catalog_size_matches_local(item: dict[str, object], local_size: int) -> bool:
        indexed_size = item.get("size")
        if indexed_size in {None, ""}:
            return True
        try:
            return int(indexed_size) == local_size
        except (TypeError, ValueError):
            return False

    def _delete_local_copies(
        self,
        rels: list[str],
        *,
        required_bytes: int | None = None,
        dry_run: bool = False,
        disk_target: bool = False,
    ) -> list[LocalCopyRemoval]:
        safe_rels = list(dict.fromkeys(
            safe_rel
            for rel in rels
            if _is_image_rel(safe_rel := normalize_image_relative_path(rel))
        ))
        target = None if required_bytes is None else max(0, int(required_bytes))
        if target == 0:
            return []

        removals: list[LocalCopyRemoval] = []
        reclaimed = 0
        for offset in range(0, len(safe_rels), IMAGE_MUTATION_BATCH_SIZE):
            if target is not None and reclaimed >= target:
                break
            batch = safe_rels[offset:offset + IMAGE_MUTATION_BATCH_SIZE]
            with self._item_guards(batch):
                with self._index_guard():
                    snapshot = self._load_clean_index()

                selected: list[tuple[str, int]] = []
                for safe_rel in batch:
                    if target is not None and reclaimed >= target:
                        break
                    item = snapshot.get(safe_rel, {})
                    # Disk-target cleanup is explicitly freeing the oldest
                    # files. A pending sync or a stale catalog size must not
                    # keep that file and push the delete onto a newer one.
                    if not disk_target and item.get("remote_sync_pending"):
                        continue
                    # R2 objects are removed by delete_many. Dropping only the
                    # local file here would leave the bucket object with no key.
                    if not dry_run and self._tombstone_r2_key(item):
                        continue
                    path = image_local_path(safe_rel)
                    try:
                        local_size = path.stat().st_size
                    except OSError:
                        continue
                    if not disk_target and not self._catalog_size_matches_local(item, local_size):
                        continue
                    if not dry_run:
                        try:
                            path.unlink()
                        except OSError:
                            continue
                    selected.append((safe_rel, local_size))
                    reclaimed += local_size

                if not selected:
                    continue
                if dry_run:
                    removals.extend(
                        LocalCopyRemoval(
                            rel=rel,
                            size=size,
                            remote_remains=bool(snapshot.get(rel, {}).get("webdav")),
                        )
                        for rel, size in selected
                    )
                    continue

                with self._index_guard():
                    items = self._load_clean_index()
                    changed = False
                    for rel, size in selected:
                        item = items.get(rel)
                        remote_remains = bool(item and item.get("webdav"))
                        removals.append(LocalCopyRemoval(rel, size, remote_remains))
                        if item is None:
                            continue
                        if remote_remains:
                            # The local bytes that still needed uploading are
                            # gone. Keeping the flag would make the next sync
                            # look unfinished even though only the WebDAV copy
                            # remains.
                            kept = {
                                **item,
                                "local": False,
                                "storage": "webdav",
                            }
                            kept.pop("remote_sync_pending", None)
                            items[rel] = kept
                        else:
                            items.pop(rel, None)
                        changed = True
                    if changed:
                        self._save_index(items)
        return removals

    def delete_local_copies(self, rels: list[str]) -> dict[str, bool]:
        return {
            removal.rel: removal.remote_remains
            for removal in self._delete_local_copies(rels)
        }

    def delete_local_copies_until(
        self,
        rels: list[str],
        required_bytes: int,
        *,
        dry_run: bool = False,
        disk_target: bool = False,
    ) -> list[LocalCopyRemoval]:
        return self._delete_local_copies(
            rels,
            required_bytes=required_bytes,
            dry_run=dry_run,
            disk_target=disk_target,
        )

    def list_items(
        self,
        base_url: str,
        start_date: str = "",
        end_date: str = "",
        *,
        refresh_index: bool = True,
        verify_existing: bool = True,
    ) -> list[dict[str, object]]:
        with self._index_guard():
            indexed = self._load_clean_index()
            root = config.images_dir
            changed = False
            if refresh_index:
                for path in root.rglob("*"):
                    if not path.is_file() or not _is_image_rel(path.name):
                        continue
                    rel = path.relative_to(root).as_posix()
                    if rel in indexed:
                        continue
                    dimensions = None
                    try:
                        dimensions = _image_dimensions(path.read_bytes())
                    except Exception:
                        dimensions = None
                    indexed[rel] = {
                        "rel": rel,
                        "path": rel,
                        "name": path.name,
                        "date": "-".join(rel.split("/")[:3]) if len(rel.split("/")) >= 4 else _mtime_date(path),
                        "size": path.stat().st_size,
                        "created_at": _mtime_datetime(path),
                        "storage": "local",
                        "local": True,
                        "webdav": False,
                        "generation": self._new_generation(),
                        **({"width": dimensions[0], "height": dimensions[1]} if dimensions else {}),
                    }
                    changed = True

            items: list[dict[str, object]] = []
            for rel, item in list(indexed.items()):
                if not _is_image_rel(rel):
                    indexed.pop(rel, None)
                    changed = True
                    continue
                if not self._item_generation(item):
                    item = {**item, "generation": self._new_generation()}
                    indexed[rel] = item
                    changed = True
                if verify_existing:
                    local_path = image_local_path(rel)
                    local = local_path.is_file()
                    webdav = bool(item.get("webdav"))
                    r2_key = self._tombstone_r2_key(item)
                    if not local and not webdav and not r2_key:
                        indexed.pop(rel, None)
                        changed = True
                        continue
                    if r2_key:
                        storage = "r2"
                    else:
                        storage = "both" if local and webdav else ("webdav" if webdav else "local")
                    local_size: int | None = None
                    if local:
                        try:
                            local_size = local_path.stat().st_size
                        except OSError:
                            local = False
                            storage = "r2" if r2_key else ("webdav" if webdav else "local")
                    if not local and not webdav and not r2_key:
                        indexed.pop(rel, None)
                        changed = True
                        continue
                    indexed_size = item.get("size")
                    size_changed = (
                        local_size is not None
                        and indexed_size not in {None, ""}
                        and not self._catalog_size_matches_local(item, local_size)
                    )
                    size_needs_update = (
                        local_size is not None
                        and (indexed_size in {None, ""} or size_changed)
                    )
                    if (
                        item.get("local") != local
                        or item.get("storage") != storage
                        or size_needs_update
                    ):
                        item = {
                            **item,
                            "local": local,
                            "storage": storage,
                        }
                        if local_size is not None:
                            item["size"] = local_size
                        if size_changed and webdav:
                            item["remote_sync_pending"] = True
                        indexed[rel] = item
                        changed = True
                day = str(item.get("date") or "")
                if start_date and day < start_date:
                    continue
                if end_date and day > end_date:
                    continue
                items.append({
                    **item,
                    "rel": rel,
                    "path": rel,
                    "url": self._public_url(rel, base_url),
                })
            if changed:
                self._save_index(indexed)
        items.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
        return items

    def delete(self, rel: str) -> bool:
        safe_rel = normalize_image_relative_path(rel)
        try:
            return safe_rel in self.delete_many([safe_rel])
        except ImageBatchDeleteError as exc:
            raise exc.cause from exc

    def _prepare_delete_batch(
        self,
        rels: list[str],
    ) -> dict[str, dict[str, object]]:
        planned: dict[str, dict[str, object]] = {}
        with self._item_guards(rels):
            with self._index_guard():
                items = self._load_clean_index()
                pending = self._load_remote_delete_pending()
                catalog_changed = False
                for rel in rels:
                    item = items.get(rel)
                    existing = pending.get(rel)
                    generation = self._item_generation(item)
                    if item is not None and not generation:
                        generation = self._new_generation()
                        items[rel] = {**item, "generation": generation}
                        item = items[rel]
                        catalog_changed = True
                    if item is None and existing is not None:
                        generation = _clean(existing.get("generation"))
                    r2_key = self._tombstone_r2_key(item) or self._tombstone_r2_key(existing)
                    has_webdav = bool(
                        (isinstance(item, dict) and item.get("webdav"))
                        or (isinstance(existing, dict) and existing.get("webdav"))
                    )
                    tombstone = self._delete_tombstone(
                        generation=generation,
                        scope="asset",
                        remote=bool(
                            (item and (item.get("webdav") or r2_key))
                            or (existing and existing.get("remote"))
                            or r2_key
                        ),
                        r2_key=r2_key,
                        webdav=has_webdav,
                    )
                    pending[rel] = tombstone
                    planned[rel] = tombstone
                if catalog_changed:
                    self._save_index(items)
                self._save_remote_delete_pending(pending)
        return planned

    def _mutate_delete_tombstone(
        self,
        rel: str,
        tombstone: dict[str, object],
        client: WebDAVClient | None,
    ) -> tuple[DeleteMutationResult, Exception | None]:
        with self._item_guard(rel):
            with self._index_guard():
                current = self._load_clean_index().get(rel)
                durable = self._load_remote_delete_pending().get(rel)
            if (
                not self._tombstone_matches(durable, tombstone)
                or not self._asset_generation_matches(
                    current,
                    tombstone,
                    allow_missing=True,
                )
            ):
                return DeleteMutationResult(completed=False, removed=False), None

            removed = False
            path = image_local_path(rel)
            if path.is_file():
                try:
                    path.unlink()
                except Exception as exc:
                    if path.exists():
                        return DeleteMutationResult(completed=False, removed=False), exc
                removed = True

            r2_key = self._tombstone_r2_key(tombstone)
            if r2_key:
                try:
                    from services.image_r2 import delete_image_object

                    delete_image_object(self.settings(), r2_key)
                    removed = True
                except Exception as exc:
                    return (
                        DeleteMutationResult(
                            completed=removed,
                            removed=removed,
                            retry_remote=True,
                        ),
                        None if removed else exc,
                    )
            if self._tombstone_needs_webdav(tombstone):
                if client is None:
                    return (
                        DeleteMutationResult(
                            completed=removed,
                            removed=removed,
                            retry_remote=True,
                        ),
                        ImageStorageError("WebDAV client is unavailable"),
                    )
                try:
                    removed = client.delete(rel) or removed
                except Exception as exc:
                    return (
                        DeleteMutationResult(
                            completed=removed,
                            removed=removed,
                            retry_remote=True,
                        ),
                        None if removed else exc,
                    )

            return DeleteMutationResult(completed=True, removed=removed), None

    def _finalize_delete_batch(
        self,
        planned: dict[str, dict[str, object]],
        results: dict[str, DeleteMutationResult],
    ) -> None:
        with self._item_guards(planned):
            with self._index_guard():
                items = self._load_clean_index()
                pending = self._load_remote_delete_pending()
                catalog_changed = False
                pending_changed = False
                for rel, tombstone in planned.items():
                    durable = pending.get(rel)
                    if not self._tombstone_matches(durable, tombstone):
                        continue
                    current = items.get(rel)
                    generation_matches = self._asset_generation_matches(
                        current,
                        tombstone,
                        allow_missing=True,
                    )
                    result = results.get(rel)
                    if result is not None and result.completed and generation_matches:
                        if current is not None:
                            items.pop(rel, None)
                            catalog_changed = True
                    if (
                        result is None
                        or not generation_matches
                        or not result.retry_remote
                    ):
                        stale_key = self._tombstone_r2_key(tombstone)
                        if (
                            not generation_matches
                            and isinstance(current, dict)
                            and stale_key
                            and stale_key != self._tombstone_r2_key(current)
                        ):
                            self._stage_orphan_r2_locked(
                                pending,
                                stale_key,
                                _clean(tombstone.get("generation")) or self._new_generation(),
                            )
                        pending.pop(rel, None)
                        pending_changed = True
                if catalog_changed:
                    self._save_index(items)
                if pending_changed:
                    self._save_remote_delete_pending(pending)

    def delete_many(self, rels: list[str]) -> set[str]:
        safe_rels = list(dict.fromkeys(normalize_image_relative_path(rel) for rel in rels))
        if not safe_rels:
            return set()

        removed_rels: set[str] = set()
        completed_rels: set[str] = set()
        client: WebDAVClient | None = None
        terminal_error: Exception | None = None
        try:
            for offset in range(0, len(safe_rels), IMAGE_MUTATION_BATCH_SIZE):
                batch = safe_rels[offset:offset + IMAGE_MUTATION_BATCH_SIZE]
                try:
                    planned = self._prepare_delete_batch(batch)
                except Exception as exc:
                    terminal_error = exc
                    break
                results: dict[str, DeleteMutationResult] = {}
                batch_error: Exception | None = None
                webdav_error: Exception | None = None
                if client is None and any(self._tombstone_needs_webdav(item) for item in planned.values()):
                    try:
                        client = WebDAVClient(self.settings())
                    except Exception as exc:
                        webdav_error = exc
                if webdav_error is not None and all(
                    self._tombstone_needs_webdav(item) for item in planned.values()
                ):
                    batch_error = webdav_error

                if batch_error is None:
                    for safe_rel, tombstone in planned.items():
                        if webdav_error is not None and self._tombstone_needs_webdav(tombstone):
                            results[safe_rel] = DeleteMutationResult(
                                completed=False,
                                removed=False,
                                retry_remote=True,
                            )
                            batch_error = webdav_error
                            continue
                        try:
                            result, error = self._mutate_delete_tombstone(
                                safe_rel,
                                tombstone,
                                client,
                            )
                        except Exception as exc:
                            results[safe_rel] = DeleteMutationResult(
                                completed=False,
                                removed=False,
                                retry_remote=True,
                            )
                            batch_error = exc
                            break
                        results[safe_rel] = result
                        if error is not None:
                            batch_error = error
                            break

                completed_rels.update(
                    rel for rel, result in results.items() if result.completed
                )
                removed_rels.update(
                    rel for rel, result in results.items() if result.removed
                )
                try:
                    self._finalize_delete_batch(planned, results)
                except Exception as exc:
                    batch_error = exc
                if batch_error is not None:
                    terminal_error = batch_error
                    break
        finally:
            if client is not None:
                client.session.close()

        if terminal_error is not None:
            raise ImageBatchDeleteError(terminal_error, completed_rels) from terminal_error
        return removed_rels

    def rels_with_r2_key(self, rels: list[str]) -> set[str]:
        wanted: list[str] = []
        for rel in rels:
            try:
                safe_rel = normalize_image_relative_path(rel)
            except HTTPException:
                continue
            if _is_image_rel(safe_rel):
                wanted.append(safe_rel)
        if not wanted:
            return set()
        with self._index_guard():
            items = self._load_clean_index()
        return {rel for rel in wanted if self._tombstone_r2_key(items.get(rel))}

    def retry_pending_r2_deletes(self) -> set[str]:
        """Replay tombstones that already have an R2 object key.

        WebDAV sync does not invent keys, and R2 mode does not run that sync.
        Retention and disk cleanup call this so a failed object delete is not
        left in the bucket.
        """
        with self._index_guard():
            pending = self._load_remote_delete_pending()
            items = self._load_clean_index()
            delete_rels: list[str] = []
            changed = False
            seen = set(pending)
            for rel, tombstone in list(pending.items()):
                key = self._tombstone_r2_key(tombstone)
                if not key:
                    continue
                item = items.get(rel)
                if isinstance(item, dict) and self._pending_r2_key_is_stale(item, tombstone):
                    self._stage_orphan_r2_locked(
                        pending,
                        key,
                        _clean(tombstone.get("generation")) or self._new_generation(),
                    )
                    pending.pop(rel, None)
                    changed = True
                    continue
                delete_rels.append(rel)
            if changed:
                delete_rels.extend(rel for rel in pending if rel not in seen)
                self._save_remote_delete_pending(pending)
        if not delete_rels:
            return set()
        try:
            return set(self.delete_many(delete_rels))
        except ImageBatchDeleteError as exc:
            return set(exc.completed_rels)

    @staticmethod
    def _compress_png(payload: bytes) -> bytes:
        output = io.BytesIO()
        with Image.open(io.BytesIO(payload)) as image:
            image = ImageOps.exif_transpose(image)
            image.save(output, format="PNG", optimize=True)
        return output.getvalue()

    def _store_thumbnail(self, rel: str, image_data: bytes) -> None:
        safe_rel = normalize_image_relative_path(rel)
        target = config.image_thumbnails_dir / safe_rel
        legacy = config.image_thumbnails_dir / f"{safe_rel}.png"
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            with Image.open(io.BytesIO(image_data)) as image:
                image = ImageOps.exif_transpose(image)
                if image.mode not in {"RGB", "RGBA"}:
                    image = image.convert("RGBA" if "A" in image.getbands() else "RGB")
                image.thumbnail((320, 320), Image.Resampling.LANCZOS)
                image.save(target, format="PNG", optimize=True)
            if legacy != target and legacy.is_file():
                legacy.unlink()
        except Exception:
            logging.getLogger(__name__).exception("failed to store image thumbnail for %s", rel)

    @staticmethod
    def _remove_thumbnail(rel: str) -> None:
        safe_rel = normalize_image_relative_path(rel)
        for path in (
            config.image_thumbnails_dir / f"{safe_rel}.png",
            config.image_thumbnails_dir / safe_rel,
        ):
            if path.is_file():
                try:
                    path.unlink()
                except OSError:
                    pass

    def _replace_compressed_r2(
        self,
        rel: str,
        path: Path,
        original: bytes,
        compressed: bytes,
    ) -> int | None:
        """Republish a smaller R2 object. None means this row is not R2."""
        from services.image_r2 import delete_image_object, public_image_url, publish_image_bytes

        with self._index_guard():
            current = dict(self._load_clean_index().get(rel) or {})
        old_key = self._tombstone_r2_key(current)
        if not old_key:
            return None

        settings = self.settings()
        try:
            new_key = publish_image_bytes(settings, compressed)
        except Exception:
            logging.getLogger(__name__).exception(
                "failed to publish compressed r2 object for %s",
                rel,
            )
            return 0
        new_url = public_image_url(settings, new_key)
        retired_key = old_key
        old_pending_key = ""
        had_local = path.is_file()
        temp_path = path.with_name(f".{path.name}.compress.tmp")
        try:
            if had_local:
                temp_path.write_bytes(compressed)
                temp_path.replace(path)
                stat = path.stat()
                if stat.st_size != len(compressed):
                    raise OSError("compressed image size changed")
            dimensions = _image_dimensions(compressed)
            self._remove_thumbnail(rel)
            with self._index_guard():
                items = self._load_clean_index()
                latest = items.get(rel, {})
                retired_key = self._tombstone_r2_key(latest) or old_key
                item = {
                    **latest,
                    "rel": rel,
                    "path": rel,
                    "name": path.name,
                    "date": str(
                        latest.get("date")
                        or current.get("date")
                        or (
                            "-".join(rel.split("/")[:3])
                            if len(rel.split("/")) >= 4
                            else _mtime_date(path)
                        )
                    ),
                    "size": len(compressed),
                    "created_at": str(
                        latest.get("created_at")
                        or current.get("created_at")
                        or _mtime_datetime(path)
                    ),
                    "storage": "r2",
                    "local": bool(had_local and path.is_file()),
                    "webdav": False,
                    "r2_key": new_key,
                    "remote_url": new_url,
                    "generation": self._new_generation(),
                }
                item.pop("remote_sync_pending", None)
                if dimensions:
                    item["width"], item["height"] = dimensions
                items[rel] = item
                self._save_index(items)
                pending = self._load_remote_delete_pending()
                if rel in pending:
                    old_pending_key = self._detach_pending_r2_key_locked(pending, rel, new_key)
                    self._save_remote_delete_pending(pending)
        except Exception:
            logging.getLogger(__name__).exception("failed to commit compressed r2 image %s", rel)
            owns_new_key = False
            index_known = False
            try:
                with self._index_guard():
                    owns_new_key = self._tombstone_r2_key(self._load_clean_index().get(rel)) == new_key
                index_known = True
            except Exception:
                logging.getLogger(__name__).exception("failed to read image index for %s", rel)
            if not index_known:
                return 0
            if owns_new_key:
                if retired_key and retired_key != new_key:
                    self._preserve_replaced_r2_key(rel, retired_key)
                return len(original) - len(compressed)
            if had_local:
                try:
                    path.write_bytes(original)
                except OSError:
                    pass
            try:
                delete_image_object(settings, new_key)
            except Exception:
                logging.getLogger(__name__).exception(
                    "failed to roll back compressed r2 object %s",
                    new_key,
                )
                self._remember_orphan_r2(new_key, self._item_generation(current))
            return 0
        finally:
            if temp_path.is_file():
                try:
                    temp_path.unlink()
                except OSError:
                    pass

        if old_pending_key:
            self._finish_detached_r2_keys([old_pending_key])
        if retired_key and retired_key != new_key and retired_key != old_pending_key:
            try:
                delete_image_object(settings, retired_key)
            except Exception:
                logging.getLogger(__name__).exception(
                    "failed to delete replaced r2 object %s",
                    retired_key,
                )
                self._remember_orphan_r2(retired_key, self._item_generation(current))
        return len(original) - len(compressed)

    def compress_local_images(self, quality: int = 60) -> dict[str, int]:
        del quality  # Kept for the existing API contract; PNG optimization has no quality level.
        updates: dict[str, dict[str, object]] = {}
        r2_compressed = 0
        r2_saved = 0
        image_root = config.images_dir
        for path in sorted(image_root.rglob("*.png")):
            if not path.is_file():
                continue
            rel = path.relative_to(image_root).as_posix()
            temp_path = path.with_name(f".{path.name}.compress.tmp")
            with self._item_guard(rel):
                try:
                    original = path.read_bytes()
                    compressed = self._compress_png(original)
                    if len(compressed) >= len(original):
                        continue
                    replaced = self._replace_compressed_r2(rel, path, original, compressed)
                    if replaced is not None:
                        if replaced > 0:
                            r2_compressed += 1
                            r2_saved += replaced
                        continue
                    temp_path.write_bytes(compressed)
                    temp_path.replace(path)
                    stat = path.stat()
                    dimensions = _image_dimensions(compressed)
                    self._remove_thumbnail(rel)
                    updates[rel] = {
                        "size": len(compressed),
                        "saved_bytes": len(original) - len(compressed),
                        "mtime_ns": stat.st_mtime_ns,
                        **({"width": dimensions[0], "height": dimensions[1]} if dimensions else {}),
                    }
                except Exception:
                    continue
                finally:
                    if temp_path.is_file():
                        try:
                            temp_path.unlink()
                        except OSError:
                            pass

        committed: dict[str, dict[str, object]] = {}
        update_items = list(updates.items())
        for offset in range(0, len(update_items), IMAGE_MUTATION_BATCH_SIZE):
            batch = dict(update_items[offset:offset + IMAGE_MUTATION_BATCH_SIZE])
            batch_committed: dict[str, dict[str, object]] = {}
            with self._item_guards(batch):
                for rel, update in batch.items():
                    path = image_local_path(rel)
                    try:
                        stat = path.stat()
                    except OSError:
                        continue
                    if stat.st_size != update["size"] or stat.st_mtime_ns != update["mtime_ns"]:
                        continue
                    batch_committed[rel] = update

                if not batch_committed:
                    continue
                with self._index_guard():
                    items = self._load_clean_index()
                    for rel, update in batch_committed.items():
                        path = image_local_path(rel)
                        current = items.get(rel, {})
                        remote_stale = bool(
                            current.get("webdav") or current.get("remote_sync_pending")
                        )
                        remote_exists = bool(current.get("webdav"))
                        item = {
                            **current,
                            "rel": rel,
                            "path": rel,
                            "name": path.name,
                            "date": str(
                                current.get("date")
                                or (
                                    "-".join(rel.split("/")[:3])
                                    if len(rel.split("/")) >= 4
                                    else _mtime_date(path)
                                )
                            ),
                            "size": int(update["size"]),
                            "created_at": str(current.get("created_at") or _mtime_datetime(path)),
                            "storage": "both" if remote_exists else "local",
                            "local": True,
                            "webdav": remote_exists,
                            "remote_url": str(current.get("remote_url") or ""),
                            "generation": self._item_generation(current) or self._new_generation(),
                        }
                        if "width" in update and "height" in update:
                            item["width"] = int(update["width"])
                            item["height"] = int(update["height"])
                        if remote_stale:
                            item["remote_sync_pending"] = True
                        else:
                            item.pop("remote_sync_pending", None)
                        items[rel] = item
                    self._save_index(items)
            committed.update(batch_committed)

        saved = sum(int(update["saved_bytes"]) for update in committed.values()) + r2_saved
        return {
            "compressed": len(committed) + r2_compressed,
            "saved_bytes": saved,
            "saved_mb": saved // (1024 * 1024),
        }

    @staticmethod
    def _published_sync_item(update: dict[str, object]) -> dict[str, object]:
        return {key: value for key, value in update.items() if not key.startswith("_")}

    def _repair_stale_sync_item(
        self,
        client: WebDAVClient,
        rel: str,
    ) -> tuple[bool, bool, bool]:
        with self._item_guard(rel):
            path = image_local_path(rel)
            if not path.is_file():
                return False, True, False
            retired_key = ""
            pending_saved = True
            try:
                payload = path.read_bytes()
                with self._index_guard():
                    current = self._load_clean_index().get(rel, {})
                update = self._sync_item(path, rel, current, payload, "")
                remote_url = client.put(rel, payload)
                update["remote_url"] = remote_url
                update = self._published_sync_item(update)
                with self._index_guard():
                    items = self._load_clean_index()
                    current = items.get(rel, {})
                    merged = {
                        **current,
                        **update,
                        "created_at": str(current.get("created_at") or update["created_at"]),
                        "generation": (
                            self._item_generation(current)
                            or self._item_generation(update)
                            or self._new_generation()
                        ),
                    }
                    merged.pop("remote_sync_pending", None)
                    remote_pending = self._load_remote_delete_pending()
                    retired_key = self._stage_detached_r2_key(
                        remote_pending,
                        merged,
                        str(merged.get("generation") or ""),
                    )
                    items[rel] = merged
                    self._save_index(items)
                    if retired_key:
                        pending_saved = False
                        self._save_remote_delete_pending(remote_pending)
                        pending_saved = True
                if retired_key:
                    self._finish_detached_r2_keys([retired_key])
                return True, False, False
            except Exception:
                if not pending_saved:
                    self._preserve_replaced_r2_key(rel, retired_key)
                return False, False, True

    def _commit_sync_batch(
        self,
        client: WebDAVClient,
        updates: dict[str, dict[str, object]],
    ) -> tuple[set[str], set[str], int]:
        merged_rels: set[str] = set()
        cleanup_remote: set[str] = set()
        stale_rels: set[str] = set()
        retired_keys: list[str] = []
        retired_pairs: list[tuple[str, str]] = []
        pending_error: Exception | None = None
        with self._item_guards(updates):
            current_payloads: dict[str, bytes] = {}
            for rel in updates:
                path = image_local_path(rel)
                if not path.is_file():
                    cleanup_remote.add(rel)
                    continue
                try:
                    current_payloads[rel] = path.read_bytes()
                except OSError:
                    cleanup_remote.add(rel)

            with self._index_guard():
                items = self._load_clean_index()
                remote_pending = self._load_remote_delete_pending()
                changed = False
                for rel, update in updates.items():
                    if rel in cleanup_remote:
                        continue
                    current_payload = current_payloads[rel]
                    if hashlib.sha256(current_payload).hexdigest() != update.get("_content_sha256"):
                        current = items.get(rel, {})
                        remote_url = str(update.get("remote_url") or current.get("remote_url") or "")
                        local_update = self._published_sync_item(
                            self._sync_item(
                                image_local_path(rel),
                                rel,
                                current,
                                current_payload,
                                remote_url,
                            )
                        )
                        pending = {
                            **current,
                            **local_update,
                            "storage": "both",
                            "local": True,
                            "webdav": True,
                            "remote_url": remote_url,
                            "remote_sync_pending": True,
                            "generation": (
                                self._item_generation(current)
                                or self._item_generation(local_update)
                                or self._new_generation()
                            ),
                        }
                        items[rel] = pending
                        retired = self._stage_detached_r2_key(
                            remote_pending,
                            pending,
                            str(pending.get("generation") or ""),
                        )
                        if retired:
                            retired_keys.append(retired)
                            retired_pairs.append((rel, retired))
                        stale_rels.add(rel)
                        changed = True
                        continue
                    current = items.get(rel, {})
                    published = self._published_sync_item(update)
                    merged = {
                        **current,
                        **published,
                        "created_at": str(current.get("created_at") or published["created_at"]),
                        "generation": (
                            self._item_generation(current)
                            or self._item_generation(published)
                            or self._new_generation()
                        ),
                    }
                    merged.pop("remote_sync_pending", None)
                    retired = self._stage_detached_r2_key(
                        remote_pending,
                        merged,
                        str(merged.get("generation") or ""),
                    )
                    if retired:
                        retired_keys.append(retired)
                        retired_pairs.append((rel, retired))
                    items[rel] = merged
                    merged_rels.add(rel)
                    changed = True
                index_saved = False
                try:
                    if changed:
                        self._save_index(items)
                        index_saved = True
                    if retired_keys:
                        self._save_remote_delete_pending(remote_pending)
                except Exception as exc:
                    if not index_saved or not retired_keys:
                        raise
                    pending_error = exc

        if pending_error is not None:
            for rel, key in retired_pairs:
                self._preserve_replaced_r2_key(rel, key)
            raise pending_error
        self._finish_detached_r2_keys(retired_keys)
        failed = 0
        for rel in stale_rels:
            repaired, needs_cleanup, repair_failed = self._repair_stale_sync_item(client, rel)
            if repaired:
                merged_rels.add(rel)
            if needs_cleanup:
                cleanup_remote.add(rel)
            if repair_failed:
                failed += 1
        return merged_rels, cleanup_remote, failed

    def _cleanup_remote_candidates(
        self,
        client: WebDAVClient,
        candidates: set[str],
        pending: dict[str, dict[str, object]],
    ) -> int:
        candidate_rels = sorted(candidates)
        for offset in range(0, len(candidate_rels), IMAGE_MUTATION_BATCH_SIZE):
            batch = candidate_rels[offset:offset + IMAGE_MUTATION_BATCH_SIZE]
            with self._item_guards(batch):
                with self._index_guard():
                    items = self._load_clean_index()
                    durable = self._load_remote_delete_pending()
                    changed = False
                    for rel in batch:
                        if rel in durable:
                            continue
                        if items.get(rel) is not None or image_local_path(rel).is_file():
                            continue
                        durable[rel] = self._delete_tombstone(
                            generation="",
                            scope="remote",
                            remote=True,
                        )
                        changed = True
                    if changed:
                        self._save_remote_delete_pending(durable)

        failed = 0
        for rel in sorted(candidates | set(pending)):
            with self._item_guard(rel):
                with self._index_guard():
                    current = self._load_clean_index().get(rel)
                    tombstone = self._load_remote_delete_pending().get(rel)
                if tombstone is None:
                    continue
                # R2 tombstones are retried by delete_many. A WebDAV 404 is
                # success here, so treating remote=true as a WebDAV delete
                # would drop the object key and the gallery row.
                if self._tombstone_r2_key(tombstone):
                    continue
                local_exists = image_local_path(rel).is_file()

                scope = _clean(tombstone.get("scope"))
                generation_matches = self._asset_generation_matches(
                    current,
                    tombstone,
                    allow_missing=True,
                )
                superseded = (
                    (scope == "asset" and not generation_matches)
                    or (scope == "remote" and (current is not None or local_exists))
                )
                if superseded:
                    with self._index_guard():
                        durable = self._load_remote_delete_pending()
                        if self._tombstone_matches(durable.get(rel), tombstone):
                            durable.pop(rel, None)
                            self._save_remote_delete_pending(durable)
                    continue

                if scope == "asset" and local_exists:
                    try:
                        image_local_path(rel).unlink()
                    except Exception:
                        if image_local_path(rel).exists():
                            failed += 1
                            continue

                if tombstone.get("remote"):
                    try:
                        client.delete(rel)
                    except Exception:
                        failed += 1
                        continue

                with self._index_guard():
                    items = self._load_clean_index()
                    durable = self._load_remote_delete_pending()
                    if not self._tombstone_matches(durable.get(rel), tombstone):
                        continue
                    latest = items.get(rel)
                    if scope == "asset" and self._asset_generation_matches(
                        latest,
                        tombstone,
                        allow_missing=True,
                    ):
                        if latest is not None:
                            items.pop(rel, None)
                            self._save_index(items)
                    durable.pop(rel, None)
                    self._save_remote_delete_pending(durable)
        return failed

    def _clear_pending_without_local(self) -> None:
        """Drop a sync flag whose local file is already gone.

        Disk cleanup can remove the only bytes that still needed uploading.
        The WebDAV object stays; the flag must not keep claiming a newer copy.
        """
        with self._index_guard():
            items = self._load_clean_index()
            changed = False
            for rel, item in items.items():
                if not isinstance(item, dict) or not item.get("remote_sync_pending"):
                    continue
                if image_local_path(rel).is_file():
                    continue
                updated = {**item, "local": False}
                updated.pop("remote_sync_pending", None)
                if updated.get("webdav"):
                    updated["storage"] = "webdav"
                items[rel] = updated
                changed = True
            if changed:
                self._save_index(items)

    def _detach_indexed_r2_copies(self, rels: list[str]) -> None:
        """Remove leftover R2 keys from rows that are already WebDAV copies.

        A size-matched WebDAV row used to be skipped forever, so the bucket
        object and the R2 gallery label stayed. The file is not uploaded again.
        """
        if not rels:
            return
        retired: list[tuple[str, str]] = []
        pending_error: Exception | None = None
        with self._item_guards(rels):
            with self._index_guard():
                items = self._load_clean_index()
                pending = self._load_remote_delete_pending()
                changed = False
                for rel in rels:
                    current = items.get(rel)
                    if not isinstance(current, dict) or not current.get("webdav"):
                        continue
                    if not self._tombstone_r2_key(current):
                        continue
                    key = self._stage_detached_r2_key(
                        pending,
                        current,
                        str(current.get("generation") or ""),
                    )
                    current["local"] = bool(current.get("local")) or image_local_path(rel).is_file()
                    current["storage"] = "both" if current.get("local") else "webdav"
                    current.pop("remote_sync_pending", None)
                    items[rel] = current
                    if key:
                        retired.append((rel, key))
                    changed = True
                index_saved = False
                try:
                    if changed:
                        self._save_index(items)
                        index_saved = True
                        if retired:
                            self._save_remote_delete_pending(pending)
                except Exception as exc:
                    if not index_saved or not retired:
                        raise
                    pending_error = exc
        if pending_error is not None:
            for rel, key in retired:
                self._preserve_replaced_r2_key(rel, key)
            raise pending_error
        self._finish_detached_r2_keys([key for _rel, key in retired])

    def _sync_all_locked(self, settings: dict[str, object]) -> dict[str, int]:
        self._clear_pending_without_local()
        with self._index_guard():
            snapshot = self._load_clean_index()
            pending_remote_deletes = self._load_remote_delete_pending()

        skipped = 0
        failed = 0
        updates: dict[str, dict[str, object]] = {}
        uncertain_remote: set[str] = set()
        detach_r2: list[str] = []
        client = WebDAVClient(settings)
        image_root = config.images_dir
        try:
            for path in sorted(image_root.rglob("*")):
                if not path.is_file() or not _is_image_rel(path.name):
                    continue
                rel = path.relative_to(image_root).as_posix()
                item = snapshot.get(rel, {})
                tombstone = pending_remote_deletes.get(rel)
                if (
                    tombstone is not None
                    and _clean(tombstone.get("scope")) == "asset"
                    and self._asset_generation_matches(
                        item if item else None,
                        tombstone,
                        allow_missing=True,
                    )
                ):
                    continue
                indexed_size = item.get("size")
                try:
                    catalog_matches_local = int(indexed_size) == path.stat().st_size
                except (OSError, TypeError, ValueError):
                    catalog_matches_local = False
                if (
                    item.get("webdav")
                    and not item.get("remote_sync_pending")
                    and catalog_matches_local
                ):
                    if self._tombstone_r2_key(item if isinstance(item, dict) else None):
                        detach_r2.append(rel)
                    skipped += 1
                    continue
                try:
                    payload = path.read_bytes()
                    update = self._sync_item(path, rel, item, payload, "")
                    remote_url = client.put(rel, payload)
                    update["remote_url"] = remote_url
                    updates[rel] = update
                except Exception:
                    failed += 1
                    uncertain_remote.add(rel)

            merged: set[str] = set()
            cleanup_remote: set[str] = set()
            update_items = list(updates.items())
            for offset in range(0, len(update_items), IMAGE_SYNC_MERGE_BATCH_SIZE):
                batch = dict(update_items[offset:offset + IMAGE_SYNC_MERGE_BATCH_SIZE])
                batch_merged, batch_cleanup, batch_failed = self._commit_sync_batch(client, batch)
                merged.update(batch_merged)
                cleanup_remote.update(batch_cleanup)
                failed += batch_failed

            self._detach_indexed_r2_copies(detach_r2)
            failed += self._cleanup_remote_candidates(
                client,
                cleanup_remote | uncertain_remote,
                pending_remote_deletes,
            )
            return {"uploaded": len(merged), "skipped": skipped, "failed": failed}
        finally:
            client.session.close()

    def sync_all(self) -> dict[str, int]:
        settings = self.settings()
        if self.mode() not in {"webdav", "both"}:
            raise ImageStorageError("WebDAV 图片存储未启用")
        with interprocess_lock(self._sync_file_lock):
            return self._sync_all_locked(settings)

    def test_webdav(self) -> dict[str, object]:
        return WebDAVClient(self.settings()).test()

    def test_connection(self) -> dict[str, object]:
        if self.mode() == "r2":
            from services.image_r2 import test_image_bucket

            return test_image_bucket(self.settings())
        return self.test_webdav()

    def _save_r2_image(self, image_data: bytes, rel: str, base_url: str) -> StoredImage:
        from services.image_r2 import public_image_url, publish_image_bytes

        settings = self.settings()
        r2_key = publish_image_bytes(settings, image_data)
        path = image_local_path(rel)
        remote_url = public_image_url(settings, r2_key)
        previous_key = ""
        old_keys: list[str] = []
        index_saved = False
        try:
            # The bucket object is the copy. A second full file on disk fills
            # the volume the R2 mode was meant to free.
            dimensions = _image_dimensions(image_data)
            item = {
                "rel": rel,
                "path": rel,
                "name": Path(rel).name,
                "date": "-".join(rel.split("/")[:3]),
                "size": len(image_data),
                "created_at": _now_iso(),
                "storage": "r2",
                "local": False,
                "webdav": False,
                "r2_key": r2_key,
                "remote_url": remote_url,
                "generation": self._new_generation(),
            }
            if dimensions:
                item["width"], item["height"] = dimensions
            with self._index_guard():
                items = self._load_clean_index()
                previous = items.get(rel)
                previous_key = self._replaced_catalog_r2_key(
                    previous if isinstance(previous, dict) else None,
                    r2_key,
                )
                items[rel] = item
                self._save_index(items)
                index_saved = True
                pending = self._load_remote_delete_pending()
                had_pending = rel in pending
                old_keys = self._stage_replaced_r2_keys_locked(
                    pending,
                    rel,
                    previous if isinstance(previous, dict) else None,
                    r2_key,
                )
                if previous_key or had_pending:
                    self._save_remote_delete_pending(pending)
        except Exception:
            self._rollback_uncommitted_r2(
                path,
                rel,
                settings,
                r2_key,
                index_saved=index_saved,
            )
            self._preserve_replaced_r2_key(rel, previous_key)
            raise
        if old_keys:
            self._finish_detached_r2_keys(old_keys)
        self._store_thumbnail(rel, image_data)
        return StoredImage(rel=rel, url=remote_url, storage="r2", size=len(image_data))

    def _rollback_uncommitted_r2(
        self,
        path: Path,
        rel: str,
        settings: dict[str, object],
        r2_key: str,
        *,
        index_saved: bool = False,
    ) -> None:
        """Drop a new object only when this save did not commit it."""
        from services.image_r2 import delete_image_object

        owns_new_key = False
        index_known = False
        try:
            with self._index_guard():
                owns_new_key = self._tombstone_r2_key(self._load_clean_index().get(rel)) == r2_key
            index_known = True
        except Exception:
            logging.getLogger(__name__).exception("failed to read image index for %s", rel)
        # A committed row must survive an unreadable index. A row this call
        # never saved is still uncommitted, so the new object can be deleted.
        if owns_new_key or (not index_known and index_saved):
            return
        if path.is_file():
            try:
                path.unlink()
            except OSError:
                pass
        try:
            delete_image_object(settings, r2_key)
        except Exception:
            logging.getLogger(__name__).exception("failed to roll back r2 object %s", r2_key)
            self._remember_orphan_r2(r2_key, self._new_generation())


image_storage_service = ImageStorageService()
