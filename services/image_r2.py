from __future__ import annotations

import hashlib
import logging
import secrets
import time
from datetime import datetime

from services.backup_service import CloudflareR2Client
from services.config import config
from utils.timezone import beijing_now


def new_object_key(payload: bytes, now: datetime | None = None) -> str:
    """Name the object so a later resume can recognize the same bytes.

    The file name matches the local ``digits_md5.png`` identity. A new
    timestamp still produces a new key, but the hash stays the identity.
    """
    current = now or beijing_now()
    digest = hashlib.md5(payload).hexdigest()
    return (
        f"images/{current:%Y}/{current:%m}/{current:%d}/"
        f"{time.time_ns()}_{digest}.png"
    )


def _retention_hours() -> int:
    try:
        return max(0, int(config.image_retention_hours))
    except (TypeError, ValueError):
        return 0


def _public_cache_control() -> str:
    # max-age follows the retention window and is not immutable, so deleting
    # the object can stop a browser or CDN from serving it after that window.
    return f"public, max-age={_retention_hours() * 3600}"


def client_for_settings(settings: dict[str, object]) -> CloudflareR2Client:
    client = CloudflareR2Client({
        "account_id": settings.get("r2_account_id"),
        "access_key_id": settings.get("r2_access_key_id"),
        "secret_access_key": settings.get("r2_secret_access_key"),
        "bucket": settings.get("r2_bucket"),
        "prefix": "images",
    })
    # Image objects use an explicit key. An empty prefix must not fall back to
    # the backup client's ``backups/`` listing prefix.
    client.prefix = ""
    return client


def public_image_url(settings: dict[str, object], key: str) -> str:
    base = str(settings.get("r2_public_base_url") or "").rstrip("/")
    return f"{base}/{str(key or '').lstrip('/')}"


def _close_image_session(client: CloudflareR2Client) -> None:
    """Close the HTTP session without hiding the upload result.

    An exception from ``finally`` replaces both the returned key and an
    upload error. The object would then be stored with no catalog key.
    """
    try:
        client.session.close()
    except Exception:
        logging.getLogger(__name__).exception("failed to close r2 image session")


def publish_image_bytes(settings: dict[str, object], payload: bytes) -> str:
    key = new_object_key(payload)
    client = client_for_settings(settings)
    try:
        client.upload_bytes(
            key,
            payload,
            content_type="image/png",
            extra_headers={"cache-control": _public_cache_control()},
        )
    except Exception:
        _close_image_session(client)
        raise
    _close_image_session(client)
    return key


def delete_image_object(settings: dict[str, object], key: str) -> None:
    client = client_for_settings(settings)
    try:
        client.delete_object(key)
    except Exception:
        _close_image_session(client)
        raise
    _close_image_session(client)


class ImageObjectNotFound(LookupError):
    pass


def _safe_object_key(key: str) -> str:
    cleaned = str(key or "").strip()
    if not cleaned or cleaned.startswith("/") or "\\" in cleaned or "\x00" in cleaned:
        return ""
    parts = cleaned.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return ""
    return cleaned


def read_image_object(settings: dict[str, object], key: str) -> bytes:
    """Read one image object by its stored key. Never uses the public URL."""
    safe_key = _safe_object_key(key)
    if not safe_key:
        raise ImageObjectNotFound(str(key or ""))
    client = client_for_settings(settings)
    try:
        response = client._request("GET", safe_key, timeout=60.0)
        status = int(getattr(response, "status_code", 0) or 0)
        if status == 404:
            raise ImageObjectNotFound(safe_key)
        if status >= 400:
            from services.backup_service import BackupError

            raise BackupError(f"读取图片失败：HTTP {status}")
        payload = bytes(getattr(response, "content", b"") or b"")
        if not payload:
            raise ImageObjectNotFound(safe_key)
        return payload
    finally:
        _close_image_session(client)


def _pinned_public_probe_options(url: str) -> dict[object, object]:
    """Resolve the probe URL and pin the connection to public addresses only."""
    from fastapi import HTTPException

    from services.backup_service import BackupError
    from services.public_image_url import public_image_curl_options, validate_public_image_url

    try:
        parsed, addresses = validate_public_image_url(url)
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        message = str(detail.get("error") or "")
        if "could not be resolved" in message:
            raise BackupError("公开图片地址无法解析") from exc
        raise BackupError("公开图片地址不能是内网、本机或链路本地地址") from exc
    return public_image_curl_options(parsed, addresses)


def test_image_bucket(settings: dict[str, object]) -> dict[str, object]:
    """Prove the S3 API and the public URL, then remove the probe object."""
    from services.backup_service import BackupError

    client = client_for_settings(settings)
    uploaded = ""
    try:
        result = client.test_connection()
        probe_key = f"images/_probe/{secrets.token_hex(8)}.txt"
        client.upload_bytes(
            probe_key,
            b"chatgpt-2api",
            content_type="text/plain",
            extra_headers={"cache-control": "no-store"},
        )
        uploaded = probe_key
        url = public_image_url(settings, probe_key)
        response = client.session.get(
            url,
            timeout=30.0,
            allow_redirects=False,
            curl_options=_pinned_public_probe_options(url),
        )
        status = int(getattr(response, "status_code", 0) or 0)
        body = bytes(getattr(response, "content", b"") or b"")
        if status != 200 or body != b"chatgpt-2api":
            raise BackupError(f"公开图片地址无法读取：HTTP {status}")
        return result
    finally:
        if uploaded:
            try:
                client.delete_object(uploaded)
            except Exception:
                logging.getLogger(__name__).exception(
                    "failed to delete r2 image probe %s", uploaded
                )
        _close_image_session(client)
