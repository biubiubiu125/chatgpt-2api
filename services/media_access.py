from __future__ import annotations

import hashlib
import hmac
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi import HTTPException

from services.config import config


def media_ttl_seconds() -> int:
    try:
        hours = int(config.image_retention_hours)
    except (TypeError, ValueError):
        hours = 24
    if hours <= 0:
        hours = 24
    return hours * 3600


def _secret() -> bytes:
    return str(config.auth_key or "").encode("utf-8")


def _signature(resource_path: str, exp: int) -> str:
    secret = _secret()
    if not secret:
        return ""
    message = f"{resource_path}\n{int(exp)}".encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def with_media_access(url: str, resource_path: str, *, now: float | None = None) -> str:
    resource_path = str(resource_path or "").strip().lstrip("/")
    exp = int((time.time() if now is None else now) + media_ttl_seconds())
    parts = urlsplit(str(url or ""))
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query["exp"] = str(exp)
    query["sig"] = _signature(resource_path, exp)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def media_access_granted(resource_path: str, exp: str | None, sig: str | None) -> bool:
    resource_path = str(resource_path or "").strip().lstrip("/")
    if not _secret() or not exp or not sig:
        return False
    try:
        expires_at = int(str(exp).strip())
    except (TypeError, ValueError):
        return False
    if expires_at < int(time.time()):
        return False
    expected = _signature(resource_path, expires_at)
    if not expected:
        return False
    return hmac.compare_digest(expected, str(sig).strip())


def require_media_access(
    resource_path: str,
    *,
    exp: str | None,
    sig: str | None,
    authorization: str | None,
) -> None:
    if media_access_granted(resource_path, exp, sig):
        return
    if str(authorization or "").strip():
        from api.support import require_admin

        require_admin(authorization)
        return
    raise HTTPException(status_code=401, detail={"error": "图片链接无效或已过期"})
