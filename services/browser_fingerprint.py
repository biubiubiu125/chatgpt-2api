"""Canonical Chrome 146 browser identity for outbound HTTP requests."""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlparse


def _load_chrome146_user_agent() -> str:
    path = Path(__file__).resolve().parents[1] / "contracts" / "chrome146.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    user_agent = str(payload.get("userAgent") or "").strip()
    if "Chrome/146.0.0.0" not in user_agent:
        raise RuntimeError(f"invalid Chrome146 user agent in {path}")
    return user_agent


CHROME146_USER_AGENT = _load_chrome146_user_agent()


def is_chrome146_user_agent(value: object) -> bool:
    text = str(value or "").strip()
    return bool(text) and "Chrome/146.0.0.0" in text


CHROME146_SEC_CH_UA = '"Google Chrome";v="146", "Chromium";v="146", "Not.A/Brand";v="24"'
CHROME146_SEC_CH_UA_FULL_VERSION = '"146.0.0.0"'
CHROME146_SEC_CH_UA_FULL_VERSION_LIST = (
    '"Google Chrome";v="146.0.0.0", '
    '"Chromium";v="146.0.0.0", '
    '"Not.A/Brand";v="24.0.0.0"'
)
CHROME146_SEC_CH_UA_PLATFORM = '"Windows"'
CHROME146_SEC_CH_UA_PLATFORM_VERSION = '"10.0.0"'
CHROME146_ACCEPT_LANGUAGE = "zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7"
CHROME146_NAVIGATOR_LANGUAGE = "zh-CN"
CHROME146_NAVIGATOR_LANGUAGES = "zh-CN,zh,en"
CHROME146_IMPERSONATE = "chrome146"
CHROME146_TIMEZONE = "Asia/Shanghai"
CHROME146_TIMEZONE_OFFSET_MIN = -480
CHROME146_TIMEZONE_GMT = "GMT+0800"
CHROME146_TIMEZONE_DISPLAY = "中国标准时间"
CHROME146_SCREEN_WIDTH = 2560
CHROME146_SCREEN_HEIGHT = 1440
CHROME146_PAGE_WIDTH = 1724
CHROME146_PAGE_HEIGHT = 1072
CHROME146_PIXEL_RATIO = 1
CHROME146_TIME_SINCE_LOADED = 120
CHROME146_HARDWARE_CONCURRENCY = 16
CHROME146_APP_NAME = "chatgpt.com"

_FORCED_HEADERS = {
    "User-Agent": CHROME146_USER_AGENT,
    "Accept-Language": CHROME146_ACCEPT_LANGUAGE,
    "Sec-Ch-Ua": CHROME146_SEC_CH_UA,
    "Sec-Ch-Ua-Arch": '"x86"',
    "Sec-Ch-Ua-Bitness": '"64"',
    "Sec-Ch-Ua-Full-Version": CHROME146_SEC_CH_UA_FULL_VERSION,
    "Sec-Ch-Ua-Full-Version-List": CHROME146_SEC_CH_UA_FULL_VERSION_LIST,
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Model": '""',
    "Sec-Ch-Ua-Platform": CHROME146_SEC_CH_UA_PLATFORM,
    "Sec-Ch-Ua-Platform-Version": CHROME146_SEC_CH_UA_PLATFORM_VERSION,
}

_DEFAULT_HEADERS = {
    "Accept": "*/*",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Priority": "u=1, i",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
}


def _set_header(headers: dict[str, object], name: str, value: object) -> None:
    lowered = name.casefold()
    existing_key = next(
        (key for key in headers if str(key).casefold() == lowered),
        None,
    )
    for key in tuple(headers):
        if str(key).casefold() == lowered and key != existing_key:
            headers.pop(key, None)
    headers[existing_key or name] = value


def chrome146_headers(
    headers: Mapping[str, object] | None = None,
    *,
    include_defaults: bool = True,
) -> dict[str, object]:
    """Return headers with browser-identifying values forced to Chrome146."""

    result: dict[str, object] = dict(headers or {})
    if include_defaults:
        for name, value in _DEFAULT_HEADERS.items():
            if not any(str(key).casefold() == name.casefold() for key in result):
                result[name] = value
    for name, value in _FORCED_HEADERS.items():
        _set_header(result, name, value)
    return result


def chrome146_signed_asset_headers(
    headers: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Build headers for a signed cross-origin asset request.

    The main ChatGPT session carries same-origin navigation context. Signed
    blob/CDN URLs are a different request context, so inherited ``Origin`` and
    ``Referer`` headers must be explicitly disabled for curl_cffi.
    """

    result = chrome146_headers(headers, include_defaults=False)
    _set_header(result, "Sec-Fetch-Site", "cross-site")
    _set_header(result, "Sec-Fetch-Mode", "cors")
    _set_header(result, "Sec-Fetch-Dest", "empty")
    if not any(str(key).casefold() == "origin" for key in result):
        result["Origin"] = None
    if not any(str(key).casefold() == "referer" for key in result):
        result["Referer"] = None
    return result


def chrome146_session_kwargs(
    kwargs: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Return curl_cffi session/request kwargs pinned to Chrome146."""

    result = dict(kwargs or {})
    result["impersonate"] = CHROME146_IMPERSONATE
    return result


def chrome146_fingerprint() -> dict[str, str]:
    """Return canonical fingerprint fields used by account records."""

    return {
        "user-agent": CHROME146_USER_AGENT,
        "impersonate": CHROME146_IMPERSONATE,
        "sec-ch-ua": CHROME146_SEC_CH_UA,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": CHROME146_SEC_CH_UA_PLATFORM,
        "sec-ch-ua-full-version": CHROME146_SEC_CH_UA_FULL_VERSION,
        "sec-ch-ua-full-version-list": CHROME146_SEC_CH_UA_FULL_VERSION_LIST,
        "sec-ch-ua-platform-version": CHROME146_SEC_CH_UA_PLATFORM_VERSION,
    }


def chrome146_client_contextual_info() -> dict[str, object]:
    """Return the single Chrome146 viewport/screen payload for all upstream calls."""

    return {
        "is_dark_mode": False,
        "time_since_loaded": CHROME146_TIME_SINCE_LOADED,
        "page_height": CHROME146_PAGE_HEIGHT,
        "page_width": CHROME146_PAGE_WIDTH,
        "pixel_ratio": CHROME146_PIXEL_RATIO,
        "screen_height": CHROME146_SCREEN_HEIGHT,
        "screen_width": CHROME146_SCREEN_WIDTH,
        "app_name": CHROME146_APP_NAME,
    }


def chrome146_pow_date_string(now: object | None = None) -> str:
    """Return Date.toString() for Chrome146 on zh-CN Windows in Asia/Shanghai."""

    from datetime import datetime, timedelta, timezone

    moment = now if isinstance(now, datetime) else datetime.now(timezone(timedelta(hours=8)))
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone(timedelta(hours=8)))
    else:
        moment = moment.astimezone(timezone(timedelta(hours=8)))
    weekdays = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
    months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
    return (
        f"{weekdays[moment.weekday()]} {months[moment.month - 1]} "
        f"{moment.day:2d} {moment.year:04d} "
        f"{moment.strftime('%H:%M:%S')} {CHROME146_TIMEZONE_GMT} "
        f"({CHROME146_TIMEZONE_DISPLAY})"
    )


def browser_origin(url: str) -> tuple[str, str, int, str] | None:
    """Return scheme, host, effective port, and site for a browser request URL."""

    try:
        parsed = urlparse(str(url or "").strip())
        scheme = (parsed.scheme or "").lower()
        host = (parsed.hostname or "").lower().rstrip(".")
        if scheme not in {"http", "https"} or not host:
            return None
        port = parsed.port
    except ValueError:
        return None
    if port is None:
        port = 443 if scheme == "https" else 80
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = [label for label in host.split(".") if label]
        site = host if len(labels) < 2 else ".".join(labels[-2:])
    else:
        site = host
    return scheme, host, port, site


def urls_share_browser_origin(left: str, right: str) -> bool:
    """Compare origins after default ports and trailing-dot hostnames are normalized."""

    first = browser_origin(left)
    second = browser_origin(right)
    return first is not None and second is not None and first[:3] == second[:3]


def navigation_sec_fetch_site(referer: str, target: str) -> str:
    """Choose Sec-Fetch-Site from the previous document and the next request."""

    source = browser_origin(referer)
    destination = browser_origin(target)
    if source is None or destination is None:
        return "none"
    if source[:3] == destination[:3]:
        return "same-origin"
    if source[3] == destination[3]:
        return "same-site"
    return "cross-site"


def chrome146_remote_image_headers(url: str = "", referer: str = "") -> dict[str, str]:
    """Headers for downloading a user-supplied image URL as Chrome 146."""

    site = navigation_sec_fetch_site(referer, url) if str(url or "").strip() else "none"
    headers = chrome146_headers(
        {
            "Accept": "image/*,*/*;q=0.8",
            "Sec-Fetch-Dest": "image",
            "Sec-Fetch-Mode": "no-cors",
            "Sec-Fetch-Site": site,
        },
        include_defaults=False,
    )
    if str(referer or "").strip():
        headers["Referer"] = referer
    return {
        str(key): str(value)
        for key, value in headers.items()
        if value is not None
    }
