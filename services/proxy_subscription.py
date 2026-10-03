from __future__ import annotations

import base64
import json
import re
from collections.abc import Mapping
from urllib.parse import quote, urlparse

from services.proxy_service import normalize_proxy_url


_SUPPORTED_SCHEMES = {"http", "https", "socks5", "socks5h"}
_DROPPED_KINDS = {
    "ss",
    "shadowsocks",
    "vmess",
    "vless",
    "trojan",
    "hysteria",
    "hysteria2",
    "tuic",
    "wireguard",
}
_SCHEME_BY_KIND = {
    "http": "http",
    "https": "https",
    "socks": "socks5",
    "socks5": "socks5",
    "socks5h": "socks5h",
}


def redact_subscription_target(url: object) -> str:
    raw = str(url or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw)
    host = parsed.hostname or ""
    if not host:
        return "subscription"
    return host


def parse_subscription_proxies(text: object) -> list[str]:
    """提取订阅里当前进程能直接使用的 HTTP / SOCKS 节点。

    ss、vmess、trojan、vless 不在进程内转换，直接丢掉。
    """
    decoded = _decode_subscription_text(text)
    entries = _structured_proxy_entries(decoded)
    raw_urls = [_proxy_url_from_fields(item) for item in entries] if entries else []
    if not raw_urls:
        raw_urls = _line_proxy_urls(decoded)
    normalized: list[str] = []
    seen: set[str] = set()
    for raw_url in raw_urls:
        candidate = _normalized_supported_url(raw_url)
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        normalized.append(candidate)
    return normalized


def _decode_subscription_text(text: object) -> str:
    raw = str(text or "").strip()
    if not raw:
        return ""
    if "://" in raw or raw.lstrip().startswith(("{", "[")) or re.search(r"(?m)^\s*proxies\s*:", raw):
        return raw
    compact = "".join(raw.split())
    try:
        padded = compact + ("=" * (-len(compact) % 4))
        decoded = base64.b64decode(padded, validate=True).decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return raw
    if "://" in decoded or decoded.lstrip().startswith(("{", "[")) or "proxies:" in decoded:
        return decoded
    return raw


def _structured_proxy_entries(text: str) -> list[Mapping[str, object]]:
    parsed = _parse_json_entries(text)
    if parsed:
        return parsed
    return _parse_clash_entries(text)


def _parse_json_entries(text: str) -> list[Mapping[str, object]]:
    stripped = text.lstrip()
    if not stripped.startswith(("{", "[")):
        return []
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []
    values: list[object] = []
    if isinstance(payload, list):
        values = payload
    elif isinstance(payload, dict):
        for key in ("proxies", "outbounds", "nodes"):
            item = payload.get(key)
            if isinstance(item, list):
                values = item
                break
    return [item for item in values if isinstance(item, Mapping)]


def _parse_clash_entries(text: str) -> list[Mapping[str, object]]:
    entries: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    in_proxies = False
    for raw_line in text.splitlines():
        if re.match(r"^\s*proxies\s*:\s*$", raw_line):
            in_proxies = True
            continue
        if not in_proxies:
            continue
        if raw_line and not raw_line.startswith((" ", "\t", "-")):
            break
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- "):
            if current:
                entries.append(current)
            current = {}
            _assign_mapping_item(current, stripped[2:].strip())
            continue
        if current is not None:
            _assign_mapping_item(current, stripped)
    if current:
        entries.append(current)
    return entries


def _assign_mapping_item(target: dict[str, object], body: str) -> None:
    if not body or body.startswith("#"):
        return
    if body.startswith("{") and body.endswith("}"):
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            target.update(payload)
            return
    name, separator, value = body.partition(":")
    if not separator:
        return
    key = name.strip().strip("\"'")
    raw_value = value.strip().strip("\"'")
    if key:
        target[key] = raw_value


def _line_proxy_urls(text: str) -> list[str]:
    urls: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        urls.append(line)
    return urls


def _proxy_url_from_fields(item: Mapping[str, object]) -> str:
    kind = str(item.get("type") or item.get("protocol") or "").strip().lower()
    if kind in _DROPPED_KINDS:
        return ""
    server = str(item.get("server") or item.get("host") or "").strip()
    port = str(item.get("port") or item.get("server_port") or "").strip()
    scheme = _SCHEME_BY_KIND.get(kind, "")
    if not scheme or not server or not port:
        return ""
    username = str(item.get("username") or item.get("user") or "")
    password = str(item.get("password") or "")
    auth = ""
    if username or password:
        auth = f"{quote(username, safe='')}:{quote(password, safe='')}@"
    host = f"[{server}]" if ":" in server and not server.startswith("[") else server
    return f"{scheme}://{auth}{host}:{port}"


def _normalized_supported_url(value: object) -> str:
    raw = str(value or "").strip()
    if not raw or "://" not in raw:
        return ""
    scheme = raw.split(":", 1)[0].strip().lower()
    if scheme in _DROPPED_KINDS:
        return ""
    try:
        normalized = normalize_proxy_url(raw)
    except (TypeError, ValueError):
        return ""
    parsed = urlparse(normalized)
    if parsed.scheme.lower() not in _SUPPORTED_SCHEMES:
        return ""
    return normalized
