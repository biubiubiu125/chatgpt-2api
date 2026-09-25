from __future__ import annotations

from ipaddress import ip_address
from urllib.parse import urljoin, urlsplit

from services.browser_fingerprint import urls_share_browser_origin


_ASSET_HOST_SUFFIXES = (
    "chatgpt.com",
    "chat.openai.com",
    "oaiusercontent.com",
)


class ProviderAssetUrlError(ValueError):
    pass


def _hostname(value: str) -> str:
    return str(value or "").strip().lower().rstrip(".")


def _is_ip_literal(host: str) -> bool:
    try:
        ip_address(host)
    except ValueError:
        return False
    return True


def _host_allowed(host: str) -> bool:
    return any(host == suffix or host.endswith(f".{suffix}") for suffix in _ASSET_HOST_SUFFIXES)


def resolve_provider_asset_url(url: str, base_url: str = "") -> str:
    """Return an absolute provider asset URL, or reject anything else.

    Same-origin ChatGPT files and signed ``*.oaiusercontent.com`` assets are
    downloadable. Arbitrary hosts, IP literals, credentials, and non-HTTPS
    URLs are not.
    """

    text = str(url or "").strip()
    parsed = urlsplit(text)
    base = str(base_url or "").strip()
    if not parsed.scheme and not parsed.netloc and base:
        text = urljoin(f"{base.rstrip('/')}/", text.lstrip("/"))
        parsed = urlsplit(text)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ProviderAssetUrlError("image download URL host is not allowed")
    if parsed.username is not None or parsed.password is not None:
        raise ProviderAssetUrlError("image download URL host is not allowed")
    host = _hostname(parsed.hostname)
    if not host or _is_ip_literal(host):
        raise ProviderAssetUrlError("image download URL host is not allowed")
    if urls_share_browser_origin(text, base) or _host_allowed(host):
        return text
    raise ProviderAssetUrlError("image download URL host is not allowed")
