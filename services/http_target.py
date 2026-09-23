"""Validated and DNS-pinned options for configured HTTP integrations."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from ipaddress import ip_address
import socket
from typing import Any
from urllib.parse import urlsplit

from curl_cffi import CurlOpt


class HttpTargetError(ValueError):
    """Raised when a configured HTTP target cannot be used safely."""


def resolve_http_target(url: object) -> tuple[str, tuple[str, ...]]:
    """Validate an HTTP(S) URL and resolve its host for connection pinning."""

    text = str(url or "").strip()
    try:
        parsed = urlsplit(text)
    except ValueError as exc:
        raise HttpTargetError("configured HTTP target URL is invalid") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise HttpTargetError("configured HTTP target must be an HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise HttpTargetError("configured HTTP target must not include credentials")
    host = str(parsed.hostname or "").strip()
    if not host:
        raise HttpTargetError("configured HTTP target must include a host")
    try:
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError as exc:
        raise HttpTargetError("configured HTTP target port is invalid") from exc

    try:
        ip_address(host)
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise HttpTargetError("configured HTTP target host could not be resolved") from exc
        addresses = {
            str(info[4][0])
            for info in infos
            if len(info) >= 5 and info[4] and str(info[4][0]).strip()
        }
    else:
        addresses = {host}
    if not addresses:
        raise HttpTargetError("configured HTTP target host could not be resolved")
    return text, tuple(sorted(addresses))


def build_http_target_request_options(
    url: object,
    *,
    allow_redirects: bool = False,
) -> dict[str, object]:
    """Return request options with the validated host pinned to its addresses."""

    text, addresses = resolve_http_target(url)
    parsed = urlsplit(text)
    host = str(parsed.hostname or "").strip()
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    try:
        ip_address(host)
    except ValueError:
        resolve = [
            f"{host}:{port}:{f'[{address}]' if ':' in address else address}"
            for address in addresses
        ]
    else:
        resolve = []
    return {
        "allow_redirects": bool(allow_redirects),
        "curl_options": {CurlOpt.RESOLVE: resolve} if resolve else {},
    }


@contextmanager
def http_target_session_request(
    session: Any,
    url: object,
    *,
    allow_redirects: bool = False,
) -> Iterator[dict[str, object]]:
    """Pin DNS on a curl_cffi Session without passing curl_options to request()."""

    options = build_http_target_request_options(url, allow_redirects=allow_redirects)
    curl_options = options.get("curl_options") if isinstance(options.get("curl_options"), dict) else {}
    resolve = curl_options.get(CurlOpt.RESOLVE) if isinstance(curl_options, dict) else None

    session_curl_options = getattr(session, "curl_options", None)
    if not isinstance(session_curl_options, dict):
        session_curl_options = {}
        session.curl_options = session_curl_options

    had_resolve = CurlOpt.RESOLVE in session_curl_options
    previous_resolve = session_curl_options.get(CurlOpt.RESOLVE)
    if resolve:
        session_curl_options[CurlOpt.RESOLVE] = resolve
    try:
        yield {"allow_redirects": options["allow_redirects"]}
    finally:
        if resolve:
            if had_resolve:
                session_curl_options[CurlOpt.RESOLVE] = previous_resolve
            else:
                session_curl_options.pop(CurlOpt.RESOLVE, None)
