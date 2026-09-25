from __future__ import annotations

import ipaddress
import socket
from urllib.parse import ParseResult, urlparse

from curl_cffi import CurlOpt
from fastapi import HTTPException


def validate_public_image_url(source: str) -> tuple[ParseResult, tuple[str, ...]]:
    """Reject a remote image URL that is not a public HTTP(S) target.

    The hostname is resolved before the request. Loopback, private, link-local,
    and other non-global addresses are refused so a caller cannot use this
    process as an SSRF client. Each redirect must be validated again.
    """

    parsed = urlparse(source)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=400, detail={"error": "image_url must be an http or https URL"})
    if parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail={"error": "image_url must not include credentials"})
    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"error": "invalid image_url host"}) from exc
    if not hostname:
        raise HTTPException(status_code=400, detail={"error": "invalid image_url host"})
    normalized_host = hostname.rstrip(".").lower()
    if (
        normalized_host in {"localhost", "localhost.localdomain"}
        or normalized_host.endswith(".localhost")
        or normalized_host.endswith(".local")
    ):
        raise HTTPException(status_code=400, detail={"error": "image_url host is not publicly reachable"})
    try:
        literal = ipaddress.ip_address(normalized_host)
    except ValueError:
        literal = None
    if literal is not None:
        addresses = [str(literal)]
    else:
        try:
            addresses = [
                item[4][0]
                for item in socket.getaddrinfo(normalized_host, port, type=socket.SOCK_STREAM)
            ]
        except OSError as exc:
            raise HTTPException(status_code=400, detail={"error": "image_url host could not be resolved"}) from exc
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise HTTPException(status_code=400, detail={"error": "image_url host is not publicly reachable"})
    return parsed, tuple(dict.fromkeys(addresses))


def public_image_curl_options(parsed: ParseResult, addresses: tuple[str, ...]) -> dict[CurlOpt, object]:
    """Pin the connection to the addresses already accepted for this hop."""

    hostname = parsed.hostname or ""
    try:
        ipaddress.ip_address(hostname.rstrip("."))
    except ValueError:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        resolved = [
            f"{hostname}:{port}:{f'[{address}]' if ':' in address else address}"
            for address in addresses
        ]
    else:
        resolved = []
    options: dict[CurlOpt, object] = {CurlOpt.NOPROXY: "*"}
    if resolved:
        options[CurlOpt.RESOLVE] = resolved
    return options
