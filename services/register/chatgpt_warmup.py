"""Read-only ChatGPT requests on the same registration session."""

from __future__ import annotations

from services.browser_fingerprint import CHROME146_TIMEZONE_OFFSET_MIN, chrome146_headers
from services.proxy_service import proxy_settings

_HOME_URL = "https://chatgpt.com/"
_API_PATHS = (
    "/backend-api/me",
    f"/backend-api/accounts/check/v4-2023-04-27?timezone_offset_min={CHROME146_TIMEZONE_OFFSET_MIN}",
    "/backend-api/models?history_and_training_disabled=false",
    "/backend-api/settings/user",
    "/backend-api/conversations?offset=0&limit=28&order=updated",
)


def warmup_registered_session(
    session,
    *,
    access_token: str,
    device_id: str,
    session_id: str,
    fingerprint: dict | None = None,
) -> list[str]:
    """GET the ChatGPT home page and known read endpoints. Never raises."""

    del fingerprint
    warnings: list[str] = []
    document_headers = chrome146_headers(
        {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        }
    )
    warning = _read(session, _HOME_URL, document_headers)
    if warning:
        warnings.append(warning)

    api_headers = chrome146_headers(
        {
            "Accept": "application/json",
            "Authorization": f"Bearer {str(access_token or '').strip()}",
            "Origin": "https://chatgpt.com",
            "Referer": "https://chatgpt.com/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "oai-device-id": str(device_id or "").strip(),
            "oai-session-id": str(session_id or "").strip(),
        }
    )
    for path in _API_PATHS:
        warning = _read(session, f"https://chatgpt.com{path}", api_headers)
        if warning:
            warnings.append(warning)
    return warnings


def _read(session, url: str, headers: dict) -> str:
    try:
        response = session.get(
            url,
            headers=headers,
            timeout=20,
            verify=not proxy_settings.should_skip_ssl_verify(),
        )
    except Exception as exc:
        return f"GET {url} 失败: {exc}"
    status = int(getattr(response, "status_code", 0) or 0)
    if status != 200:
        return f"GET {url} 返回 HTTP {status or 'unknown'}"
    return ""
