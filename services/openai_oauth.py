"""Shared OpenAI OAuth protocol constants and request headers."""

from __future__ import annotations

from services.browser_fingerprint import (
    CHROME146_SEC_CH_UA,
    CHROME146_SEC_CH_UA_FULL_VERSION_LIST,
    CHROME146_USER_AGENT,
    chrome146_headers,
)


auth_base = "https://auth.openai.com"
platform_base = "https://platform.openai.com"
platform_oauth_client_id = "app_2SKx67EdpoN0G6j64rFvigXD"
platform_oauth_redirect_uri = f"{platform_base}/auth/callback"
platform_oauth_audience = "https://api.openai.com/v1"
platform_auth0_client = "eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjEuMjEuMCJ9"

user_agent = CHROME146_USER_AGENT
sec_ch_ua = CHROME146_SEC_CH_UA
sec_ch_ua_full_version_list = CHROME146_SEC_CH_UA_FULL_VERSION_LIST

common_headers = chrome146_headers({
    "accept": "application/json",
    "accept-encoding": "gzip, deflate, br",
    "connection": "keep-alive",
    "content-type": "application/json",
    "dnt": "1",
    "origin": auth_base,
    "sec-gpc": "1",
    "sec-fetch-site": "same-origin",
})


def platform_token_exchange_headers() -> dict[str, object]:
    """Headers for auth.openai.com token exchange started from platform.openai.com."""
    return {
        **common_headers,
        "referer": f"{platform_base}/",
        "origin": platform_base,
        "auth0-client": platform_auth0_client,
        "sec-fetch-site": "same-site",
    }


def refresh_token_headers() -> dict[str, object]:
    """Headers for auth.openai.com/oauth/token refresh started from platform.openai.com."""
    return chrome146_headers({
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": platform_base,
        "Referer": f"{platform_base}/",
        "Sec-Fetch-Site": "same-site",
    }, include_defaults=False)
