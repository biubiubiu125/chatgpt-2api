from __future__ import annotations

import base64
import json
import random
import secrets
import string
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

from curl_cffi import requests

from services.account_service import account_service
from services.browser_fingerprint import (
    CHROME146_ACCEPT_LANGUAGE,
    CHROME146_IMPERSONATE,
    CHROME146_SEC_CH_UA,
    CHROME146_SEC_CH_UA_FULL_VERSION,
    CHROME146_SEC_CH_UA_FULL_VERSION_LIST,
    CHROME146_SEC_CH_UA_PLATFORM,
    CHROME146_SEC_CH_UA_PLATFORM_VERSION,
    CHROME146_USER_AGENT,
    browser_origin,
    chrome146_headers,
    navigation_sec_fetch_site,
)
from services.config import DATA_DIR
from services.proxy_service import ClearanceBundle, normalize_proxy_url, proxy_settings
from services.image_failure import InvalidAccessTokenError
from services.register import mail_provider
from services.register.errors import (
    REGISTER_CORE_STAGE_LABELS,
    RegisterError,
    classify_register_error,
    display_register_stage,
    format_register_error,
    looks_like_cloudflare_challenge,
)
from services.register.log_redaction import redact_register_log_text
from services.register.recovery_crypto import read_secure_json_file, write_secure_json_file
from services.register.state_machine import RegisterCoreStage, RegisterCoreStateMachine
from utils.helper import UpstreamHTTPError
from utils.timezone import TIME_FORMAT, beijing_now_str

config = {
    "mail": {
        "request_timeout": 30,
        "wait_timeout": 30,
        "wait_interval": 2,
        "api_use_register_proxy": False,
        "providers": [],
    },
    "proxy": "",
    "proxy_required": True,
    "total": 10,
    "threads": 3,
}
register_core_results_pending_file = DATA_DIR / "register_core_results_pending.json"
register_core_results_lock = threading.Lock()

auth_base = "https://auth.openai.com"
platform_base = "https://platform.openai.com"
platform_oauth_client_id = "app_2SKx67EdpoN0G6j64rFvigXD"
platform_oauth_redirect_uri = f"{platform_base}/auth/callback"
platform_oauth_audience = "https://api.openai.com/v1"
platform_auth0_client = "eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjEuMjEuMCJ9"
AUTH_NAVIGATION_HOSTS = frozenset({"auth.openai.com", "chatgpt.com", "platform.openai.com"})
AUTH_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
REGISTER_PROXY_SCHEMES = frozenset({"http", "https", "socks5", "socks5h"})
REGISTER_PROXY_REFERENCES = frozenset({"", "direct", "global"})
REGISTER_BROWSER_PROFILES: tuple[dict[str, str], ...] = (
    {
        "impersonate": CHROME146_IMPERSONATE,
        "major": "146",
        "full_version": "146.0.0.0",
        "platform_version": "10.0.0",
        "accept_language": CHROME146_ACCEPT_LANGUAGE,
    },
)


def _chrome_user_agent(_major: str = "", _full_version: str = "") -> str:
    return CHROME146_USER_AGENT


def _chrome_sec_ch_ua(_major: str = "") -> str:
    return CHROME146_SEC_CH_UA


def is_register_proxy_url(value: object) -> bool:
    raw = str(value or "").strip()
    lower = raw.lower()
    if not raw or lower in REGISTER_PROXY_REFERENCES or lower.startswith(("group:", "profile:")):
        return False
    if "***" in raw:
        return False
    parsed = urlparse(normalize_proxy_url(raw))
    return parsed.scheme in REGISTER_PROXY_SCHEMES and bool(parsed.netloc)


def normalize_register_proxy(value: object) -> str:
    raw = str(value or "").strip()
    if not is_register_proxy_url(raw):
        return ""
    return normalize_proxy_url(raw)


def _chrome_sec_ch_ua_full_version_list(_major: str = "", _full_version: str = "") -> str:
    return CHROME146_SEC_CH_UA_FULL_VERSION_LIST


def _complete_browser_fingerprint(profile: dict[str, str]) -> dict[str, str]:
    # 注册链路不接受外部传入的旧浏览器版本，所有指纹字段统一收敛到
    # curl_cffi 的 Chrome146 impersonation 和同一套 Client Hints。
    major = "146"
    full_version = "146.0.0.0"
    return {
        **profile,
        "major": major,
        "full_version": full_version,
        "user_agent": _chrome_user_agent(major, full_version),
        "sec_ch_ua": _chrome_sec_ch_ua(major),
        "sec_ch_ua_full_version_list": _chrome_sec_ch_ua_full_version_list(major, full_version),
        "accept_language": CHROME146_ACCEPT_LANGUAGE,
        "platform_version": CHROME146_SEC_CH_UA_PLATFORM_VERSION.strip('"'),
        "impersonate": CHROME146_IMPERSONATE,
    }


DEFAULT_BROWSER_FINGERPRINT = _complete_browser_fingerprint(REGISTER_BROWSER_PROFILES[0])
user_agent = DEFAULT_BROWSER_FINGERPRINT["user_agent"]
sec_ch_ua = DEFAULT_BROWSER_FINGERPRINT["sec_ch_ua"]
sec_ch_ua_full_version_list = DEFAULT_BROWSER_FINGERPRINT["sec_ch_ua_full_version_list"]
default_timeout = 30
print_lock = threading.Lock()
stats_lock = threading.Lock()
stats = {"done": 0, "success": 0, "fail": 0, "start_time": 0.0}
register_log_sink = None

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

navigate_headers = chrome146_headers({
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "accept-encoding": "gzip, deflate, br",
    "cache-control": "max-age=0",
    "connection": "keep-alive",
    "dnt": "1",
    "sec-gpc": "1",
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "same-origin",
    "sec-fetch-user": "?1",
    "upgrade-insecure-requests": "1",
})


def _browser_fingerprint(fingerprint: dict[str, str] | None = None) -> dict[str, str]:
    return _complete_browser_fingerprint(fingerprint or DEFAULT_BROWSER_FINGERPRINT)


def _header_fingerprint(headers: dict[str, str], fingerprint: dict[str, str] | None = None) -> dict[str, str]:
    fp = _browser_fingerprint(fingerprint)
    next_headers = chrome146_headers(headers)
    next_headers["user-agent"] = fp["user_agent"]
    next_headers["sec-ch-ua"] = fp["sec_ch_ua"]
    next_headers["sec-ch-ua-full-version"] = CHROME146_SEC_CH_UA_FULL_VERSION
    next_headers["sec-ch-ua-full-version-list"] = fp["sec_ch_ua_full_version_list"]
    next_headers["sec-ch-ua-platform-version"] = f'"{fp["platform_version"]}"'
    next_headers["accept-language"] = fp["accept_language"]
    return {str(key).lower(): str(value) for key, value in next_headers.items()}


def _extract_chrome_version_from_user_agent(value: str) -> tuple[str, str]:
    ua = str(value or "")
    for marker in ("Chrome/", "Chromium/", "Edg/"):
        if marker not in ua:
            continue
        tail = ua.split(marker, 1)[1]
        version = tail.split(" ", 1)[0].strip()
        major = version.split(".", 1)[0].strip()
        if major.isdigit():
            return major, version or f"{major}.0.0.0"
    return "", ""


def _fingerprint_with_user_agent(fingerprint: dict[str, str] | None, value: str) -> dict[str, str]:
    ua = str(value or "").strip()
    fp = _browser_fingerprint(fingerprint)
    if not ua:
        return fp
    major, full_version = _extract_chrome_version_from_user_agent(ua)
    if major != "146":
        return fp
    return fp


def _make_browser_fingerprint() -> dict[str, str]:
    return _complete_browser_fingerprint(REGISTER_BROWSER_PROFILES[0])


def _account_fingerprint_payload(
    fingerprint: dict[str, str] | None,
    *,
    device_id: str = "",
    session_id: str = "",
) -> dict[str, str]:
    fp = _browser_fingerprint(fingerprint)
    payload = {
        "user-agent": fp["user_agent"],
        "impersonate": fp["impersonate"],
        "sec-ch-ua": fp["sec_ch_ua"],
        "sec-ch-ua-full-version": f'"{fp["full_version"]}"',
        "sec-ch-ua-full-version-list": fp["sec_ch_ua_full_version_list"],
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": CHROME146_SEC_CH_UA_PLATFORM,
        "sec-ch-ua-platform-version": f'"{fp["platform_version"]}"',
        "accept-language": fp["accept_language"],
    }
    if device_id:
        payload["oai-device-id"] = device_id
    if session_id:
        payload["oai-session-id"] = session_id
    return payload


def _session_cookie_payload(session: Any) -> dict[str, str]:
    cookies: dict[str, str] = {}
    jar = getattr(session, "cookies", None)
    if jar is None:
        return cookies
    try:
        items = jar.items() if hasattr(jar, "items") else []
        for name, value in items:
            name_text = str(name or "").strip()
            value_text = str(value or "").strip()
            if name_text and value_text:
                cookies[name_text] = value_text
        if cookies:
            return cookies
    except Exception:
        cookies = {}
    try:
        for cookie in jar:
            name_text = str(getattr(cookie, "name", "") or "").strip()
            value_text = str(getattr(cookie, "value", "") or "").strip()
            if name_text and value_text:
                cookies[name_text] = value_text
    except Exception:
        return cookies
    return cookies


def log(text: str, color: str = "") -> None:
    colors = {"red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m"}
    safe_text = redact_register_log_text(text)
    if register_log_sink:
        try:
            register_log_sink(safe_text, color)
        except Exception:
            pass
    with print_lock:
        prefix = colors.get(color, "")
        suffix = "\033[0m" if prefix else ""
        print(f"{prefix}{beijing_now_str(TIME_FORMAT)} {safe_text}{suffix}")


def step(index: int, text: str, color: str = "") -> None:
    log(f"[任务{index}] {text}", color)


def _pending_core_result_rows() -> list[dict[str, Any]]:
    data = read_secure_json_file(
        register_core_results_pending_file,
        default_factory=list,
        expected_types=(list, dict),
    )
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    rows = data.get("items") if isinstance(data, dict) else None
    if isinstance(rows, list):
        return [item for item in rows if isinstance(item, dict)]
    return [item for item in data.values() if isinstance(item, dict)] if isinstance(data, dict) else []


def write_pending_core_result_rows(rows: list[dict[str, Any]]) -> None:
    write_secure_json_file(register_core_results_pending_file, rows[-500:])


def _core_result_recovery_item(result: dict[str, Any], *, reason: object = "", stage: str = "", index: int = 0) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    item = {
        "email": str(result.get("email") or "").strip(),
        "password": str(result.get("password") or ""),
        "access_token": str(result.get("access_token") or "").strip(),
        "refresh_token": str(result.get("refresh_token") or "").strip(),
        "id_token": str(result.get("id_token") or "").strip(),
        "source_type": str(result.get("source_type") or "web").strip() or "web",
        "created_at": str(result.get("created_at") or now).strip(),
        "failure_reason": str(reason or "").strip(),
        "register_stage": display_register_stage(stage, fallback="finalize") or "收口",
        "task_index": int(index or 0),
        "status": "pending",
        "retry_count": 0,
        "last_error": "",
        "next_retry_at": "",
        "updated_at": now,
    }
    if isinstance(result.get("fp"), dict):
        item["fp"] = dict(result["fp"])
    for key in ("register_proxy", "proxy", "clearance_user_agent"):
        value = str(result.get(key) or "").strip()
        if value:
            item[key] = value
    if isinstance(result.get("cookies"), dict):
        item["cookies"] = dict(result["cookies"])
    return item


def record_pending_core_result(result: dict[str, Any], *, reason: object = "", stage: str = "", index: int = 0) -> str:
    try:
        if not isinstance(result, dict):
            return "注册核心结果格式无效，无法暂存"
        item = _core_result_recovery_item(result, reason=reason, stage=stage, index=index)
        access_token = str(item.get("access_token") or "").strip()
        if not access_token:
            return "注册核心结果缺少 access_token，无法暂存"
        email = str(item.get("email") or "").strip().lower()
        with register_core_results_lock:
            rows = _pending_core_result_rows()
            merged: list[dict[str, Any]] = []
            for row in rows:
                row_token = str(row.get("access_token") or "").strip()
                row_email = str(row.get("email") or "").strip().lower()
                if row_token and row_token == access_token:
                    continue
                if email and row_email == email:
                    continue
                merged.append(row)
            merged.append(item)
            write_pending_core_result_rows(merged)
        return ""
    except Exception as exc:
        return str(exc) or exc.__class__.__name__


def remove_pending_core_result(access_token: object) -> str:
    token = str(access_token or "").strip()
    if not token:
        return ""
    try:
        with register_core_results_lock:
            rows = _pending_core_result_rows()
            kept = [row for row in rows if str(row.get("access_token") or "").strip() != token]
            if len(kept) != len(rows):
                write_pending_core_result_rows(kept)
        return ""
    except Exception as exc:
        return str(exc) or exc.__class__.__name__


def _make_trace_headers() -> dict[str, str]:
    trace_id = str(random.getrandbits(64))
    parent_id = str(random.getrandbits(64))
    return {
        "traceparent": f"00-{uuid.uuid4().hex}-{format(int(parent_id), '016x')}-01",
        "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum",
        "x-datadog-parent-id": parent_id,
        "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": trace_id,
    }


from utils.pkce import generate_pkce as _generate_pkce  # noqa: F401


def _random_password(length: int = 16) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%"
    value = list(
        secrets.choice(string.ascii_uppercase)
        + secrets.choice(string.ascii_lowercase)
        + secrets.choice(string.digits)
        + secrets.choice("!@#$%")
        + "".join(secrets.choice(chars) for _ in range(max(0, length - 4)))
    )
    random.shuffle(value)
    return "".join(value)


def _random_name() -> tuple[str, str]:
    return random.choice(["James", "Robert", "John", "Michael", "David", "Mary", "Emma", "Olivia"]), random.choice(
        ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller"]
    )


def _random_birthdate() -> str:
    return f"{random.randint(1996, 2006):04d}-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}"


def _response_json(resp) -> dict:
    try:
        data = resp.json()
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _safe_json_detail(value: object, limit: int = 0) -> str:
    try:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        encoded = str(value or "")
    if int(limit) > 0:
        encoded = encoded[: int(limit)]
    return redact_register_log_text(encoded)


def _safe_response_body(resp, limit: int = 0) -> str:
    if resp is None:
        return ""
    try:
        text = str(getattr(resp, "text", "") or "")
    except Exception:
        return ""
    if int(limit) > 0:
        text = text[: int(limit)]
    return redact_register_log_text(text)


def _response_debug_detail(resp, limit: int = 0) -> str:
    if resp is None:
        return ""
    data = _response_json(resp)
    parts = [
        f"url={_safe_url_for_log(str(getattr(resp, 'url', '') or ''))}",
        f"content_type={str(getattr(resp, 'headers', {}).get('content-type') or '')}",
    ]
    for key in ("cf-ray", "x-request-id", "openai-processing-ms"):
        value = str(getattr(resp, "headers", {}).get(key) or "").strip()
        if value:
            parts.append(f"{key}={value}")
    if data:
        dumped = json.dumps(data, ensure_ascii=False)
        if limit > 0:
            dumped = dumped[:limit]
        parts.append(f"json={redact_register_log_text(dumped)}")
    else:
        body = str(getattr(resp, "text", "") or "")
        if limit > 0:
            body = body[:limit]
        parts.append(f"body={redact_register_log_text(body)}")
    return ", ".join(parts)


def _is_cloudflare_challenge(resp) -> bool:
    if resp is None:
        return False
    try:
        status_code = int(getattr(resp, "status_code", 0) or 0)
    except (TypeError, ValueError):
        status_code = 0
    if status_code not in (403, 503):
        return False
    return looks_like_cloudflare_challenge(getattr(resp, "text", "") or "")


def _mail_config(register_proxy: str = "") -> dict:
    mail = dict(config["mail"]) if isinstance(config.get("mail"), dict) else {}
    register = str(register_proxy or "").strip() or "direct"
    mail["_register_proxy"] = register
    if bool(mail.get("api_use_register_proxy")):
        mail["proxy"] = register
    else:
        mail["proxy"] = str(mail.get("proxy") or "").strip() or "direct"
    return mail


def _authorize_landed_page(resp) -> str:
    """诊断用：粗判 authorize 之后落在哪个页面。返回 signup / login / "" 仅供日志。

    注意：email-verification / email_otp_verification 在注册和登录流程里都会出现，
    无法据此可靠区分，所以这里只用于打日志，绝不据此中断注册流程。
    """
    if resp is None:
        return ""
    final_url = str(getattr(resp, "url", "") or "").lower()
    data = _response_json(resp)
    page_type = ""
    page = data.get("page") if isinstance(data, dict) else None
    if isinstance(page, dict):
        page_type = str(page.get("type") or "").lower()
    if "create-account" in final_url or "signup" in final_url or "create_account" in page_type:
        return "signup"
    if "/log-in" in final_url or "/login" in final_url or page_type in {"login", "password_verification"}:
        return "login"
    return ""


def create_mailbox(username: str | None = None, register_proxy: str = "") -> dict:
    return mail_provider.create_mailbox(_mail_config(register_proxy), username)


def _mailbox_wait_timeout_seconds() -> int:
    mail = config.get("mail") if isinstance(config.get("mail"), dict) else {}
    try:
        return max(1, int(mail.get("wait_timeout") or 30))
    except (TypeError, ValueError):
        return 30


def _mailbox_wait_timeout_error(
    mailbox: dict | None,
    *,
    login: bool = False,
    register_proxy: str = "",
) -> RegisterError:
    mailbox = mailbox if isinstance(mailbox, dict) else {}
    email = str(mailbox.get("email") or "").strip()
    provider = str(mailbox.get("provider") or mailbox.get("type") or mailbox.get("source") or "").strip() or "unknown"
    timeout = _mailbox_wait_timeout_seconds()
    proxy = str(register_proxy or "").strip() or "direct"
    original = f"邮箱={email}，来源={provider}，代理={proxy}，wait_timeout={timeout}s"
    if login:
        return RegisterError(
            "mailbox_login_wait_timeout",
            f"等待 Microsoft 登录验证码超时（{timeout} 秒）。这不是 Cloudflare 拦截。",
            original=original,
            stage="等待 Microsoft 登录验证码",
        )
    return RegisterError(
        "mailbox_wait_timeout",
        f"等待注册验证码超时（{timeout} 秒）。这不是 Cloudflare 拦截。",
        original=original,
        stage="等待验证码",
    )


def wait_for_code(mailbox: dict, register_proxy: str = "", *, login: bool = False) -> str:
    try:
        code = mail_provider.wait_for_code(_mail_config(register_proxy), mailbox)
    except RegisterError as exc:
        if exc.code in {"mailbox_wait_timeout", "mailbox_login_wait_timeout"}:
            raise _mailbox_wait_timeout_error(
                mailbox,
                login=login,
                register_proxy=register_proxy,
            ) from exc
        raise
    except Exception as exc:
        classified = classify_register_error(exc, stage="等待验证码")
        if classified.code in {"mailbox_wait_timeout", "mailbox_login_wait_timeout"}:
            raise _mailbox_wait_timeout_error(
                mailbox,
                login=login,
                register_proxy=register_proxy,
            ) from exc
        raise
    if str(code or "").strip():
        return str(code).strip()
    raise _mailbox_wait_timeout_error(mailbox, login=login, register_proxy=register_proxy)


from utils.sentinel import (
    build_sentinel_token as _build_sentinel_token_tuple,
    build_sentinel_with_so_token,
)


def build_sentinel_token(
    session: requests.Session,
    device_id: str,
    flow: str,
    fingerprint: dict[str, str] | None = None,
) -> str:
    """请求 sentinel token，返回 sentinel header 字符串（兼容旧接口）。"""
    fp = _browser_fingerprint(fingerprint)
    sentinel_val, _oai_sc_val = _build_sentinel_token_tuple(
        session,
        device_id,
        flow,
        user_agent=fp["user_agent"],
        sec_ch_ua=fp["sec_ch_ua"],
    )
    return sentinel_val


def create_session(proxy: str = "", fingerprint: dict[str, str] | None = None) -> Any:
    proxy = str(proxy or "").strip()
    if not is_register_proxy_url(proxy):
        raise RuntimeError("注册必须使用住宅代理地址")
    fp = _browser_fingerprint(fingerprint)
    kwargs = proxy_settings.build_session_kwargs(
        proxy=proxy,
        upstream=True,
        impersonate=fp["impersonate"],
        verify=not proxy_settings.should_skip_ssl_verify(),
    )
    session = requests.Session(**kwargs)
    session.headers.update(chrome146_headers({"user-agent": fp["user_agent"]}))
    return session


def _apply_clearance_to_session(session: requests.Session, bundle: ClearanceBundle | None) -> None:
    if bundle is None:
        return
    if bundle.user_agent:
        session.headers["user-agent"] = DEFAULT_BROWSER_FINGERPRINT["user_agent"]
    for name, value in bundle.cookies.items():
        try:
            session.cookies.set(name, value, domain=f".{bundle.target_host or 'openai.com'}")
            session.cookies.set(name, value, domain=bundle.target_host or "auth.openai.com")
        except Exception:
            continue


def _headers_with_clearance(
    headers: dict[str, str],
    target_url: str,
    proxy: str = "",
    user_agent_override: str = "",
) -> dict[str, str]:
    merged = proxy_settings.build_headers(
        headers=headers,
        target_url=target_url,
        proxy=proxy,
        upstream=True,
    )
    normalized = {str(key): str(value) for key, value in merged.items()}
    if user_agent_override:
        ua_key = next((key for key in normalized if key.lower() == "user-agent"), "user-agent")
        normalized[ua_key] = DEFAULT_BROWSER_FINGERPRINT["user_agent"]
    return normalized


def _cloudflare_block_message(resp, prefix: str = "被 Cloudflare 拦截", reason: str = "") -> str:
    status = getattr(resp, "status_code", "unknown")
    debug = _response_debug_detail(resp)
    reason = reason or "clearance 刷新失败或重试后仍失败，请更换 IP/代理重试"
    return f"{prefix}，{reason}: status={status}, {debug}"


def _cloudflare_block_error(resp, prefix: str = "被 Cloudflare 拦截", reason: str = "") -> RegisterError:
    return RegisterError(
        "cloudflare_block",
        "请求被 Cloudflare 拦截。这不是 Token 失效，也不是邮箱接码超时。",
        original=_cloudflare_block_message(resp, prefix=prefix, reason=reason),
        stage="Cloudflare",
    )


def request_with_local_retry(session: requests.Session, method: str, url: str, retry_attempts: int = 3, **kwargs):
    kwargs.setdefault("allow_redirects", False)
    last_error = ""
    for _ in range(max(1, retry_attempts)):
        try:
            return session.request(method.upper(), url, timeout=default_timeout, **kwargs), ""
        except Exception as error:
            last_error = redact_register_log_text(error)
            time.sleep(1)
    return None, last_error


def _validate_auth_url(url: str) -> str:
    value = str(url or "").strip()
    if not value:
        return ""
    try:
        initial = urlparse(value)
    except ValueError as exc:
        raise ValueError("不受信任的认证 URL") from exc
    if not initial.scheme and not initial.netloc and not value.startswith("//"):
        value = urljoin(f"{auth_base}/", value)
    try:
        parsed = urlparse(value)
        hostname = str(parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError as exc:
        raise ValueError("不受信任的认证 URL") from exc
    if (
        parsed.scheme.lower() != "https"
        or not hostname
        or hostname not in AUTH_NAVIGATION_HOSTS
        or parsed.username
        or parsed.password
        or port not in (None, 443)
    ):
        raise ValueError("不受信任的认证 URL")
    return value


def _header_value(headers: dict, name: str) -> str:
    for key, value in headers.items():
        if str(key).lower() == name:
            return str(value or "")
    return ""


def _set_header_value(headers: dict, name: str, value: str) -> None:
    for key in list(headers):
        if str(key).lower() == name:
            headers[key] = value
            return
    headers[name] = value


def _document_origin(url: str) -> str:
    parsed = browser_origin(url)
    if parsed is None:
        return ""
    scheme, host, port, _site = parsed
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def _apply_navigation_fetch_metadata(headers: dict, referer: str, target: str) -> dict:
    current_referer = str(referer or "").strip() or _header_value(headers, "referer")
    if current_referer:
        _set_header_value(headers, "referer", current_referer)
    _set_header_value(
        headers,
        "sec-fetch-site",
        navigation_sec_fetch_site(current_referer, target),
    )
    return headers


def _request_trusted_auth_navigation(
    session: requests.Session,
    url: str,
    headers_factory,
    *,
    verify: bool,
    max_redirects: int = 10,
):
    current = _validate_auth_url(url)
    hop_referer = ""
    last_response = None
    last_error = ""
    for _ in range(max(0, int(max_redirects)) + 1):
        headers = _apply_navigation_fetch_metadata(
            dict(headers_factory(current) or {}),
            hop_referer,
            current,
        )
        last_response, last_error = request_with_local_retry(
            session,
            "get",
            current,
            headers=headers,
            allow_redirects=False,
            verify=verify,
        )
        if last_response is None:
            return None, last_error, current
        status = int(getattr(last_response, "status_code", 0) or 0)
        if status not in AUTH_REDIRECT_STATUSES:
            return last_response, last_error, current
        location = str(getattr(last_response, "headers", {}).get("Location") or "").strip()
        if not location:
            return last_response, last_error, current
        next_url = _validate_auth_url(urljoin(current, location))
        hop_referer = current
        current = next_url
    return last_response, "认证重定向次数超过限制", current


def validate_otp(
    session: requests.Session,
    device_id: str,
    code: str,
    fingerprint: dict[str, str] | None = None,
):
    headers = _header_fingerprint(common_headers, fingerprint)
    headers["referer"] = f"{auth_base}/email-verification"
    headers["oai-device-id"] = device_id
    headers.update(_make_trace_headers())
    resp, error = request_with_local_retry(session, "post", f"{auth_base}/api/accounts/email-otp/validate", json={"code": code}, headers=headers, verify=not proxy_settings.should_skip_ssl_verify())
    if resp is not None and resp.status_code == 200:
        return resp, ""
    headers["openai-sentinel-token"] = build_sentinel_token(session, device_id, "authorize_continue", fingerprint)
    resp, error = request_with_local_retry(session, "post", f"{auth_base}/api/accounts/email-otp/validate", json={"code": code}, headers=headers, verify=not proxy_settings.should_skip_ssl_verify())
    return resp, error


def extract_oauth_callback_params_from_url(url: str) -> dict[str, str] | None:
    if not url:
        return None
    try:
        params = parse_qs(urlparse(url).query)
    except Exception:
        return None
    code = str((params.get("code") or [""])[0]).strip()
    if not code:
        return None
    return {"code": code, "state": str((params.get("state") or [""])[0]).strip(), "scope": str((params.get("scope") or [""])[0]).strip()}


def extract_continue_url(data: dict[str, Any] | None) -> str:
    if not isinstance(data, dict):
        return ""
    direct = str(data.get("continue_url") or data.get("continueUrl") or "").strip()
    if direct:
        return direct
    page = data.get("page")
    if isinstance(page, dict):
        payload = page.get("payload")
        if isinstance(payload, dict):
            nested = str(
                payload.get("continue_url")
                or payload.get("continueUrl")
                or payload.get("next_url")
                or payload.get("nextUrl")
                or ""
            ).strip()
            if nested:
                return nested
    session_info = data.get("oai-client-auth-session")
    if isinstance(session_info, dict):
        return str(session_info.get("continue_url") or session_info.get("continueUrl") or "").strip()
    return ""


def _absolute_auth_url(url: str) -> str:
    return _validate_auth_url(url)


def _safe_url_for_log(url: str) -> str:
    value = str(url or "").strip()
    if not value:
        return "-"
    return redact_register_log_text(value)


def _url_path(url: str) -> str:
    value = _absolute_auth_url(url)
    try:
        return urlparse(value).path.rstrip("/") or "/"
    except Exception:
        return ""


def _append_exchange_error(errors: list[str] | None, message: str) -> None:
    if errors is not None and message:
        errors.append(redact_register_log_text(message))


def request_platform_oauth_token(
    session: requests.Session,
    code: str,
    code_verifier: str,
    errors: list[str] | None = None,
    fingerprint: dict[str, str] | None = None,
) -> dict | None:
    fp = _browser_fingerprint(fingerprint)
    headers = _header_fingerprint(
        {
            "accept": "*/*",
            "auth0-client": platform_auth0_client,
            "cache-control": "no-cache",
            "content-type": "application/json",
            "origin": platform_base,
            "pragma": "no-cache",
            "priority": "u=1, i",
            "referer": f"{platform_base}/",
            "sec-fetch-site": "same-site",
        },
        fp,
    )
    try:
        resp = session.post(
            f"{auth_base}/api/accounts/oauth/token",
            headers=headers,
            json={
                "client_id": platform_oauth_client_id,
                "code_verifier": code_verifier,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": platform_oauth_redirect_uri,
            },
            verify=not proxy_settings.should_skip_ssl_verify(),
            timeout=60,
        )
    except Exception as error:
        _append_exchange_error(errors, f"api token 请求异常: {str(error)}")
        return None
    if resp.status_code != 200:
        _append_exchange_error(errors, f"api token 接口拒绝: status={resp.status_code}, {_response_debug_detail(resp)}")
        return None
    data = _response_json(resp)
    missing = [key for key in ("access_token", "refresh_token") if not data.get(key)]
    if missing:
        _append_exchange_error(errors, f"api token 返回缺少字段: {', '.join(missing)}")
        return None
    return data


def request_platform_oauth_token_legacy(
    session: requests.Session,
    code: str,
    code_verifier: str,
    proxy: str = "",
    errors: list[str] | None = None,
    fresh_session: bool = False,
    fingerprint: dict[str, str] | None = None,
) -> dict | None:
    token_session = create_session(proxy, fingerprint) if fresh_session else session
    resp = None
    try:
        resp = token_session.post(
            f"{auth_base}/oauth/token",
            headers=_header_fingerprint(
                {
                    "Accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": platform_base,
                    "Referer": f"{platform_base}/",
                    "Sec-Fetch-Site": "same-site",
                },
                fingerprint,
            ),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": platform_oauth_redirect_uri,
                "client_id": platform_oauth_client_id,
                "code_verifier": code_verifier,
            },
            verify=not proxy_settings.should_skip_ssl_verify(),
            timeout=60,
        )
    except Exception as error:
        _append_exchange_error(errors, f"legacy token 请求异常: {str(error)}")
        return None
    finally:
        if fresh_session:
            try:
                token_session.close()
            except Exception:
                pass
    if resp is None:
        _append_exchange_error(errors, "legacy token 未返回响应")
        return None
    data = _response_json(resp)
    if resp.status_code != 200:
        _append_exchange_error(errors, f"legacy token 接口拒绝: status={resp.status_code}, {_response_debug_detail(resp)}")
        return None
    missing = [key for key in ("access_token", "refresh_token", "id_token") if not data.get(key)]
    if missing:
        _append_exchange_error(errors, f"legacy token 返回缺少字段: {', '.join(missing)}")
        return None
    return data


def extract_callback_via_consent(
    session: requests.Session,
    consent_url: str,
    device_id: str,
    proxy: str = "",
    user_agent_override: str = "",
    fingerprint: dict[str, str] | None = None,
    referer: str = "",
) -> dict[str, str] | None:
    current = _absolute_auth_url(consent_url)
    if not current:
        return None
    fp = _fingerprint_with_user_agent(fingerprint, user_agent_override) if user_agent_override else _browser_fingerprint(fingerprint)
    hop_referer = str(referer or "").strip()
    for _ in range(10):
        headers = _apply_navigation_fetch_metadata(
            _headers_with_clearance(_header_fingerprint(navigate_headers, fp), current, proxy, user_agent_override),
            hop_referer,
            current,
        )
        resp, _error = request_with_local_retry(session, "get", current, headers=headers, verify=not proxy_settings.should_skip_ssl_verify(), allow_redirects=False)
        if resp is None:
            return None
        callback = extract_oauth_callback_params_from_url(str(getattr(resp, "url", "") or ""))
        callback = callback or extract_oauth_callback_params_from_url(str(getattr(resp, "headers", {}).get("Location") or ""))
        if callback:
            return callback
        location = str(getattr(resp, "headers", {}).get("Location") or "").strip()
        if getattr(resp, "status_code", 0) not in (301, 302, 303, 307, 308) or not location:
            break
        requested = current
        current = _absolute_auth_url(location)
        hop_referer = requested

    raw = session.cookies.get("oai-client-auth-session", domain=".auth.openai.com") or session.cookies.get("oai-client-auth-session")
    if not raw:
        return None
    try:
        first = raw.split(".")[0]
        pad = 4 - len(first) % 4
        if pad != 4:
            first += "=" * pad
        payload = json.loads(base64.urlsafe_b64decode(first))
        workspace_id = payload["workspaces"][0]["id"]
    except Exception:
        return None

    url = f"{auth_base}/api/accounts/workspace/select"
    headers = _header_fingerprint(common_headers, fp)
    headers["referer"] = current
    headers["oai-device-id"] = device_id
    headers.update(_make_trace_headers())
    headers = _headers_with_clearance(headers, url, proxy, user_agent_override)
    _set_header_value(headers, "sec-fetch-site", navigation_sec_fetch_site(current, url))
    document_origin = _document_origin(current)
    if document_origin:
        _set_header_value(headers, "origin", document_origin)
    ws_resp, _error = request_with_local_retry(session, "post", url, json={"workspace_id": workspace_id}, headers=headers, verify=not proxy_settings.should_skip_ssl_verify(), allow_redirects=False)
    if ws_resp is None:
        return None
    callback = extract_oauth_callback_params_from_url(str(getattr(ws_resp, "headers", {}).get("Location") or ""))
    if callback:
        return callback

    ws_data = _response_json(ws_resp)
    orgs = ((ws_data.get("data") or {}).get("orgs") or []) if isinstance(ws_data, dict) else []
    if not orgs:
        return None
    org_id = str((orgs[0] or {}).get("id") or "").strip()
    project_id = str(((orgs[0] or {}).get("projects") or [{}])[0].get("id") or "").strip()
    if not org_id:
        return None
    org_url = f"{auth_base}/api/accounts/organization/select"
    org_referer = str(ws_data.get("continue_url") or current)
    org_headers = _header_fingerprint(common_headers, fp)
    org_headers["referer"] = org_referer
    org_headers["oai-device-id"] = device_id
    org_headers.update(_make_trace_headers())
    org_headers = _headers_with_clearance(org_headers, org_url, proxy, user_agent_override)
    _set_header_value(org_headers, "sec-fetch-site", navigation_sec_fetch_site(org_referer, org_url))
    org_origin = _document_origin(org_referer)
    if org_origin:
        _set_header_value(org_headers, "origin", org_origin)
    body = {"org_id": org_id}
    if project_id:
        body["project_id"] = project_id
    org_resp, _error = request_with_local_retry(session, "post", org_url, json=body, headers=org_headers, verify=not proxy_settings.should_skip_ssl_verify(), allow_redirects=False)
    if org_resp is None:
        return None
    return extract_oauth_callback_params_from_url(str(getattr(org_resp, "headers", {}).get("Location") or ""))


def exchange_tokens_from_continue_url(
    session: requests.Session,
    device_id: str,
    code_verifier: str,
    continue_url: str,
    proxy: str = "",
    user_agent_override: str = "",
    errors: list[str] | None = None,
    fingerprint: dict[str, str] | None = None,
    referer: str = "",
) -> dict | None:
    start_referer = str(referer or "").strip() or f"{auth_base}/email-verification"
    callback = extract_oauth_callback_params_from_url(continue_url)
    fp = _fingerprint_with_user_agent(fingerprint, user_agent_override) if user_agent_override else _browser_fingerprint(fingerprint)
    callback = callback or extract_callback_via_consent(
        session,
        continue_url,
        device_id,
        proxy,
        user_agent_override,
        fp,
        referer=start_referer,
    )
    if not callback:
        url = _absolute_auth_url(continue_url)
        try:
            resp, navigation_error, final_url = _request_trusted_auth_navigation(
                session,
                url,
                lambda current: _headers_with_clearance(
                    _header_fingerprint({**navigate_headers, "referer": start_referer}, fp),
                    current,
                    proxy,
                    user_agent_override,
                ),
                verify=not proxy_settings.should_skip_ssl_verify(),
            )
            callback = extract_oauth_callback_params_from_url(final_url)
            callback = callback or extract_oauth_callback_params_from_url(str(getattr(resp, "url", "") or ""))
            if not callback:
                for history in getattr(resp, "history", []) or []:
                    callback = extract_oauth_callback_params_from_url(str(history.headers.get("Location") or ""))
                    if callback:
                        break
            if not callback:
                _append_exchange_error(
                    errors,
                    f"跟随 continue_url 后仍未拿到 callback: status={getattr(resp, 'status_code', 'unknown')}, "
                    f"final={_safe_url_for_log(final_url)}, error={navigation_error}",
                )
        except Exception as error:
            _append_exchange_error(errors, f"跟随 continue_url 异常: {str(error)}")
            callback = None
    code = str((callback or {}).get("code") or "").strip()
    if not code:
        _append_exchange_error(errors, f"未拿到 OAuth callback code: continue={_safe_url_for_log(continue_url)}")
        return None
    return request_platform_oauth_token_legacy(session, code, code_verifier, proxy, errors, fresh_session=True, fingerprint=fp)


class PlatformRegistrar:
    def __init__(self, proxy: str = "") -> None:
        self.proxy = str(proxy or "").strip()
        self.fingerprint = _make_browser_fingerprint()
        self.session = create_session(self.proxy, self.fingerprint)
        self.clearance_user_agent = ""
        self.clearance_failure_reason = ""
        self.device_id = str(uuid.uuid4())
        self.session_id = str(uuid.uuid4())
        self.code_verifier = ""
        self.platform_auth_code = ""
        self.last_otp_continue_url = ""
        self.passwordless_signup = False
        self.created_new_account = False
        self.mailbox: dict | None = None
        self._mailbox_result_marked = False
        self._mailbox_result_ok = False
        self._mailbox_result_error = ""
        self._register_state_machine = RegisterCoreStateMachine()
        self._register_stage = self._register_state_machine.state.value
        self._register_stage_detail = ""
        self._register_stage_started_at = time.time()
        self._mailbox_code_received = False

    def close(self) -> None:
        self.session.close()

    @property
    def stage(self) -> str:
        machine = getattr(self, "_register_state_machine", None)
        if isinstance(machine, RegisterCoreStateMachine):
            return machine.state.value
        return self._register_stage

    @property
    def mailbox_result_ok(self) -> bool:
        return self._mailbox_result_ok

    @property
    def mailbox_result_error(self) -> str:
        return self._mailbox_result_error

    @property
    def stage_detail(self) -> str:
        return str(self._register_stage_detail or "")

    @property
    def failed_from_stage(self) -> str:
        machine = getattr(self, "_register_state_machine", None)
        if isinstance(machine, RegisterCoreStateMachine):
            return str(machine.snapshot().get("failed_from") or "")
        return ""

    def _set_stage(self, stage: str, detail: str = "") -> None:
        target = str(stage or RegisterCoreStage.PREFLIGHT.value)
        machine = getattr(self, "_register_state_machine", None)
        if isinstance(machine, RegisterCoreStateMachine):
            machine.transition(target, detail)
            self._register_stage = machine.state.value
        else:
            self._register_stage = target
        self._register_stage_detail = str(detail or "")
        self._register_stage_started_at = time.time()

    def _fail_stage(self, error: Exception) -> None:
        machine = getattr(self, "_register_state_machine", None)
        if isinstance(machine, RegisterCoreStateMachine):
            machine.fail(format_register_error(error, stage=str(getattr(self, "stage", "") or "")))
            self._register_stage = machine.state.value
        else:
            self._register_stage = RegisterCoreStage.FAILED.value
        self._register_stage_detail = format_register_error(error, stage=str(getattr(self, "stage", "") or ""))
        self._register_stage_started_at = time.time()

    def _stage_step(self, index: int, stage: str, text: str, color: str = "") -> None:
        self._set_stage(stage, text)
        label = REGISTER_CORE_STAGE_LABELS.get(stage, stage)
        step(index, f"[{label}] {text}", color)

    def mark_mailbox_success(self) -> bool:
        if self.mailbox is None:
            self._mailbox_result_ok = False
            self._mailbox_result_error = "邮箱尚未初始化"
            return False
        if not self._mailbox_result_marked:
            try:
                ok = bool(mail_provider.mark_mailbox_result(self.mailbox, success=True))
            except Exception as exc:
                ok = False
                self._mailbox_result_error = str(exc)
            else:
                if not ok:
                    self._mailbox_result_error = "邮箱结果回写失败"
            self._mailbox_result_ok = ok
            self._mailbox_result_marked = ok
            if ok:
                self._mailbox_result_error = ""
        return self._mailbox_result_ok

    def mark_mailbox_failure(self, error: Exception) -> bool:
        if self.mailbox is None:
            self._mailbox_result_ok = True
            self._mailbox_result_error = ""
            return True
        if not self._mailbox_result_marked:
            try:
                ok = bool(mail_provider.mark_mailbox_result(self.mailbox, success=False, error=error))
            except Exception as exc:
                ok = False
                self._mailbox_result_error = str(exc)
            else:
                if not ok:
                    self._mailbox_result_error = "邮箱结果回写失败"
            self._mailbox_result_ok = ok
            self._mailbox_result_marked = ok
            if ok:
                self._mailbox_result_error = ""
        return self._mailbox_result_ok

    def _navigate_headers(self, referer: str = "") -> dict[str, str]:
        headers = _header_fingerprint(navigate_headers, self.fingerprint)
        if referer:
            headers["referer"] = referer
        return headers

    def _json_headers(self, referer: str) -> dict[str, str]:
        headers = _header_fingerprint(common_headers, self.fingerprint)
        headers["referer"] = referer
        headers["oai-device-id"] = self.device_id
        headers.update(_make_trace_headers())
        return headers

    def _refresh_cloudflare_clearance(self, target_url: str, index: int) -> ClearanceBundle | None:
        self.clearance_failure_reason = ""
        profile = proxy_settings.get_profile(proxy=self.proxy, upstream=True)
        if not profile.clearance_enabled:
            self.clearance_failure_reason = (
                "可在系统设置用手动 Cookie 填写 Chrome146 的 cf_clearance"
            )
            step(index, f"检测到 Cloudflare 拦截，{self.clearance_failure_reason}", "yellow")
            return None
        step(index, "检测到 Cloudflare 拦截，尝试刷新通行状态", "yellow")
        bundle = proxy_settings.refresh_clearance(
            target_url=target_url,
            proxy=self.proxy,
            force=True,
            upstream=True,
        )
        if bundle is not None:
            _apply_clearance_to_session(self.session, bundle)
            self.clearance_user_agent = bundle.user_agent or self.clearance_user_agent
            step(index, "Cloudflare 通行状态刷新完成，重试当前请求", "yellow")
        else:
            self.clearance_failure_reason = "通行状态刷新未返回可用 Cookie，请检查手动 Cookie 是否匹配 Chrome146"
            step(index, f"Cloudflare 通行状态刷新失败：{self.clearance_failure_reason}", "yellow")
        return bundle

    def _platform_authorize(self, email: str, index: int, screen_hint: str = "login_or_signup") -> str:
        self._stage_step(index, "fingerprint_sentinel", "开始平台授权")
        self.session.cookies.set("oai-did", self.device_id, domain=".auth.openai.com")
        self.session.cookies.set("oai-did", self.device_id, domain="auth.openai.com")
        self.code_verifier, code_challenge = _generate_pkce()
        params = {
            "issuer": auth_base,
            "client_id": platform_oauth_client_id,
            "audience": platform_oauth_audience,
            "redirect_uri": platform_oauth_redirect_uri,
            "device_id": self.device_id,
            # 官网当前的新账号流程使用 passwordless signup。
            "screen_hint": screen_hint,
            "max_age": "0",
            "login_hint": email,
            "scope": "openid profile email offline_access",
            "response_type": "code",
            "response_mode": "query",
            "state": secrets.token_urlsafe(32),
            "nonce": secrets.token_urlsafe(32),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "auth0Client": platform_auth0_client,
        }
        target_url = f"{auth_base}/api/accounts/authorize?{urlencode(params)}"
        resp, error, final_url = _request_trusted_auth_navigation(
            self.session,
            target_url,
            lambda current: _headers_with_clearance(
                self._navigate_headers(f"{platform_base}/"),
                current,
                self.proxy,
                self.clearance_user_agent,
            ),
            verify=not proxy_settings.should_skip_ssl_verify(),
        )
        if _is_cloudflare_challenge(resp):
            bundle = self._refresh_cloudflare_clearance(auth_base, index)
            if bundle is None:
                raise _cloudflare_block_error(resp, reason=self.clearance_failure_reason)
            resp, error, final_url = _request_trusted_auth_navigation(
                self.session,
                target_url,
                lambda current: _headers_with_clearance(
                    self._navigate_headers(f"{platform_base}/"),
                    current,
                    self.proxy,
                    self.clearance_user_agent,
                ),
                verify=not proxy_settings.should_skip_ssl_verify(),
            )
            if _is_cloudflare_challenge(resp):
                raise _cloudflare_block_error(resp, "Cloudflare 通行状态重试仍被拦截")
        if resp is None or resp.status_code != 200:
            err = _response_json(resp).get("error", {}) if resp is not None else {}
            detail = f": {err.get('code', '')} - {err.get('message', '')}".strip(" -") if err else ""
            debug = _response_debug_detail(resp)
            status = getattr(resp, "status_code", "unknown")
            raise RuntimeError(error or f"platform_authorize_http_{status}{detail}, {debug}")
        landed = _authorize_landed_page(resp)
        final_url = final_url or str(getattr(resp, "url", "") or "")
        self.passwordless_signup = "/email-verification" in final_url.lower()
        mode = "无密码" if self.passwordless_signup else "密码"
        step(index, f"平台授权完成[{landed or '?'}] 模式={mode} url={_safe_url_for_log(final_url)}")
        return landed

    def _reset_auth_cookies(self) -> None:
        jar = getattr(self.session.cookies, "jar", self.session.cookies)
        for cookie in list(jar):
            domain = str(getattr(cookie, "domain", "") or "")
            if "auth.openai.com" not in domain:
                continue
            try:
                self.session.cookies.delete(
                    str(getattr(cookie, "name", "") or ""),
                    domain=domain,
                    path=str(getattr(cookie, "path", "/") or "/"),
                )
            except Exception:
                continue
        self.session.cookies.set("oai-did", self.device_id, domain=".auth.openai.com")
        self.session.cookies.set("oai-did", self.device_id, domain="auth.openai.com")

    def _authorize_continue_login(self, email: str, index: int) -> dict:
        step(index, "提交 Microsoft 邮箱进入登录验证")
        url = f"{auth_base}/api/accounts/authorize/continue"

        def send():
            headers = self._json_headers(f"{auth_base}/log-in?usernameKind=email")
            headers["openai-sentinel-token"] = build_sentinel_token(self.session, self.device_id, "authorize_continue", self.fingerprint)
            headers = _headers_with_clearance(headers, url, self.proxy, self.clearance_user_agent)
            return request_with_local_retry(
                self.session,
                "post",
                url,
                json={"username": {"kind": "email", "value": email}},
                headers=headers,
                allow_redirects=False,
                verify=not proxy_settings.should_skip_ssl_verify(),
            )

        resp, error = send()
        if _is_cloudflare_challenge(resp):
            bundle = self._refresh_cloudflare_clearance(auth_base, index)
            if bundle is None:
                raise _cloudflare_block_error(resp, reason=self.clearance_failure_reason)
            resp, error = send()
            if _is_cloudflare_challenge(resp):
                raise _cloudflare_block_error(resp, "Cloudflare 通行状态重试仍被拦截")
        if resp is not None and resp.status_code == 409:
            step(index, "登录会话过期，重新发起登录授权", "yellow")
            self._reset_auth_cookies()
            self._platform_authorize(email, index, screen_hint="login_or_signup")
            resp, error = send()
            if _is_cloudflare_challenge(resp):
                bundle = self._refresh_cloudflare_clearance(auth_base, index)
                if bundle is None:
                    raise _cloudflare_block_error(resp, reason=self.clearance_failure_reason)
                resp, error = send()
                if _is_cloudflare_challenge(resp):
                    raise _cloudflare_block_error(resp, "Cloudflare 通行状态重试仍被拦截")
        if resp is None or resp.status_code != 200:
            detail = _response_json(resp) if resp is not None else {}
            raise RuntimeError(
                error
                or f"login_continue_http_{getattr(resp, 'status_code', 'unknown')}, "
                f"detail={_safe_json_detail(detail)}"
            )
        data = _response_json(resp)
        if ((data.get("page") or {}).get("payload") or {}).get("passwordless_disabled"):
            raise RuntimeError("Microsoft 邮箱登录流不支持无密码登录，请换邮箱或使用已有密码重登")
        return data

    def _send_passwordless_otp(self, index: int) -> None:
        self._stage_step(index, "code_wait", "发送 Microsoft 登录验证码")
        url = f"{auth_base}/api/accounts/passwordless/send-otp"

        def send():
            headers = self._json_headers(f"{auth_base}/log-in/password")
            headers = _headers_with_clearance(headers, url, self.proxy, self.clearance_user_agent)
            return request_with_local_retry(self.session, "post", url, json={}, headers=headers, allow_redirects=False, verify=not proxy_settings.should_skip_ssl_verify())

        resp, error = send()
        if _is_cloudflare_challenge(resp):
            bundle = self._refresh_cloudflare_clearance(auth_base, index)
            if bundle is None:
                raise _cloudflare_block_error(resp, reason=self.clearance_failure_reason)
            resp, error = send()
            if _is_cloudflare_challenge(resp):
                raise _cloudflare_block_error(resp, "Cloudflare 通行状态重试仍被拦截")
        if resp is None or resp.status_code not in (200, 201, 204):
            detail = _response_json(resp) if resp is not None else {}
            raise RuntimeError(
                error
                or f"passwordless_send_otp_http_{getattr(resp, 'status_code', 'unknown')}, "
                f"detail={_safe_json_detail(detail)}"
            )

    @staticmethod
    def _is_passwordless_invalid_state(resp) -> bool:
        if resp is None or getattr(resp, "status_code", None) != 409:
            return False
        data = _response_json(resp)
        error = data.get("error") if isinstance(data, dict) else None
        if not isinstance(error, dict):
            return False
        code = str(error.get("code") or "").strip().lower()
        message = str(error.get("message") or "").strip().lower()
        return code == "invalid_state" or "sign-in session is no longer valid" in message

    def _passwordless_login(self, email: str, mailbox: dict, index: int) -> dict:
        step(index, "OpenAI 返回登录流，转入 Microsoft 无密码登录", "yellow")
        self._authorize_continue_login(email, index)
        mailbox["_received_after"] = datetime.now(timezone.utc).isoformat()
        self._send_passwordless_otp(index)
        self._stage_step(index, "code_wait", "开始等待 Microsoft 登录验证码")
        code = wait_for_code(mailbox, register_proxy=self.proxy, login=True)
        mailbox["_code_received"] = True
        self._mailbox_code_received = True
        step(index, f"收到 Microsoft 登录验证码: {code}")
        for attempt in range(2):
            resp, error = validate_otp(self.session, self.device_id, code, self.fingerprint)
            if resp is not None and resp.status_code == 200:
                break
            body = _safe_response_body(resp)
            if attempt == 0 and self._is_passwordless_invalid_state(resp):
                step(index, "Microsoft 登录会话失效，重新发起无密码登录后复用已收到的验证码", "yellow")
                self._reset_auth_cookies()
                self._platform_authorize(email, index, screen_hint="login_or_signup")
                self._authorize_continue_login(email, index)
                continue
            raise RuntimeError(
                error
                or f"passwordless_validate_otp_http_{getattr(resp, 'status_code', 'unknown')}_body="
                f"{redact_register_log_text(body)}"
            )
        data = _response_json(resp)
        continue_url = str(data.get("continue_url") or "").strip() or f"{auth_base}/sign-in-with-chatgpt/platform/consent"
        if _url_path(continue_url) == "/about-you":
            first_name, last_name = _random_name()
            step(index, "Microsoft 登录验证完成，需要完善账号资料")
            self._create_account(f"{first_name} {last_name}", _random_birthdate(), index)
            self.created_new_account = True
            return self._exchange_registered_tokens(index)
        self._stage_step(index, "token_exchange", "Microsoft 登录验证完成，开始换 Token")
        exchange_errors: list[str] = []
        tokens = exchange_tokens_from_continue_url(
            self.session,
            self.device_id,
            self.code_verifier,
            continue_url,
            self.proxy,
            self.clearance_user_agent,
            exchange_errors,
            self.fingerprint,
        )
        if not tokens:
            detail = "；".join(exchange_errors[-4:]) if exchange_errors else "未返回 token"
            raise RuntimeError(f"微软无密码 Token 换取失败: {detail}")
        step(index, "Microsoft 无密码 Token 换取完成")
        return tokens

    def _start_passwordless_signup(self, index: int) -> None:
        self._stage_step(index, "code_wait", "开始切换无密码注册并发送验证码")
        url = f"{auth_base}/api/accounts/passwordless/send-otp"

        def send():
            headers = self._json_headers(f"{auth_base}/create-account/password")
            headers = _headers_with_clearance(headers, url, self.proxy, self.clearance_user_agent)
            return request_with_local_retry(self.session, "post", url, headers=headers, verify=not proxy_settings.should_skip_ssl_verify())

        resp, error = send()
        if _is_cloudflare_challenge(resp):
            bundle = self._refresh_cloudflare_clearance(auth_base, index)
            if bundle is None:
                raise _cloudflare_block_error(resp, reason=self.clearance_failure_reason)
            resp, error = send()
            if _is_cloudflare_challenge(resp):
                raise _cloudflare_block_error(resp, "Cloudflare 通行状态重试仍被拦截")
        if resp is None or resp.status_code not in (200, 201, 204):
            data = _response_json(resp) if resp is not None else {}
            detail = f", detail={_safe_json_detail(data)}" if data else ""
            raise RuntimeError(error or f"passwordless_send_otp_http_{getattr(resp, 'status_code', 'unknown')}{detail}")
        self.passwordless_signup = True
        step(index, "无密码注册验证码发送完成")

    def _register_user(self, email: str, password: str, index: int) -> None:
        self._stage_step(index, "account_create", "开始提交注册密码")
        url = f"{auth_base}/api/accounts/user/register"
        headers = self._json_headers(f"{auth_base}/create-account/password")
        headers["openai-sentinel-token"] = build_sentinel_token(self.session, self.device_id, "username_password_create", self.fingerprint)
        headers = _headers_with_clearance(headers, url, self.proxy, self.clearance_user_agent)
        resp, error = request_with_local_retry(self.session, "post", url, json={"username": email, "password": password}, headers=headers, verify=not proxy_settings.should_skip_ssl_verify())
        if _is_cloudflare_challenge(resp):
            bundle = self._refresh_cloudflare_clearance(auth_base, index)
            if bundle is None:
                raise _cloudflare_block_error(resp, reason=self.clearance_failure_reason)
            headers = self._json_headers(f"{auth_base}/create-account/password")
            headers["openai-sentinel-token"] = build_sentinel_token(self.session, self.device_id, "username_password_create", self.fingerprint)
            headers = _headers_with_clearance(headers, url, self.proxy, self.clearance_user_agent)
            resp, error = request_with_local_retry(self.session, "post", url, json={"username": email, "password": password}, headers=headers, verify=not proxy_settings.should_skip_ssl_verify())
            if _is_cloudflare_challenge(resp):
                raise _cloudflare_block_error(resp, "Cloudflare 通行状态重试仍被拦截")
        if resp is None or resp.status_code != 200:
            data = _response_json(resp) if resp is not None else {}
            if data.get("message") == "Failed to create account. Please try again.":
                step(index, "注册失败提示: 邮箱域名很可能因滥用被封禁，请更换邮箱域名", "yellow")
            detail = f", detail={_safe_json_detail(data)}" if data else ""
            raise RuntimeError(error or f"user_register_http_{getattr(resp, 'status_code', 'unknown')}{detail}")
        step(index, "提交注册密码完成")

    def _send_otp(self, index: int) -> None:
        self._stage_step(index, "code_wait", "开始发送验证码")
        url = f"{auth_base}/api/accounts/email-otp/send"
        resp, error, _final_url = _request_trusted_auth_navigation(
            self.session,
            url,
            lambda current: _headers_with_clearance(
                self._navigate_headers(f"{auth_base}/create-account/password"),
                current,
                self.proxy,
                self.clearance_user_agent,
            ),
            verify=not proxy_settings.should_skip_ssl_verify(),
        )
        if _is_cloudflare_challenge(resp):
            bundle = self._refresh_cloudflare_clearance(auth_base, index)
            if bundle is None:
                raise _cloudflare_block_error(resp, reason=self.clearance_failure_reason)
            resp, error, _final_url = _request_trusted_auth_navigation(
                self.session,
                url,
                lambda current: _headers_with_clearance(
                    self._navigate_headers(f"{auth_base}/create-account/password"),
                    current,
                    self.proxy,
                    self.clearance_user_agent,
                ),
                verify=not proxy_settings.should_skip_ssl_verify(),
            )
            if _is_cloudflare_challenge(resp):
                raise _cloudflare_block_error(resp, "Cloudflare 通行状态重试仍被拦截")
        if resp is None or resp.status_code not in (200, 302):
            raise RuntimeError(error or f"send_otp_http_{getattr(resp, 'status_code', 'unknown')}")
        step(index, "发送验证码完成")

    def _validate_otp(self, code: str, index: int) -> None:
        self._stage_step(index, "code_wait", f"开始校验验证码 {code}")
        resp, error = validate_otp(self.session, self.device_id, code, self.fingerprint)
        if resp is None or resp.status_code != 200:
            body = ""
            try:
                body = _safe_response_body(resp)
            except Exception:
                pass
            raise RuntimeError(error or f"validate_otp_http_{getattr(resp, 'status_code', 'unknown')}_body={body}")
        data = _response_json(resp)
        continue_url = extract_continue_url(data)
        if continue_url:
            self.last_otp_continue_url = continue_url
            self._authorize_continue(continue_url, index)
        step(index, "验证码校验完成")

    def _authorize_continue(self, continue_url: str, index: int) -> None:
        url = str(continue_url or "").strip()
        if not url:
            return
        url = _absolute_auth_url(url)

        step(index, "开始继续注册授权")
        resp, error, _final_url = _request_trusted_auth_navigation(
            self.session,
            url,
            lambda current: _headers_with_clearance(
                self._navigate_headers(f"{auth_base}/email-verification"),
                current,
                self.proxy,
                self.clearance_user_agent,
            ),
            verify=not proxy_settings.should_skip_ssl_verify(),
        )
        if _is_cloudflare_challenge(resp):
            bundle = self._refresh_cloudflare_clearance(auth_base, index)
            if bundle is None:
                raise _cloudflare_block_error(resp, reason=self.clearance_failure_reason)
            resp, error, _final_url = _request_trusted_auth_navigation(
                self.session,
                url,
                lambda current: _headers_with_clearance(
                    self._navigate_headers(f"{auth_base}/email-verification"),
                    current,
                    self.proxy,
                    self.clearance_user_agent,
                ),
                verify=not proxy_settings.should_skip_ssl_verify(),
            )
            if _is_cloudflare_challenge(resp):
                raise _cloudflare_block_error(resp, "Cloudflare 通行状态重试仍被拦截")
        if resp is None or resp.status_code not in (200, 302):
            debug = _response_debug_detail(resp)
            raise RuntimeError(
                error
                or f"authorize_continue_http_{getattr(resp, 'status_code', 'unknown')}, {debug}"
            )
        step(index, f"继续注册授权完成 url={_safe_url_for_log(str(getattr(resp, 'url', '') or ''))}")

    def _create_account(self, name: str, birthdate: str, index: int) -> None:
        self._stage_step(index, "account_create", "开始创建账号资料")
        url = f"{auth_base}/api/accounts/create_account"
        headers = self._json_headers(f"{auth_base}/about-you")

        # 使用新的 Sentinel 函数，同时获取 Sentinel Token 和 SO Token
        fp = _browser_fingerprint(self.fingerprint)
        sentinel_token, so_token, _oai_sc = build_sentinel_with_so_token(
            self.session,
            self.device_id,
            "oauth_create_account",
            user_agent=fp["user_agent"],
            sec_ch_ua=fp["sec_ch_ua"],
        )

        headers["openai-sentinel-token"] = sentinel_token
        if so_token:
            headers["openai-sentinel-so-token"] = so_token

        headers = _headers_with_clearance(headers, url, self.proxy, self.clearance_user_agent)
        resp, error = request_with_local_retry(self.session, "post", url, json={"name": name, "birthdate": birthdate}, headers=headers, verify=not proxy_settings.should_skip_ssl_verify())
        if _is_cloudflare_challenge(resp):
            bundle = self._refresh_cloudflare_clearance(auth_base, index)
            if bundle is None:
                raise _cloudflare_block_error(resp, reason=self.clearance_failure_reason)
            headers = self._json_headers(f"{auth_base}/about-you")

            # 重新生成 Sentinel Token 和 SO Token
            sentinel_token, so_token, _oai_sc = build_sentinel_with_so_token(
                self.session,
                self.device_id,
                "oauth_create_account",
                user_agent=fp["user_agent"],
                sec_ch_ua=fp["sec_ch_ua"],
            )

            headers["openai-sentinel-token"] = sentinel_token
            if so_token:
                headers["openai-sentinel-so-token"] = so_token

            headers = _headers_with_clearance(headers, url, self.proxy, self.clearance_user_agent)
            resp, error = request_with_local_retry(self.session, "post", url, json={"name": name, "birthdate": birthdate}, headers=headers, verify=not proxy_settings.should_skip_ssl_verify())
            if _is_cloudflare_challenge(resp):
                raise _cloudflare_block_error(resp, "Cloudflare 通行状态重试仍被拦截")
        if resp is None or resp.status_code not in (200, 302):
            data = _response_json(resp) if resp is not None else {}
            if data.get("message") == "Failed to create account. Please try again.":
                step(index, "创建账号失败提示: 邮箱域名很可能因滥用被封禁，请更换邮箱域名", "yellow")
            detail = f", detail={_safe_json_detail(data)}" if data else ""
            raise RuntimeError(error or f"create_account_http_{getattr(resp, 'status_code', 'unknown')}{detail}")
        data = _response_json(resp)
        callback_params = (
            extract_oauth_callback_params_from_url(str(data.get("continue_url") or "").strip())
            or extract_oauth_callback_params_from_url(str(getattr(resp, "headers", {}).get("Location") or "").strip())
            or extract_oauth_callback_params_from_url(str(getattr(resp, "url", "") or "").strip())
        )
        self.platform_auth_code = str((callback_params or {}).get("code") or "").strip()
        if not self.platform_auth_code:
            continue_hint = str(data.get("continue_url") or getattr(resp, "headers", {}).get("Location") or getattr(resp, "url", "") or "")
            raise RuntimeError(f"创建账号未返回回调: continue={_safe_url_for_log(continue_hint)}")
        step(index, "创建账号资料完成")

    def _exchange_registered_tokens(self, index: int) -> dict:
        self._stage_step(index, "token_exchange", "开始换 Token")
        if not self.platform_auth_code:
            raise RuntimeError("token换取失败: 缺少 OAuth callback code")
        exchange_errors: list[str] = []
        tokens = request_platform_oauth_token(self.session, self.platform_auth_code, self.code_verifier, exchange_errors, self.fingerprint)
        if not tokens:
            detail = "；".join(exchange_errors[-3:]) if exchange_errors else "未返回 token"
            raise RuntimeError(f"token换取失败: {detail}")
        step(index, "Token 换取完成")
        return tokens

    def register(self, index: int) -> dict:
        self._stage_step(index, "preflight", "开始注册预检")
        self._stage_step(index, "mailbox_prep", "开始创建邮箱")
        self._mailbox_result_marked = False
        self._mailbox_code_received = False
        try:
            mailbox = create_mailbox(register_proxy=self.proxy)
        except Exception as error:
            self._fail_stage(error)
            self.mark_mailbox_failure(error)
            raise
        self.mailbox = mailbox
        email = str(mailbox.get("address") or "").strip()
        if not email:
            error = RuntimeError("\u90ae\u7bb1\u670d\u52a1\u672a\u8fd4\u56de\u5730\u5740")
            self._fail_stage(error)
            self.mark_mailbox_failure(error)
            if str(mailbox.get("provider") or "") == "outlook_token":
                mail_provider.release_mailbox(mailbox)
            raise error
        label = str(mailbox.get("label") or "")
        self.created_new_account = False
        self._set_stage("mailbox_prep", f"邮箱创建完成[{label}]: {email}")
        step(index, f"邮箱创建完成[{label}]: {email}")
        try:
            first_name, last_name = _random_name()
            # authorize 可能直接发送 OTP，先记录收信边界，避免慢跳转后漏掉验证码。
            mailbox["_received_after"] = datetime.now(timezone.utc).isoformat()
            self._stage_step(index, "fingerprint_sentinel", "开始平台授权")
            landed = self._platform_authorize(email, index)
            if landed == "login":
                self._stage_step(index, "code_wait", "开始等待 Microsoft 登录验证码")
                tokens = self._passwordless_login(email, mailbox, index)
                self._set_stage("token_exchange", "Microsoft 无密码验证完成，准备收口")
            else:
                if not self.passwordless_signup:
                    mailbox["_received_after"] = datetime.now(timezone.utc).isoformat()
                    self._start_passwordless_signup(index)
                step(index, "已进入无密码注册，不创建本地不可用的随机密码")
                self._stage_step(index, "code_wait", "开始等待注册验证码")
                code = wait_for_code(mailbox, register_proxy=self.proxy)
                mailbox["_code_received"] = True
                self._mailbox_code_received = True
                step(index, f"收到注册验证码: {code}")
                self._validate_otp(code, index)
                self._create_account(f"{first_name} {last_name}", _random_birthdate(), index)
                self.created_new_account = True
                tokens = self._exchange_registered_tokens(index)
            access_token = str(tokens.get("access_token") or "").strip()
            if not access_token:
                raise RegisterError(
                    "token_exchange_failed",
                    "Token 换取成功但未返回 access_token。",
                    stage="token_exchange",
                )
            self._set_stage("finalize", f"Token 已获取，邮箱 {email} 准备收口")
        except Exception as error:
            self._fail_stage(error)
            self.mark_mailbox_failure(error)
            raise
        result = {
            "email": email,
            "password": "",
            "access_token": access_token,
            "refresh_token": str(tokens.get("refresh_token") or "").strip(),
            "id_token": str(tokens.get("id_token") or "").strip(),
            "source_type": "web",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        result["fp"] = _account_fingerprint_payload(
            self.fingerprint,
            device_id=self.device_id,
            session_id=self.session_id,
        )
        result["register_proxy"] = str(self.proxy or "").strip()
        if result["register_proxy"]:
            result["proxy"] = result["register_proxy"]
        cookies = _session_cookie_payload(self.session)
        if cookies:
            result["cookies"] = cookies
        if str(self.clearance_user_agent or "").strip():
            result["clearance_user_agent"] = str(self.clearance_user_agent).strip()
        return result


def worker(index: int) -> dict:
    start = time.time()
    registrar = PlatformRegistrar(config["proxy"])

    def finish_failure(
        error: Exception,
        *,
        core_ok: bool = False,
        core_result: dict[str, Any] | None = None,
        recovery_error: str = "",
        recovery_file_available: bool = False,
        mailbox_finalize_attempted: bool = False,
    ) -> dict:
        cost = time.time() - start
        mailbox_mark_ok = True
        mailbox_result_error = ""
        if core_ok:
            if not mailbox_finalize_attempted:
                try:
                    mailbox_mark_ok = bool(registrar.mark_mailbox_success())
                except Exception as mailbox_error:
                    mailbox_mark_ok = False
                    mailbox_result_error = str(mailbox_error)
            else:
                mailbox_mark_ok = bool(getattr(registrar, "mailbox_result_ok", False))
        else:
            try:
                mailbox_mark_ok = bool(registrar.mark_mailbox_failure(error))
            except Exception as mailbox_error:
                mailbox_mark_ok = False
                mailbox_result_error = str(mailbox_error)
        mailbox_result_error = mailbox_result_error or str(
            getattr(registrar, "mailbox_result_error", getattr(registrar, "_mailbox_result_error", "")) or ""
        ).strip()
        raw_stage = str(getattr(registrar, "stage", "") or "")
        if raw_stage.strip().lower() == "failed":
            raw_stage = str(getattr(registrar, "failed_from_stage", "") or "")
        classified = classify_register_error(error, stage=raw_stage)
        extra_parts: list[str] = []
        if recovery_error:
            if recovery_file_available:
                extra_parts.append(f"核心结果已暂存，等待自动收口: {recovery_error}")
            else:
                extra_parts.append(f"核心结果暂存失败: {recovery_error}")
        elif core_ok and recovery_file_available:
            extra_parts.append(f"核心结果已暂存: {register_core_results_pending_file}")
        if not mailbox_mark_ok and mailbox_result_error:
            extra_parts.append(f"邮箱结果回写失败: {mailbox_result_error}")
        original = classified.original or classified.reason
        if extra_parts:
            original = f"{original}；{'；'.join(extra_parts)}" if original else "；".join(extra_parts)
        classified = RegisterError(
            classified.code,
            classified.reason,
            stage=classified.stage,
            original=original,
            failure_class=classified.failure_class,
            label=classified.label,
        )
        error_text = classified.format_log(index=index, cost=cost)
        with stats_lock:
            stats["done"] += 1
            stats["fail"] += 1
        safe_error_text = redact_register_log_text(error_text)
        failed_from_stage = str(getattr(registrar, "failed_from_stage", "") or "").strip()
        log(safe_error_text, "red")
        payload = {
            "ok": False,
            "index": index,
            "error": safe_error_text,
            "failure_class": classified.failure_class,
            "error_code": classified.code,
            "error_label": classified.label,
            "stage": classified.stage or display_register_stage(raw_stage),
        }
        if failed_from_stage:
            payload["failed_from_stage"] = display_register_stage(failed_from_stage) or failed_from_stage
        if core_ok:
            payload["core_ok"] = True
            if isinstance(core_result, dict):
                payload["result"] = core_result
                if recovery_file_available:
                    payload["recovery_file"] = str(register_core_results_pending_file)
        return payload

    try:
        step(index, "任务启动")
        try:
            result = registrar.register(index)
        except Exception as e:
            return finish_failure(e, core_ok=False)

        access_token = str(result.get("access_token") or "").strip()
        if not access_token:
            return finish_failure(
                RegisterError("token_exchange_failed", "注册核心未返回 access_token。", stage="Token 换取"),
                core_ok=False,
            )
        postprocess_warnings: list[str] = []
        pending_core_record_error = record_pending_core_result(
            result,
            reason="注册核心已完成，等待后续验活和入库",
            stage=display_register_stage(registrar.stage) or registrar.stage,
            index=index,
        )
        if pending_core_record_error:
            postprocess_warnings.append(
                RegisterError(
                    "persist_failed",
                    "注册核心结果暂存失败，账号已继续入库。",
                    original=pending_core_record_error,
                    stage="入库",
                    label="核心结果暂存失败",
                ).format_log(kind="warning")
            )

        mailbox_mark_ok = True
        mailbox_result_error = ""
        try:
            mailbox_mark_ok = bool(registrar.mark_mailbox_success())
        except Exception as mailbox_error:
            mailbox_mark_ok = False
            mailbox_result_error = str(mailbox_error)
        mailbox_result_error = mailbox_result_error or str(
            getattr(registrar, "mailbox_result_error", getattr(registrar, "_mailbox_result_error", "")) or ""
        ).strip()
        if not mailbox_mark_ok:
            mailbox_error = RuntimeError(
                mailbox_result_error or "邮箱结果回写失败"
            )
            # Do not leave a consumed mailbox in an indeterminate in_use
            # state when its success finalization failed.
            try:
                registrar.mark_mailbox_failure(mailbox_error)
            except Exception:
                pass
            postprocess_warnings.append(
                RegisterError(
                    "postprocess_failed",
                    "邮箱结果回写失败，账号已继续入库。",
                    original=mailbox_result_error or str(mailbox_error),
                    stage="收口",
                    label="邮箱结果回写失败",
                ).format_log(kind="warning")
            )
        try:
            from services.register.core_result_recovery import reconcile_core_result

            handoff = reconcile_core_result(
                result,
                register_proxy=str(result.get("register_proxy") or registrar.proxy or "").strip(),
                verify_fn=verify_registered_account,
                account_service_obj=account_service,
            )
            result = dict(handoff.get("result") or result)
            postprocess_warnings.extend(str(item) for item in handoff.get("warnings") or [])
        except Exception as postprocess_error:
            classified_error = (
                postprocess_error
                if isinstance(postprocess_error, RegisterError)
                else classify_register_error(postprocess_error, stage="收口")
            )
            if not isinstance(postprocess_error, RegisterError) and classified_error.code == "unknown":
                classified_error = RegisterError(
                    "postprocess_failed",
                    "注册结果收口失败。",
                    original=str(postprocess_error),
                    stage="收口",
                )
            return finish_failure(
                classified_error,
                core_ok=True,
                core_result=result,
                recovery_error=pending_core_record_error or str(postprocess_error),
                recovery_file_available=not bool(pending_core_record_error),
                mailbox_finalize_attempted=True,
            )

        cost = time.time() - start
        avg = None
        with stats_lock:
            try:
                stats["done"] += 1
                stats["success"] += 1
                avg = (time.time() - stats["start_time"]) / stats["success"]
            except Exception as stats_error:
                postprocess_warnings.append(
                    RegisterError(
                        "unknown",
                        "统计更新失败。",
                        original=str(stats_error),
                        stage="收口",
                        label="收口警告",
                    ).format_log(kind="warning")
                )
        try:
            if postprocess_warnings:
                log(f'{result["email"]} 注册核心成功，耗时{cost:.1f}s，后续处理警告: {"；".join(postprocess_warnings)}', "yellow")
            elif avg is not None:
                log(f'{result["email"]} 注册成功，耗时{cost:.1f}s，全局平均每个号注册耗时{avg:.1f}s', "green")
            else:
                log(f'{result["email"]} 注册核心成功，耗时{cost:.1f}s', "green")
        except Exception:
            pass
        payload = {
            "ok": True,
            "index": index,
            "result": result,
            "stage": display_register_stage(registrar.stage) or registrar.stage,
        }
        if postprocess_warnings:
            payload["warnings"] = [redact_register_log_text(item) for item in postprocess_warnings]
        return payload
    finally:
        registrar.close()


def verify_registered_account(
    access_token: str,
    register_proxy: str = "",
    account: dict[str, Any] | None = None,
) -> dict[str, Any]:
    token = str(access_token or "").strip()
    if not token:
        raise RegisterError("token_invalid", "注册账号 token 为空。", stage="收口验活")
    account_payload = dict(account or {}) if isinstance(account, dict) else {}
    proxy = str(register_proxy or account_payload.get("register_proxy") or account_payload.get("proxy") or "").strip()
    if proxy:
        account_payload["proxy"] = proxy
        account_payload["register_proxy"] = proxy
    account_payload["access_token"] = token
    from services.openai_backend_api import OpenAIBackendAPI

    try:
        with OpenAIBackendAPI(token, account=account_payload, proxy=proxy) as backend:
            remote_info = backend.get_user_info()
    except InvalidAccessTokenError as exc:
        raise RegisterError(
            "token_invalid",
            "Token 已失效（HTTP 401）。",
            original=str(exc),
            stage="收口验活",
        ) from exc
    except UpstreamHTTPError as exc:
        original = str(exc)
        status = int(getattr(exc, "status_code", 0) or 0)
        if looks_like_cloudflare_challenge(original):
            raise RegisterError(
                "cloudflare_block",
                "请求被 Cloudflare 拦截。这不是 Token 失效，也不是邮箱接码超时。",
                original=original,
                stage="收口验活",
            ) from exc
        if status == 403:
            raise RegisterError(
                "verify_blocked",
                "请求被上游拒绝（HTTP 403）。这不是 Token 失效。",
                original=original,
                stage="收口验活",
            ) from exc
        raise RegisterError("verify_blocked", "收口验活失败。", original=original, stage="收口验活") from exc
    if not isinstance(remote_info, dict):
        raise RegisterError("verify_blocked", "收口验活返回结果格式无效。", stage="收口验活")
    if not str(remote_info.get("email") or "").strip() and not str(remote_info.get("user_id") or "").strip():
        raise RegisterError("verify_blocked", "收口验活没有返回用户身份。", original=str(remote_info), stage="收口验活")
    image_quota_unknown = bool(remote_info.get("image_quota_unknown"))
    try:
        quota = int(remote_info.get("quota") or 0)
    except (TypeError, ValueError):
        quota = 0
    if not image_quota_unknown and quota <= 0:
        remote_info = dict(remote_info)
        remote_info["quota_warning"] = RegisterError(
            "quota_unavailable",
            "注册账号当前没有图片额度，已先入库。",
            original=f"quota={quota}",
            stage="收口验活",
        ).format_log(kind="warning")
    return remote_info
