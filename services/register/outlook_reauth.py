"""Outlook 辅助邮箱重授权。只给维护动作使用，不进入注册收信。"""

from __future__ import annotations

import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Any, Callable
from urllib.parse import parse_qs, unquote, urlencode, urlsplit

from services.browser_fingerprint import chrome146_headers
from services.http_target import http_target_session_request
from services.proxy_service import proxy_settings
from services.register.log_redaction import redact_register_log_text
from services.register.mail_provider import (
    OUTLOOK_GRAPH_SCOPE,
    OUTLOOK_REAUTH_AUTHORIZE_URL,
    OUTLOOK_REAUTH_CLIENT_ID,
    OUTLOOK_REAUTH_REDIRECT_URI,
    OUTLOOK_REAUTH_SCOPE,
    OUTLOOK_TOKEN_URL,
    OutlookTokenError,
    OutlookTokenProvider,
    _chrome146_user_agent,
    _create_session,
    _family_lease_active,
    _mail_recipient_matches,
    _message_tracking_ref,
    _outlook_credential_state,
    _outlook_timestamp_stale,
    outlook_alias_parent_email,
)


logger = logging.getLogger(__name__)
OUTLOOK_REAUTH_LOCK = Lock()
OUTLOOK_REAUTH_CODE_SKEW_SECONDS = 5
OUTLOOK_REAUTH_CODE_TIMEOUT_SECONDS = 90

_VERIFY_MARKERS = ("验证你的电子邮件", "验证您的电子邮件", "verify your email")
_CODE_MARKERS = ("输入代码", "输入验证码", "enter the code", "enter code", "enter your code")
_SEND_MARKERS = ("发送验证码", "发送代码", "send code")
_ADD_MARKERS = (
    "帮助保护你的帐户",
    "帮助保护你的账户",
    "让我们来保护你的帐户",
    "让我们来保护你的账户",
    "添加恢复邮箱",
    "添加电子邮件",
    "add an email address",
    "add a recovery email",
    "protect your account",
    "help us protect your account",
)
_MAIN_EMAIL_BLOCK_MARKERS = (
    "保护你的帐户",
    "保护你的账户",
    "恢复邮箱",
    "添加电子邮件",
    "添加恢复",
    "发送验证码",
    "发送代码",
    "send code",
    "protect your account",
    "recovery email",
)
_CODE_LABELED = re.compile(
    r"(?:安全代码|安全码|验证码|security code|verification code|code is|code:)[^\d]{0,24}(\d{6,8})",
    re.IGNORECASE,
)
_CODE_BEFORE = re.compile(
    r"(\d{6,8})[^\d]{0,24}(?:安全代码|安全码|验证码|security code|verification code)",
    re.IGNORECASE,
)
_CODE_REGION = re.compile(r"(?:验证|verify)[^\n]{0,48}(\d{6,8})", re.IGNORECASE)


class OutlookReauthError(RuntimeError):
    """重授权失败。调用方不得据此改账号状态。"""


def outlook_reauth_skip_reason(store: dict[str, dict[str, Any]], credential: dict[str, Any]) -> str | None:
    recovery_email = str(credential.get("recovery_email") or "").strip()
    recovery_token = str(credential.get("recovery_refresh_token") or "").strip()
    if "@" not in recovery_email or not recovery_token:
        return "没有辅助邮箱"
    state = _outlook_credential_state(store, credential)
    if state not in {"token_invalid", "login_required"}:
        return "不是失效或需登录状态"
    if _outlook_reauth_busy(store, credential):
        return "主号仍在使用"
    if str(credential.get("client_id") or "").strip() != OUTLOOK_REAUTH_CLIENT_ID:
        return "这个应用编号不能自动重授权"
    if not str(credential.get("password") or "").strip():
        return "缺少密码"
    return None


def _outlook_reauth_busy(store: dict[str, dict[str, Any]], credential: dict[str, Any]) -> bool:
    parent = outlook_alias_parent_email(
        str(credential.get("login_email") or credential.get("alias_of") or credential.get("email") or "")
    )
    if not parent:
        return False
    for key, entry in store.items():
        if outlook_alias_parent_email(key) != parent or not isinstance(entry, dict):
            continue
        if str(entry.get("state") or "") == "in_use" and not _outlook_timestamp_stale(str(entry.get("updated_at") or "")):
            return True
        if key == parent and _family_lease_active(entry):
            return True
    return False


def public_reauth_reason(exc: BaseException, credential: dict[str, Any] | None = None) -> str:
    text = " ".join(str(exc or "").split()) or exc.__class__.__name__
    for key in ("refresh_token", "recovery_refresh_token", "password"):
        secret = str((credential or {}).get(key) or "")
        if len(secret) >= 4:
            text = text.replace(secret, "[redacted]")
    return text[:180] or "重授权失败"


def build_outlook_reauth_url(credential: dict[str, Any]) -> str:
    query = urlencode({
        "client_id": str(credential.get("client_id") or "").strip(),
        "response_type": "code",
        "redirect_uri": OUTLOOK_REAUTH_REDIRECT_URI,
        "response_mode": "query",
        "scope": OUTLOOK_REAUTH_SCOPE,
        "login_hint": str(credential.get("email") or "").strip(),
    })
    return f"{OUTLOOK_REAUTH_AUTHORIZE_URL}?{query}"


def authorization_code_from_url(url: str) -> str:
    parsed = urlsplit(str(url or ""))
    host = str(parsed.hostname or "").lower()
    if host not in {"localhost", "127.0.0.1"}:
        return ""
    code = str((parse_qs(parsed.query).get("code") or [""])[0] or "").strip()
    return code


def _recovery_mask_matches(mask: str, email: str) -> bool:
    """掩码必须整段对上这行辅助邮箱，只凭首字母不能算。"""
    shown = str(mask or "").strip().lower()
    target = str(email or "").strip().lower()
    if "@" not in shown or "@" not in target or "*" not in shown:
        return False
    shown_local, _, shown_domain = shown.partition("@")
    local, _, domain = target.partition("@")
    if not shown_local or not local or shown_domain != domain:
        return False
    collapsed = re.sub(r"\*+", "*", shown_local)
    literals = collapsed.replace("*", "")
    if len(literals) < 2 or literals[0] != local[0]:
        return False
    parts = [re.escape(part) for part in collapsed.split("*")]
    return re.fullmatch(".+".join(parts), local) is not None


def recovery_address_visible(page_text: str, recovery_email: str) -> bool:
    email = str(recovery_email or "").strip().lower()
    text = str(page_text or "").lower()
    if "@" not in email or not text:
        return False
    if email in text:
        return True
    _, _, domain = email.partition("@")
    if not domain or domain not in text:
        return False
    pattern = re.compile(rf"[a-z0-9*][a-z0-9*._+-]*@{re.escape(domain)}")
    return any(_recovery_mask_matches(match.group(0), email) for match in pattern.finditer(text))


def recovery_proof_click_labels(email: str) -> list[str]:
    """只点能唯一对上这行辅助邮箱的文本，不点通用发送按钮。"""
    value = str(email or "").strip()
    local, separator, domain = value.partition("@")
    labels = [value]
    if separator and len(local) >= 2 and domain:
        labels.append(f"{local[0]}***{local[-1]}@{domain}")
        if len(local) >= 3:
            labels.append(f"{local[:2]}***@{domain}")
    unique: list[str] = []
    for label in labels:
        if label and "@" in label and label not in unique:
            unique.append(label)
    return unique


def choose_outlook_reauth_action(page_text: str, recovery_email: str) -> str:
    text = str(page_text or "")
    lowered = text.lower()
    if _has_marker(text, lowered, _VERIFY_MARKERS):
        if recovery_address_visible(text, recovery_email):
            return "send_to_recovery"
        return "verify_unmatched"
    if _has_marker(text, lowered, _ADD_MARKERS):
        return "add_recovery"
    if _has_marker(text, lowered, _CODE_MARKERS):
        return "enter_code"
    if _has_marker(text, lowered, _SEND_MARKERS) and recovery_address_visible(text, recovery_email):
        return "send_to_recovery"
    return "continue"


def drive_outlook_reauth(
    page: Any,
    credential: dict[str, Any],
    read_code: Callable[[], str],
    *,
    on_code_requested: Callable[[], None] | None = None,
    max_steps: int = 40,
) -> str:
    recovery_email = str(credential.get("recovery_email") or "").strip()
    email = str(credential.get("email") or "").strip()
    password = str(credential.get("password") or "")
    code_reads = 0
    code_requested = False

    def prepare_code_request() -> None:
        nonlocal code_requested
        if code_requested:
            return
        code_requested = True
        if on_code_requested is not None:
            on_code_requested()

    for _ in range(max_steps):
        code = authorization_code_from_url(str(page.current_url() or ""))
        if code:
            return code
        text = str(page.page_text() or "")
        action = choose_outlook_reauth_action(text, recovery_email)
        if action == "verify_unmatched":
            raise OutlookReauthError("当前验证页不是这行的辅助邮箱")
        if action == "send_to_recovery":
            prepare_code_request()
            page.click_recovery_proof(recovery_email)
        elif action == "enter_code":
            code_reads += 1
            if code_reads > 2:
                raise OutlookReauthError("安全代码已提交但仍停在验证码页")
            page.fill_security_code(str(read_code() or "").strip())
        elif action == "add_recovery":
            prepare_code_request()
            page.fill_recovery_email(recovery_email)
        else:
            lowered = text.lower()
            acted = False
            if not _has_marker(text, lowered, _MAIN_EMAIL_BLOCK_MARKERS):
                acted = bool(page.fill_email_if_present(email))
            acted = bool(page.fill_password_if_present(password)) or acted
            acted = bool(page.click_consent_if_present()) or acted
            if not acted:
                page.wait_brief()
        page.wait_brief()
    raise OutlookReauthError("登录页没有在限定步骤内完成")


def extract_microsoft_security_code(*parts: object) -> str:
    text = "\n".join(str(part or "") for part in parts)
    for pattern in (_CODE_LABELED, _CODE_BEFORE, _CODE_REGION):
        for match in pattern.finditer(text):
            code = match.group(1)
            if _usable_security_code(code):
                return code
    return ""


def collect_recovery_message_refs(credential: dict[str, Any], proxy: str = "") -> set[str]:
    """记下这次请求前已经在辅助邮箱里的邮件，避免串到上一封安全代码。"""
    provider, mailbox, recovery_token, client_id = _recovery_graph_reader(credential, proxy)
    if provider is None:
        return set()
    try:
        access_token = provider._access_token(mailbox, client_id, recovery_token, OUTLOOK_GRAPH_SCOPE)
        messages = provider._graph_messages(mailbox, access_token)
    finally:
        provider.close()
    refs: set[str] = set()
    for message in messages or []:
        if not isinstance(message, dict):
            continue
        ref = _message_tracking_ref(message)
        if ref:
            refs.add(ref)
    return refs


def outlook_reauth_code_callbacks(
    credential: dict[str, Any],
    proxy: str = "",
) -> tuple[Callable[[], None], Callable[[], str]]:
    seen: set[str] = set()
    requested = {"at": datetime.now(timezone.utc)}

    def snapshot() -> None:
        try:
            seen.update(collect_recovery_message_refs(credential, proxy))
        except OutlookTokenError:
            raise
        except Exception:
            logger.warning("Outlook 辅助邮箱重授权未能记下已有邮件")

    snapshot()

    def on_code_requested() -> None:
        snapshot()
        requested["at"] = datetime.now(timezone.utc)

    def read_code() -> str:
        return read_outlook_recovery_security_code(
            credential,
            requested["at"] or datetime.now(timezone.utc),
            proxy=proxy,
            exclude_refs=set(seen),
        )

    return on_code_requested, read_code


def read_outlook_recovery_security_code(
    credential: dict[str, Any],
    received_after: datetime,
    *,
    proxy: str = "",
    timeout: float = OUTLOOK_REAUTH_CODE_TIMEOUT_SECONDS,
    exclude_refs: set[str] | None = None,
) -> str:
    provider, mailbox, recovery_token, client_id = _recovery_graph_reader(credential, proxy)
    if provider is None:
        raise OutlookReauthError("没有辅助邮箱")
    recovery_email = str(mailbox.get("address") or "")
    excluded = {str(item) for item in (exclude_refs or set()) if str(item)}
    deadline = time.monotonic() + max(float(timeout), 0)
    try:
        while True:
            messages: list[dict[str, Any]] = []
            try:
                access_token = provider._access_token(mailbox, client_id, recovery_token, OUTLOOK_GRAPH_SCOPE)
                messages = provider._graph_messages(mailbox, access_token)
            except OutlookTokenError:
                raise
            except Exception:
                messages = []
            code = _security_code_from_messages(messages, recovery_email, received_after, excluded)
            if code:
                return code
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise OutlookReauthError("辅助邮箱没有读到安全代码")
            time.sleep(min(1.0, remaining))
    finally:
        provider.close()


def _recovery_graph_reader(
    credential: dict[str, Any],
    proxy: str,
) -> tuple[OutlookTokenProvider | None, dict[str, str], str, str]:
    recovery_email = str(credential.get("recovery_email") or "").strip()
    recovery_token = str(credential.get("recovery_refresh_token") or "").strip()
    client_id = str(credential.get("client_id") or "").strip()
    if "@" not in recovery_email or not recovery_token:
        return None, {}, "", ""
    provider = OutlookTokenProvider(
        {"type": "outlook_token", "mode": "graph", "mailboxes": "", "imap_host": "outlook.office365.com"},
        {
            "proxy": proxy,
            "user_agent": _chrome146_user_agent(),
            "request_timeout": 30,
            "wait_timeout": 30,
            "wait_interval": 1,
        },
    )
    mailbox = {
        "address": recovery_email,
        "login_email": recovery_email,
        "client_id": client_id,
        "refresh_token": recovery_token,
    }
    return provider, mailbox, recovery_token, client_id


def exchange_outlook_authorization_code(code: str, client_id: str, proxy: str = "") -> str:
    if str(client_id or "").strip() != OUTLOOK_REAUTH_CLIENT_ID:
        raise OutlookReauthError("这个应用编号不能自动重授权")
    if not str(code or "").strip():
        raise OutlookReauthError("没有拿到授权码")
    session = _create_session({"proxy": proxy})
    try:
        with http_target_session_request(session, OUTLOOK_TOKEN_URL) as request_options:
            response = session.post(
                OUTLOOK_TOKEN_URL,
                data={
                    "client_id": client_id,
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": OUTLOOK_REAUTH_REDIRECT_URI,
                    "scope": OUTLOOK_REAUTH_SCOPE,
                },
                headers=chrome146_headers({
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": _chrome146_user_agent(),
                }, include_defaults=False),
                timeout=30,
                verify=not proxy_settings.should_skip_ssl_verify(),
                **request_options,
            )
        try:
            payload = response.json()
        except Exception:
            payload = {}
        if int(response.status_code) >= 400:
            detail = str(payload.get("error_description") or payload.get("error") or "")
            logger.warning("outlook reauth token exchange failed: %s", redact_register_log_text(detail[:180]))
            raise OutlookReauthError("令牌交换失败")
        token = str(payload.get("refresh_token") or "").strip()
    finally:
        session.close()
    if not token:
        raise OutlookReauthError("没有换到新的主令牌")
    return token


def default_outlook_reauth_session() -> "PatchrightOutlookReauthSession":
    return PatchrightOutlookReauthSession()


class PatchrightOutlookReauthSession:
    """真实浏览器会话。缺少组件或图形界面时失败，不改账号状态。"""

    def ensure_ready(self) -> None:
        _require_display()
        _require_browser_binary(_load_patchright())

    def authorize(self, credential: dict[str, Any], *, proxy: str = "") -> str:
        client_id = str(credential.get("client_id") or "").strip()
        if client_id != OUTLOOK_REAUTH_CLIENT_ID:
            raise OutlookReauthError("这个应用编号不能自动重授权")
        _require_recovery_token(credential, proxy)
        _require_display()
        sync_playwright = _load_patchright()
        on_code_requested, read_code = outlook_reauth_code_callbacks(credential, proxy)
        captured = {"url": ""}
        launch_kwargs: dict[str, Any] = {"headless": False}
        browser_proxy = _browser_proxy(proxy)
        if browser_proxy:
            launch_kwargs["proxy"] = browser_proxy
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(**launch_kwargs)
            try:
                page = browser.new_page(locale="zh-CN")
                page.on("framenavigated", lambda frame: _remember_code_url(captured, getattr(frame, "url", "")))
                page.on("request", lambda request: _remember_code_url(captured, getattr(request, "url", "")))
                page.goto(build_outlook_reauth_url(credential), wait_until="domcontentloaded", timeout=60000)
                code = drive_outlook_reauth(
                    _PatchrightPage(page, captured),
                    credential,
                    read_code,
                    on_code_requested=on_code_requested,
                )
            finally:
                browser.close()
        return exchange_outlook_authorization_code(code, client_id, proxy=proxy)


class _PatchrightPage:
    def __init__(self, page: Any, captured: dict[str, str]) -> None:
        self.page = page
        self.captured = captured

    def current_url(self) -> str:
        captured = str(self.captured.get("url") or "")
        if authorization_code_from_url(captured):
            return captured
        return str(getattr(self.page, "url", "") or "")

    def page_text(self) -> str:
        try:
            return str(self.page.locator("body").inner_text(timeout=2000))
        except Exception:
            return ""

    def wait_brief(self) -> None:
        try:
            self.page.wait_for_timeout(500)
        except Exception:
            return

    def click_recovery_proof(self, email: str) -> None:
        if not self._click_text(*recovery_proof_click_labels(email)):
            raise OutlookReauthError("没有找到辅助邮箱的发送按钮")

    def fill_security_code(self, code: str) -> None:
        if not code:
            raise OutlookReauthError("辅助邮箱没有读到安全代码")
        if not (self._fill_visible("input[name='otc']", code) or self._fill_visible("input[type='tel']", code)):
            raise OutlookReauthError("没有找到安全代码输入框")
        self._click_button("下一步", "验证", "Next", "Verify")

    def fill_recovery_email(self, email: str) -> None:
        if not (self._fill_visible("input[type='email']", email) or self._fill_visible("input[name='Email']", email)):
            raise OutlookReauthError("没有找到恢复邮箱输入框")
        self._click_button("下一步", "发送代码", "Next", "Send code")

    def fill_email_if_present(self, email: str) -> bool:
        if not email or not self._fill_visible("input[type='email']", email):
            return False
        self._click_button("下一步", "Next")
        return True

    def fill_password_if_present(self, password: str) -> bool:
        if not password or not self._fill_visible("input[type='password']", password):
            return False
        self._click_button("下一步", "登录", "Next", "Sign in")
        return True

    def click_consent_if_present(self) -> bool:
        text = self.page_text().lower()
        if "保持登录" in text or "stay signed in" in text:
            return self._click_button("否", "No")
        if any(marker in text for marker in ("权限", "permissions", "accept", "接受")):
            return self._click_button("接受", "Accept", "是", "Yes")
        return False

    def _click_text(self, *labels: str) -> bool:
        for label in labels:
            if not label:
                continue
            try:
                locator = self.page.get_by_text(label, exact=True)
                if locator.count() and locator.first.is_visible():
                    locator.first.click(timeout=3000)
                    return True
            except Exception:
                continue
        return False

    def _click_button(self, *labels: str) -> bool:
        for label in labels:
            try:
                locator = self.page.get_by_role("button", name=label)
                if locator.count() and locator.first.is_visible():
                    locator.first.click(timeout=3000)
                    return True
            except Exception:
                continue
        return self._click_text(*labels)

    def _fill_visible(self, selector: str, value: str) -> bool:
        try:
            locator = self.page.locator(selector)
            count = min(int(locator.count()), 4)
        except Exception:
            return False
        for index in range(count):
            item = locator.nth(index)
            try:
                if item.is_visible():
                    item.fill(value, timeout=3000)
                    return True
            except Exception:
                continue
        return False


def _has_marker(text: str, lowered: str, markers: tuple[str, ...]) -> bool:
    return any(marker.lower() in lowered or marker in text for marker in markers)


def _usable_security_code(code: str) -> bool:
    if not code.isdigit() or not 6 <= len(code) <= 8:
        return False
    if len(code) == 6 and 2020 <= int(code[:4]) <= 2099 and 1 <= int(code[4:6]) <= 12:
        return False
    return True


def _security_code_from_messages(
    messages: list[dict[str, Any]],
    recovery_email: str,
    received_after: datetime,
    exclude_refs: set[str] | None = None,
) -> str:
    boundary = received_after
    if boundary.tzinfo is None:
        boundary = boundary.replace(tzinfo=timezone.utc)
    boundary = boundary - timedelta(seconds=OUTLOOK_REAUTH_CODE_SKEW_SECONDS)
    excluded = exclude_refs or set()
    best = ""
    best_at: datetime | None = None
    mailbox = {"address": recovery_email}
    for message in messages:
        if not isinstance(message, dict) or not _message_matches_recovery(mailbox, message):
            continue
        if _message_tracking_ref(message) in excluded:
            continue
        received = message.get("received_at")
        if not isinstance(received, datetime):
            continue
        if received.tzinfo is None:
            received = received.replace(tzinfo=timezone.utc)
        if received < boundary or not _is_microsoft_security_message(message):
            continue
        code = extract_microsoft_security_code(
            message.get("subject"),
            message.get("text_content"),
            message.get("html_content"),
        )
        if code and (best_at is None or received >= best_at):
            best = code
            best_at = received
    return best


def _message_matches_recovery(mailbox: dict[str, str], message: dict[str, Any]) -> bool:
    for key in ("to", "cc", "delivered_to", "x_forwarded_to", "x_original_to"):
        if _mail_recipient_matches(mailbox, message.get(key)):
            return True
    return False


def _is_microsoft_security_message(message: dict[str, Any]) -> bool:
    sender = str(message.get("sender") or "").lower()
    microsoft = any(part in sender for part in (
        "microsoft.com",
        "microsoftonline.com",
        "accountprotection.microsoft",
        "office365.com",
    ))
    if not microsoft:
        return False
    return bool(extract_microsoft_security_code(
        message.get("subject"),
        message.get("text_content"),
        message.get("html_content"),
    ))


def _require_display() -> None:
    if os.name == "nt":
        return
    if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
        return
    raise OutlookReauthError("没有图形界面，不能自动重授权")


def _require_browser_binary(sync_playwright: Any) -> None:
    try:
        with sync_playwright() as playwright:
            path = str(getattr(playwright.chromium, "executable_path", "") or "")
    except OutlookReauthError:
        raise
    except Exception as exc:
        raise OutlookReauthError("没有安装浏览器组件，不能自动重授权") from exc
    if not path or not os.path.isfile(path):
        raise OutlookReauthError("没有安装浏览器组件，不能自动重授权")


def _require_recovery_token(credential: dict[str, Any], proxy: str) -> None:
    provider, mailbox, recovery_token, client_id = _recovery_graph_reader(credential, proxy)
    if provider is None or mailbox is None:
        raise OutlookReauthError("没有辅助邮箱")
    try:
        provider._access_token(mailbox, client_id, recovery_token, OUTLOOK_GRAPH_SCOPE)
    finally:
        provider.close()


def _browser_proxy(proxy: str) -> dict[str, str] | None:
    value = str(proxy or "").strip()
    if not value or value.lower() in {"direct", "none"}:
        return None
    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.hostname:
        return {"server": value}
    port = f":{parsed.port}" if parsed.port else ""
    result = {"server": f"{parsed.scheme}://{parsed.hostname}{port}"}
    if parsed.username:
        result["username"] = unquote(parsed.username)
    if parsed.password:
        result["password"] = unquote(parsed.password)
    return result


def _remember_code_url(captured: dict[str, str], url: object) -> None:
    text = str(url or "")
    if authorization_code_from_url(text):
        captured["url"] = text


def _load_patchright() -> Any:
    try:
        from patchright.sync_api import sync_playwright
    except ImportError as exc:
        raise OutlookReauthError("没有安装浏览器组件，不能自动重授权") from exc
    return sync_playwright
