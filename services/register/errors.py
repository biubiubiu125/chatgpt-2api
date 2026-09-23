from __future__ import annotations

from typing import Any


def _looks_like_mixed_original(value: str) -> bool:
    lowered = value.lower()
    if any(
        marker in lowered
        for marker in (
            "http://",
            "https://",
            "continue=",
            "status=",
            "status_code=",
        )
    ):
        return True
    if "{" in value or "}" in value:
        return True
    for sep in (":", "："):
        if sep not in value:
            continue
        after = value.split(sep, 1)[1]
        if any(char.isascii() and char.isalpha() for char in after):
            return True
    return False


def _register_reason(text: str, fallback: str) -> str:
    value = str(text or "").strip()
    if value and any("\u4e00" <= char <= "\u9fff" for char in value) and not _looks_like_mixed_original(value):
        return value
    return fallback


REGISTER_CORE_STAGE_LABELS = {
    "preflight": "预检",
    "mailbox_prep": "邮箱准备",
    "fingerprint_sentinel": "指纹校验",
    "account_create": "创建账号资料",
    "code_wait": "验证码等待",
    "token_exchange": "Token 换取",
    "finalize": "收口",
}


def display_register_stage(stage: str, *, fallback: str = "") -> str:
    value = str(stage or "").strip()
    if not value or value.lower() == "failed":
        fallback_value = str(fallback or "").strip()
        if not fallback_value or fallback_value.lower() == "failed":
            return ""
        return display_register_stage(fallback_value)
    return REGISTER_CORE_STAGE_LABELS.get(value, value)


REGISTER_ERROR_SPECS: dict[str, tuple[str, str, str]] = {
    "mailbox_wait_timeout": ("邮箱接码超时", "mailbox", "等待验证码"),
    "mailbox_login_wait_timeout": ("邮箱接码超时", "mailbox", "等待 Microsoft 登录验证码"),
    "mailbox_claim_failed": ("邮箱领取失败", "mailbox", "领取邮箱"),
    "cloudflare_block": ("Cloudflare 拦截", "network", "Cloudflare"),
    "proxy_failed": ("代理失败", "network", "代理"),
    "network_failed": ("网络失败", "network", "网络"),
    "auth_failed": ("授权失败", "auth", "授权"),
    "token_exchange_failed": ("Token 换取失败", "auth", "Token 换取"),
    "verify_blocked": ("验活被拦", "auth", "收口验活"),
    "token_invalid": ("Token 已失效", "auth", "Token 校验"),
    "quota_unavailable": ("图片额度不可用", "account", "收口验活"),
    "pool_full": ("号池已满", "account", "号池检查"),
    "persist_failed": ("入库失败", "postprocess", "入库"),
    "refresh_failed": ("账号池刷新失败", "postprocess", "刷新号池"),
    "postprocess_failed": ("收口失败", "postprocess", "收口"),
    "unknown": ("注册失败", "unknown", "未知阶段"),
}

_CLOUDFLARE_CHALLENGE_MARKERS = (
    "just a moment",
    "attention required",
    "cf-chl-",
    "__cf_chl_",
    "cf-browser-verification",
    "checking your browser",
    "enable javascript and cookies to continue",
)

_CLOUDFLARE_MARKERS = _CLOUDFLARE_CHALLENGE_MARKERS + (
    "cloudflare",
    "cf-ray",
    "被 cloudflare 拦截",
    "请求被 cloudflare 拦截",
)

_MAILBOX_WAIT_MARKERS = (
    "等待注册验证码超时",
    "等待 microsoft 登录验证码超时",
    "等待验证码超时",
    "mailbox wait timeout",
)

_MAILBOX_CLAIM_MARKERS = (
    "mail_sync",
    "mail code",
    "release_url",
    "result_url",
    "邮箱服务未返回地址",
    "邮箱领取",
    "领取邮箱",
    "mailbox_claim",
    "mailbox not initialized",
    "邮箱尚未初始化",
)

_HTTP_CODE_PREFIXES = (
    ("platform_authorize_http_", "auth_failed", "授权失败", "平台授权"),
    ("authorize_continue_http_", "auth_failed", "授权失败", "继续授权"),
    ("login_continue_http_", "auth_failed", "授权失败", "继续授权"),
    ("passwordless_send_otp_http_", "auth_failed", "授权失败", "发送验证码"),
    ("passwordless_validate_otp_http_", "auth_failed", "授权失败", "校验验证码"),
    ("send_otp_http_", "auth_failed", "授权失败", "发送验证码"),
    ("validate_otp_http_", "auth_failed", "授权失败", "校验验证码"),
    ("user_register_http_", "auth_failed", "授权失败", "创建账号资料"),
    ("create_account_http_", "auth_failed", "授权失败", "创建账号资料"),
)

_PROXY_MARKERS = (
    "failed to connect to proxy",
    "cannot connect to proxy",
    "connect to proxy",
    "proxyerror",
    "proxy error",
    "proxy_error",
    "proxyconnect",
    "socks5 connect",
    "socks4 connect",
    "socks proxy",
    "connect to socks",
    "http proxy",
    "https proxy",
    "tunnel connection failed",
    "connect tunnel failed",
)

_TOKEN_INVALID_MARKERS = (
    "token invalidated",
    "token 已失效",
    "invalid_access_token",
    "registered account token is empty",
    "注册账号 token 为空",
    "http 401",
)

_TOKEN_EXCHANGE_MARKERS = (
    "token换取失败",
    "token 换取失败",
    "token exchange",
    "未返回 access_token",
    "未返回 token",
)

_VERIFY_MARKERS = (
    "验活",
    "verification returned",
    "cannot generate images",
)


class RegisterError(RuntimeError):
    """Admin-facing registration failure with a Chinese type, stage, reason, and original text."""

    def __init__(
        self,
        code: str,
        reason: str,
        *,
        stage: str = "",
        original: str = "",
        details: dict[str, Any] | None = None,
        failure_class: str | None = None,
        label: str = "",
    ) -> None:
        spec = REGISTER_ERROR_SPECS.get(str(code or "").strip()) or REGISTER_ERROR_SPECS["unknown"]
        self.code = str(code or "unknown").strip() or "unknown"
        self.label = str(label or spec[0]).strip() or spec[0]
        self.failure_class = str(failure_class or spec[1]).strip() or spec[1]
        raw_stage = str(stage or spec[2]).strip() or spec[2]
        self.stage = display_register_stage(raw_stage, fallback=spec[2]) or spec[2]
        self.reason = str(reason or "").strip() or self.label
        self.original = str(original or "").strip()
        self.details = dict(details or {})
        super().__init__(self.format_log())

    def format_log(self, *, index: int | None = None, cost: float | None = None, kind: str = "error") -> str:
        if str(kind or "error").strip().lower() == "warning":
            prefix = f"任务 {index} 注册警告" if index is not None else "注册警告"
        else:
            prefix = f"任务 {index} 注册失败" if index is not None else "注册失败"
        head = f"{prefix}【{self.label}】【{self.stage}】"
        if cost is not None:
            head += f"耗时 {cost:.1f}s"
        text = f"{head}：{self.reason}"
        if self.original and self.original not in text:
            text += f" 原文：{self.original}"
        return text


def looks_like_cloudflare(text: object) -> bool:
    value = str(text or "").lower()
    if not value:
        return False
    if "这不是 cloudflare" in value or "不是 cloudflare 拦截" in value:
        return False
    return any(marker in value for marker in _CLOUDFLARE_MARKERS)


def looks_like_cloudflare_challenge(text: object) -> bool:
    value = str(text or "").lower()
    if not value:
        return False
    if "这不是 cloudflare" in value or "不是 cloudflare 拦截" in value:
        return False
    return any(marker in value for marker in _CLOUDFLARE_CHALLENGE_MARKERS)


def _looks_like_cloudflare_challenge(lowered: str) -> bool:
    return looks_like_cloudflare_challenge(lowered)


def classify_register_error(error: object, *, stage: str = "") -> RegisterError:
    if isinstance(error, RegisterError):
        mapped = display_register_stage(error.stage, fallback=stage)
        if mapped:
            error.stage = mapped
        elif not str(error.stage or "").strip() or str(error.stage).strip().lower() == "failed":
            spec = REGISTER_ERROR_SPECS.get(error.code) or REGISTER_ERROR_SPECS["unknown"]
            error.stage = spec[2]
        return error

    text = str(error or "").strip()
    lowered = text.lower()
    resolved_stage = display_register_stage(stage)

    if _is_mailbox_wait_timeout(text, lowered):
        login = "microsoft" in lowered or "登录验证码" in text
        code = "mailbox_login_wait_timeout" if login else "mailbox_wait_timeout"
        return RegisterError(
            code,
            _register_reason(text, "等待验证码超时"),
            stage=resolved_stage,
            original=text,
        )

    if _looks_like_cloudflare_challenge(lowered):
        return RegisterError(
            "cloudflare_block",
            "请求被 Cloudflare 拦截。这不是 Token 失效，也不是邮箱接码超时。",
            stage=resolved_stage or "Cloudflare",
            original=text,
        )

    for prefix, code, reason, default_stage in _HTTP_CODE_PREFIXES:
        if prefix in lowered:
            reason_text = (
                "请求被上游拒绝（HTTP 403）。这不是 Token 失效。"
                if "403" in lowered
                else f"{reason}，上游 HTTP 失败。"
            )
            return RegisterError(
                code,
                reason_text,
                stage=default_stage,
                original=text,
            )

    has_token_exchange = any(marker in lowered or marker in text for marker in _TOKEN_EXCHANGE_MARKERS)
    if (
        looks_like_cloudflare(text)
        and not has_token_exchange
        and not _looks_like_verify_context(text, lowered, resolved_stage)
    ):
        return RegisterError(
            "cloudflare_block",
            "请求被 Cloudflare 拦截。这不是 Token 失效，也不是邮箱接码超时。",
            stage=resolved_stage or "Cloudflare",
            original=text,
        )

    if has_token_exchange:
        return RegisterError(
            "token_exchange_failed",
            _register_reason(text, "Token 换取失败"),
            stage="Token 换取",
            original=text,
        )

    if (
        "http 403" in lowered
        or "status=403" in lowered
        or "status_code=403" in lowered
        or "http_403" in lowered
        or ("403" in lowered and _looks_like_verify_context(text, lowered, resolved_stage))
    ):
        if _looks_like_verify_context(text, lowered, resolved_stage):
            return RegisterError(
                "verify_blocked",
                "请求被上游拒绝（HTTP 403）。这不是 Token 失效。",
                stage=resolved_stage or "收口验活",
                original=text,
            )
        return RegisterError(
            "auth_failed",
            "请求被上游拒绝（HTTP 403）。这不是 Token 失效。",
            stage=resolved_stage or "授权",
            original=text,
        )

    if any(marker in lowered or marker in text for marker in _MAILBOX_CLAIM_MARKERS):
        return RegisterError(
            "mailbox_claim_failed",
            _register_reason(text, "邮箱领取失败"),
            stage=resolved_stage or "领取邮箱",
            original=text,
        )

    if any(marker in lowered for marker in _TOKEN_INVALID_MARKERS):
        return RegisterError(
            "token_invalid",
            "Token 已失效（HTTP 401）。",
            stage=resolved_stage or "Token 校验",
            original=text,
        )

    if any(marker in lowered or marker in text for marker in _VERIFY_MARKERS):
        return RegisterError(
            "verify_blocked",
            _register_reason(text, "收口验活失败"),
            stage=resolved_stage or "收口验活",
            original=text,
        )

    if any(marker in lowered for marker in _PROXY_MARKERS):
        return RegisterError(
            "proxy_failed",
            _register_reason(text, "代理连接失败"),
            stage=resolved_stage or "代理",
            original=text,
        )

    if "不支持无密码登录" in text or "passwordless_disabled" in lowered:
        return RegisterError(
            "auth_failed",
            _register_reason(text, "当前邮箱不支持无密码登录。"),
            stage="继续授权",
            original=text,
        )

    if "创建账号" in text or "未返回回调" in text:
        return RegisterError(
            "unknown",
            _register_reason(text, "账号创建失败"),
            stage=resolved_stage or "创建账号资料",
            original=text,
            failure_class="account",
            label="账号创建失败",
        )

    if any(
        marker in lowered
        for marker in (
            "sentinel",
            "oauth",
            "authorize",
            "passwordless",
            "login",
            "validate_otp",
            "invalid verification code",
        )
    ):
        return RegisterError(
            "auth_failed",
            _register_reason(text, "授权失败"),
            stage=resolved_stage or "授权",
            original=text,
        )

    if any(
        marker in lowered or marker in text
        for marker in (
            "register",
            "create_account",
            "about-you",
            "birthdate",
            "username",
        )
    ):
        return RegisterError(
            "unknown",
            _register_reason(text, "账号创建失败"),
            stage=resolved_stage or "创建账号资料",
            original=text,
            failure_class="account",
            label="账号创建失败",
        )

    if any(marker in lowered for marker in ("connect timeout", "connection", "dns", "ssl", "timeout", "network")):
        return RegisterError(
            "network_failed",
            _register_reason(text, "网络失败"),
            stage=resolved_stage or "网络",
            original=text,
        )

    return RegisterError(
        "unknown",
        _register_reason(text, "注册失败"),
        stage=resolved_stage,
        original=text,
    )


def classify_register_failure(error: object, *, stage: str = "") -> str:
    """Keep the historical short-code surface used by worker payloads."""
    return classify_register_error(error, stage=stage).failure_class


def format_register_error(
    error: object,
    *,
    stage: str = "",
    index: int | None = None,
    cost: float | None = None,
    kind: str = "error",
) -> str:
    return classify_register_error(error, stage=stage).format_log(index=index, cost=cost, kind=kind)


def _is_mailbox_wait_timeout(text: str, lowered: str) -> bool:
    if any(marker in text or marker in lowered for marker in _MAILBOX_WAIT_MARKERS):
        return True
    return "no_code" in lowered and ("timeout" in lowered or "超时" in text)


def _looks_like_verify_context(text: str, lowered: str, stage: str) -> bool:
    if "验活" in stage or "验活" in text:
        return True
    if "backend-api/me" in lowered or "get_user_info" in lowered:
        return True
    return any(marker in lowered or marker in text for marker in _VERIFY_MARKERS)
