from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import threading
import time
import uuid
from concurrent.futures import FIRST_COMPLETED, Future, wait
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

from services.account_service import account_service
from services.bounded_task_runner import BoundedTaskRunner
from services.config import DATA_DIR
from services.file_lock import file_lock
from services.register_config_store import create_register_config_store
from services.register import mail_provider, openai_register
from services.register.errors import RegisterError
from services.register.log_redaction import (
    redact_register_log_text,
    redact_register_proxy,
    redact_register_snapshot_inplace,
)
from services.register.provider_catalog import validate_provider_entries
from services.register.types import RegistrationWindow


REGISTER_FILE = DATA_DIR / "register.json"
REGISTER_PEAK = {"time_range": "09:00-18:00", "target_available": 100, "threads": 4}
REGISTER_OFFPEAK = {"time_range": "18:00-09:00", "target_available": 30, "threads": 2}
REGISTER_THREADS_MAX = 16
REGISTER_RUNTIME_LEASE_SECONDS = 30
REGISTER_RUNTIME_HEARTBEAT_SECONDS = max(1.0, min(10.0, REGISTER_RUNTIME_LEASE_SECONDS / 3))
REGISTER_QUEUE_SIZE = 16
REGISTER_PROVIDER_SECRET_PLACEHOLDER = "********"
REGISTER_PROVIDER_SECRET_FIELDS = frozenset({
    "access_token",
    "api_key",
    "authorization",
    "admin_key",
    "admin_password",
    "bearer_token",
    "client_secret",
    "password",
    "refresh_token",
    "secret_key",
    "service_token",
    "token",
})
REGISTER_PROVIDER_SECRET_MARKERS = ("password", "secret", "token", "authorization")
REGISTER_PROVIDER_DISPLAY_KEY_FIELDS = frozenset({
    "api_key",
    "admin_key",
    "client_secret",
    "private_key",
    "secret_key",
    "service_token",
    "token_key",
})
REGISTER_OPENAI_DEFAULT_CONFIG = deepcopy(openai_register.config)


class _RegistrationFutureAdapter:
    """Compatibility surface for callers that previously expected an executor."""

    def __init__(self, runner: BoundedTaskRunner) -> None:
        self._runner = runner

    def submit(self, callback, /, *args, **kwargs) -> Future:
        return self._runner.submit_future(callback, *args, **kwargs)

    def shutdown(self, *, wait: bool = False, cancel_futures: bool = False, timeout: float | None = None) -> bool:
        del cancel_futures
        return self._runner.shutdown(wait=wait, timeout=timeout)


def _serialize_outlook_pool(credentials: list[dict]) -> str:
    lines = []
    for item in credentials:
        email = str(item.get("email") or "").strip()
        if not email:
            continue
        fields = [
            email,
            str(item.get("password") or ""),
            str(item.get("client_id") or ""),
            str(item.get("refresh_token") or ""),
        ]
        recovery_email = str(item.get("recovery_email") or "").strip()
        recovery_token = str(item.get("recovery_refresh_token") or "").strip()
        if "@" in recovery_email and recovery_token:
            fields.extend([recovery_email, recovery_token])
        lines.append("----".join(fields))
    return "\n".join(lines)


def _merge_outlook_pool(old_text: str, new_text: str) -> str:
    """把前端提交的邮箱池当成完整列表。空提交保留原文；同邮箱空密码沿用旧值。"""
    if not str(new_text or "").strip():
        return str(old_text or "")
    old_credentials = {
        credential["email"].strip().lower(): credential
        for credential in mail_provider.parse_outlook_credentials(old_text or "")
    }
    merged: list[dict] = []
    for credential in mail_provider.parse_outlook_credentials(new_text or ""):
        email = credential["email"].strip().lower()
        old = old_credentials.get(email) or {}
        password = str(credential.get("password") or "").strip()
        if not password:
            password = str(old.get("password") or "")
        recovery_email = str(credential.get("recovery_email") or "").strip()
        recovery_token = str(credential.get("recovery_refresh_token") or "").strip()
        if "@" not in recovery_email or not recovery_token:
            recovery_email = str(old.get("recovery_email") or "")
            recovery_token = str(old.get("recovery_refresh_token") or "")
        merged.append({
            "email": credential["email"],
            "password": password,
            "client_id": credential["client_id"],
            "refresh_token": credential["refresh_token"],
            "recovery_email": recovery_email,
            "recovery_refresh_token": recovery_token,
        })
    return _serialize_outlook_pool(merged)


def _serialize_outlook_pool_preserving(credentials: list[dict], original_text: str) -> str:
    """重写合法行时保留无法识别的原文，避免维护动作把历史坏行删掉。"""
    serialized = _serialize_outlook_pool(credentials)
    extras = mail_provider.outlook_invalid_lines(original_text)
    if not extras:
        return serialized
    extra_text = "\n".join(extras)
    if not serialized:
        return extra_text
    return serialized + "\n" + extra_text


def _reject_unrecognized_outlook_pool(text: str) -> None:
    report = mail_provider.inspect_outlook_credentials(text)
    invalid = int(report.get("invalid") or 0)
    if invalid <= 0:
        return
    issues = report.get("invalid_issues") if isinstance(report.get("invalid_issues"), list) else []
    parts: list[str] = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        line = issue.get("line")
        reason = str(issue.get("reason") or "无法识别")
        if line:
            parts.append(f"第 {line} 行：{reason}")
    shown = "；".join(parts)
    hidden = invalid - len(parts)
    extra = f"；另有 {hidden} 行未列出" if hidden > 0 else ""
    detail = f"{shown}{extra}" if shown else ""
    prefix = f"Outlook 邮箱池有 {invalid} 行无法识别，未保存。"
    raise ValueError(prefix + detail if detail else prefix)


def _reject_conflicting_outlook_pool(text: str) -> None:
    report = mail_provider.inspect_outlook_credentials(text)
    conflicts = int(report.get("conflicts") or 0)
    if conflicts <= 0:
        return
    issues = report.get("conflict_issues") if isinstance(report.get("conflict_issues"), list) else []
    parts: list[str] = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        line = issue.get("line")
        reason = str(issue.get("reason") or "凭据不一致")
        if line:
            parts.append(f"第 {line} 行：{reason}")
    shown = "；".join(parts)
    hidden = conflicts - len(parts)
    extra = f"；另有 {hidden} 行未列出" if hidden > 0 else ""
    detail = f"{shown}{extra}" if shown else ""
    prefix = f"Outlook 邮箱池有 {conflicts} 行重复邮箱凭据不一致，未保存。"
    raise ValueError(prefix + detail if detail else prefix)


def _projected_outlook_pool_text(old_text: str, new_text: str, clear_requested: bool) -> str:
    if str(new_text or "").strip():
        return _merge_outlook_pool(old_text, new_text)
    if clear_requested:
        return ""
    return str(old_text or "")


def _reject_cross_pool_outlook_token_conflicts(texts: list[str]) -> None:
    """不同 Outlook 池里同一邮箱的主令牌不一致则整次拒绝。不报出令牌原文。"""
    seen: dict[str, str] = {}
    issues: list[str] = []
    counted: set[str] = set()
    for index, text in enumerate(texts, start=1):
        for credential in mail_provider.parse_outlook_credentials(text):
            email = str(credential.get("email") or "").strip().lower()
            token = str(credential.get("refresh_token") or "")
            if not email or not token:
                continue
            previous = seen.get(email)
            if previous is None:
                seen[email] = token
                continue
            if previous == token or email in counted:
                continue
            counted.add(email)
            issues.append(f"第 {index} 个 Outlook 邮箱池：同一邮箱的主令牌不一致")
    if not issues:
        return
    shown = "；".join(issues[:5])
    hidden = len(issues) - len(issues[:5])
    extra = f"；另有 {hidden} 行未列出" if hidden > 0 else ""
    prefix = f"Outlook 邮箱池有 {len(issues)} 个邮箱在不同池里的主令牌不一致，未保存。"
    raise ValueError(prefix + shown + extra)


def _outlook_credential_changed(old: dict | None, new: dict) -> bool:
    if not old:
        return False
    for key in ("password", "client_id", "refresh_token", "recovery_email", "recovery_refresh_token"):
        if str(old.get(key) or "") != str(new.get(key) or ""):
            return True
    return False


def _outlook_state_reset_requested(old: dict | None, new: dict, store: dict | None = None) -> bool:
    """只有主令牌变化，或离开池后再次导入了不同主令牌，才解除停用。

    只改密码、应用编号或辅助邮箱不解除。已经记住的同一枚停用主令牌再次导入不解除。
    没有旧池记录、也没有记住旧令牌时，停用状态随这个邮箱本身的新导入解除。
    加号行导入不按主号上记住的令牌判断，也不解除主号。
    """
    new_token = str(new.get("refresh_token") or "")
    if old:
        return str(old.get("refresh_token") or "") != new_token
    if not new_token.strip():
        return False
    email = str(new.get("email") or "").strip().lower()
    if not email:
        return False
    if store is None:
        store = mail_provider._load_outlook_token_state()
    fingerprint = mail_provider.outlook_removed_token_fingerprint(new_token)
    for key in (email,):
        entry = store.get(key)
        if not isinstance(entry, dict):
            continue
        if str(entry.get("state") or "") not in mail_provider.OUTLOOK_REFRESHED_CREDENTIAL_RESET_STATES:
            continue
        remembered = str(entry.get(mail_provider.OUTLOOK_REMOVED_TOKEN_KEY) or "")
        if remembered and remembered == fingerprint:
            return False
        return True
    return False


def _acceptable_outlook_refresh_token(token: str, old_token: str) -> bool:
    value = str(token or "").strip()
    if not value or value == str(old_token or "").strip():
        return False
    return "----" not in value and "\n" not in value and "\r" not in value


def _reauth_summary(results: list[dict]) -> dict:
    return {
        "replaced": sum(1 for item in results if item.get("status") == "replaced"),
        "failed": sum(1 for item in results if item.get("status") == "failed"),
        "skipped": sum(1 for item in results if item.get("status") == "skipped"),
        "results": results,
    }


_OUTLOOK_REAUTH_PENDING_CLEAR_KEY = "outlook_reauth_pending_clears"
_OUTLOOK_REAUTH_ROLLBACK_KEY = "outlook_reauth_rollbacks"


def _unique_text_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    seen: set[str] = set()
    for item in value:
        text = str(item or "").strip()
        key = text.lower()
        if not text or key in seen:
            continue
        seen.add(key)
        items.append(text)
    return items


def _outlook_reauth_pending_clear(config: dict) -> tuple[list[str], list[str]]:
    raw = config.get(_OUTLOOK_REAUTH_PENDING_CLEAR_KEY) if isinstance(config, dict) else None
    if isinstance(raw, dict):
        emails = _unique_text_list(raw.get("emails"))
        addresses = _unique_text_list(raw.get("addresses")) or list(emails)
        return emails, addresses
    if isinstance(raw, list):
        emails = _unique_text_list(raw)
        return emails, list(emails)
    return [], []


def _outlook_token_fingerprint(token: object) -> str:
    value = str(token or "").strip()
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _outlook_reauth_pending_token_records(config: dict) -> dict[str, dict]:
    raw = config.get(_OUTLOOK_REAUTH_PENDING_CLEAR_KEY) if isinstance(config, dict) else None
    tokens = raw.get("tokens") if isinstance(raw, dict) else None
    if not isinstance(tokens, dict):
        return {}
    records: dict[str, dict] = {}
    for email, record in tokens.items():
        key = str(email or "").strip().lower()
        if key and isinstance(record, dict):
            records[key] = record
    return records


def _outlook_pool_credentials(config: dict) -> dict[str, dict]:
    mail = config.get("mail") if isinstance(config, dict) and isinstance(config.get("mail"), dict) else {}
    providers = mail.get("providers") if isinstance(mail.get("providers"), list) else []
    found: dict[str, dict] = {}
    for provider in providers:
        if not isinstance(provider, dict) or provider.get("type") != "outlook_token":
            continue
        for credential in mail_provider.parse_outlook_credentials(str(provider.get("mailboxes") or "")):
            email = str(credential.get("email") or "").strip().lower()
            if email and email not in found:
                found[email] = credential
    return found


def _drop_pending_reauth_emails(config: dict, emails: list[str]) -> None:
    raw = config.get(_OUTLOOK_REAUTH_PENDING_CLEAR_KEY)
    if not isinstance(raw, dict):
        return
    drop = {str(item or "").strip().lower() for item in emails if str(item or "").strip()}
    if not drop:
        return
    kept_emails = [
        item for item in _unique_text_list(raw.get("emails"))
        if item.strip().lower() not in drop
    ]
    tokens = raw.get("tokens") if isinstance(raw.get("tokens"), dict) else {}
    kept_tokens = {
        str(key).strip().lower(): value
        for key, value in tokens.items()
        if str(key).strip().lower() not in drop and isinstance(value, dict)
    }
    if not kept_emails and not kept_tokens:
        config.pop(_OUTLOOK_REAUTH_PENDING_CLEAR_KEY, None)
        return
    addresses: list[str] = []
    for key, record in kept_tokens.items():
        addresses.extend(_unique_text_list(record.get("addresses")) or [key])
    config[_OUTLOOK_REAUTH_PENDING_CLEAR_KEY] = {
        "emails": kept_emails,
        "addresses": _unique_text_list(addresses) or list(kept_emails),
        "tokens": kept_tokens,
    }


def _restore_pending_reauth_tokens(
    config: dict,
    old_credentials: dict[str, dict],
    merged_credentials: list[dict],
) -> bool:
    """过期文本框保存不能把刚换上的主令牌写回失效令牌。"""
    raw = config.get(_OUTLOOK_REAUTH_PENDING_CLEAR_KEY) if isinstance(config, dict) else None
    if not isinstance(raw, dict) or not isinstance(raw.get("tokens"), dict):
        return False
    tokens = _outlook_reauth_pending_token_records(config)
    submitted = {str(item.get("email") or "").strip().lower() for item in merged_credentials}
    drop = [email for email in tokens if email not in submitted]
    restored = False
    for credential in merged_credentials:
        email = str(credential.get("email") or "").strip().lower()
        record = tokens.get(email)
        if not isinstance(record, dict):
            continue
        saved = str(record.get("saved") or "")
        previous = str(record.get("previous") or "")
        old = old_credentials.get(email) or {}
        disk_fp = _outlook_token_fingerprint(old.get("refresh_token"))
        submitted_fp = _outlook_token_fingerprint(credential.get("refresh_token"))
        if saved and disk_fp == saved and previous and submitted_fp == previous:
            credential["refresh_token"] = str(old.get("refresh_token") or "")
            restored = True
        elif saved and submitted_fp and submitted_fp != saved:
            drop.append(email)
    if drop:
        _drop_pending_reauth_emails(config, drop)
    return restored


def _restore_reauth_rollbacks(
    config: dict,
    old_credentials: dict[str, dict],
    merged_credentials: list[dict],
) -> bool:
    """成功换上的主令牌不能被稍后保存的旧文本框写回去。"""
    raw = config.get(_OUTLOOK_REAUTH_ROLLBACK_KEY) if isinstance(config, dict) else None
    if not isinstance(raw, dict) or not raw:
        return False
    submitted = {str(item.get("email") or "").strip().lower() for item in merged_credentials}
    remaining = {
        str(email).strip().lower(): record
        for email, record in raw.items()
        if str(email).strip().lower() in submitted and isinstance(record, dict)
    }
    restored = False
    for credential in merged_credentials:
        email = str(credential.get("email") or "").strip().lower()
        record = remaining.get(email)
        if not isinstance(record, dict):
            continue
        saved = str(record.get("saved") or "")
        previous = str(record.get("previous") or "")
        old = old_credentials.get(email) or {}
        disk_fp = _outlook_token_fingerprint(old.get("refresh_token"))
        submitted_fp = _outlook_token_fingerprint(credential.get("refresh_token"))
        if submitted_fp and submitted_fp not in {saved, previous}:
            remaining.pop(email, None)
            continue
        if saved and disk_fp == saved and (not submitted_fp or submitted_fp == previous):
            credential["refresh_token"] = str(old.get("refresh_token") or "")
            restored = True
    if remaining:
        config[_OUTLOOK_REAUTH_ROLLBACK_KEY] = remaining
    else:
        config.pop(_OUTLOOK_REAUTH_ROLLBACK_KEY, None)
    return restored


def _remember_reauth_rollbacks(config: dict, applied: list[dict], previous_by_email: dict[str, str]) -> None:
    current = config.get(_OUTLOOK_REAUTH_ROLLBACK_KEY)
    records = dict(current) if isinstance(current, dict) else {}
    for item in applied:
        email = str(item.get("email") or "").strip().lower()
        if not email:
            continue
        records[email] = {
            "saved": _outlook_token_fingerprint(item.get("refresh_token")),
            "previous": _outlook_token_fingerprint(previous_by_email.get(email, "")),
        }
    if records:
        config[_OUTLOOK_REAUTH_ROLLBACK_KEY] = records


def _drop_reset_addresses_whose_token_remains(
    addresses: list[str],
    old_credentials: dict[str, dict],
    new_credentials: list[dict],
) -> list[str]:
    """旧主令牌还在任一池里时，不解除这个地址的停用。"""
    present: dict[str, set[str]] = {}
    for credential in new_credentials:
        email = str(credential.get("email") or "").strip().lower()
        token = str(credential.get("refresh_token") or "")
        if email and token:
            present.setdefault(email, set()).add(token)
    kept: list[str] = []
    seen: set[str] = set()
    for address in addresses:
        key = address.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        old = old_credentials.get(key)
        old_token = str(old.get("refresh_token") or "") if isinstance(old, dict) else ""
        if old_token and old_token in present.get(key, set()):
            continue
        kept.append(address.strip())
    return kept


def _reauth_clear_addresses(
    applied: list[dict],
    old_credentials: dict[str, dict],
    new_credentials: list[dict],
) -> list[str]:
    """重授权后只解除旧令牌已经不在任何池里的地址。"""
    addresses = _drop_reset_addresses_whose_token_remains(
        _outlook_refresh_reset_addresses(applied),
        old_credentials,
        new_credentials,
    )
    new_tokens = {
        str(item.get("email") or "").strip().lower(): str(item.get("refresh_token") or "")
        for item in applied
        if str(item.get("email") or "").strip()
    }
    present: dict[str, set[str]] = {}
    for credential in new_credentials:
        email = str(credential.get("email") or "").strip().lower()
        token = str(credential.get("refresh_token") or "")
        if email and token:
            present.setdefault(email, set()).add(token)
    kept: list[str] = []
    for address in addresses:
        key = address.strip().lower()
        new_token = new_tokens.get(key, "")
        if new_token and present.get(key, set()) - {new_token}:
            continue
        kept.append(address)
    return kept


def _outlook_refresh_reset_addresses(credentials: list[dict]) -> list[str]:
    """只解除这次凭据自己的地址。加号行不解除主号停用。"""
    addresses: list[str] = []
    seen: set[str] = set()
    for credential in credentials:
        email = str(credential.get("email") or "").strip()
        key = email.lower()
        if not key or key in seen:
            continue
        seen.add(key)
        addresses.append(email)
    return addresses


def _safe_bool(value: object, fallback: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on", "enabled"}:
        return True
    if text in {"0", "false", "no", "n", "off", "disabled", "none", "null", ""}:
        return False
    return fallback


def _safe_int(value: object, fallback: int = 0) -> int:
    try:
        return int(float(str(value or "").strip()))
    except (TypeError, ValueError):
        return fallback


def _bounded_int(
    value: object,
    fallback: int,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    try:
        normalized = int(float(str(value or "").strip()))
    except (TypeError, ValueError):
        normalized = fallback
    normalized = max(minimum, normalized)
    if maximum is not None:
        normalized = min(maximum, normalized)
    return normalized


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _provider_id(provider: dict) -> str:
    return str(provider.get("id") or provider.get("provider_id") or "").strip()


def _normalize_provider_secret_key(key: object) -> str:
    value = str(key or "").strip()
    value = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", value)
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    value = re.sub(r"[^A-Za-z0-9]+", "_", value)
    return value.strip("_").lower()


def _is_provider_secret_field(key: object) -> bool:
    lowered = _normalize_provider_secret_key(key)
    if not lowered or lowered.startswith("public_"):
        return False
    return (
        lowered in REGISTER_PROVIDER_SECRET_FIELDS
        or any(marker in lowered for marker in REGISTER_PROVIDER_SECRET_MARKERS)
        or lowered.endswith("_key")
    )


def _provider_value_contains_secret(value: object) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if _is_provider_secret_field(key):
                if str(item or "").strip() or isinstance(item, (dict, list)):
                    return True
                continue
            if _provider_value_contains_secret(item):
                return True
        return False
    if isinstance(value, list):
        for item in value:
            if _provider_value_contains_secret(item):
                return True
        return False
    return False


def _restore_provider_secret_placeholders(provider: object, old_provider: object | None = None) -> None:
    if not isinstance(provider, dict):
        return
    old = old_provider if isinstance(old_provider, dict) else {}
    for key, value in list(provider.items()):
        if _is_provider_secret_field(key):
            incoming = str(value or "").strip()
            old_value = old.get(key)
            if str(old_value or "").strip():
                if not incoming or incoming == REGISTER_PROVIDER_SECRET_PLACEHOLDER:
                    provider[key] = deepcopy(old_value)
            elif incoming == REGISTER_PROVIDER_SECRET_PLACEHOLDER:
                provider[key] = old_value if str(old_value or "").strip() else ""
            continue
        old_value = old.get(key) if isinstance(old, dict) else None
        if isinstance(value, dict):
            _restore_provider_secret_placeholders(value, old_value)
        elif isinstance(value, list):
            old_items = old_value if isinstance(old_value, list) else []
            for index, item in enumerate(value):
                previous_item = old_items[index] if index < len(old_items) else None
                _restore_provider_secret_placeholders(item, previous_item)
    for key, old_value in old.items():
        if key in provider:
            continue
        if _is_provider_secret_field(key):
            if str(old_value or "").strip() or isinstance(old_value, (dict, list)):
                provider[key] = deepcopy(old_value)
            continue
        if _provider_value_contains_secret(old_value):
            provider[key] = deepcopy(old_value)


def _is_provider_display_key_field(key: object) -> bool:
    return _normalize_provider_secret_key(key) in REGISTER_PROVIDER_DISPLAY_KEY_FIELDS


def _redact_provider_display_keys(value: object) -> None:
    del value


def _ensure_provider_id(provider: dict) -> str:
    provider_id = _provider_id(provider)
    if provider_id:
        provider["id"] = provider_id
        provider.pop("provider_id", None)
        return provider_id
    provider_id = f"provider-{uuid.uuid4().hex[:12]}"
    provider["id"] = provider_id
    return provider_id


def _ensure_provider_ids_unique(providers: object, *, assign_missing: bool = True) -> None:
    if not isinstance(providers, list):
        return
    seen: dict[tuple[str, str], int] = {}
    for index, provider in enumerate(providers):
        if not isinstance(provider, dict):
            continue
        provider_id = _ensure_provider_id(provider) if assign_missing else _provider_id(provider)
        provider_type = str(provider.get("type") or "").strip()
        if not provider_type or not provider_id:
            continue
        key = (provider_type, provider_id)
        previous = seen.get(key)
        if previous is not None:
            raise ValueError(f"邮箱服务重复配置：{provider_type}:{provider_id}")
        seen[key] = index


def _default_config() -> dict:
    base = deepcopy(REGISTER_OPENAI_DEFAULT_CONFIG)
    return {
        **base,
        "mode": "available",
        "target_quota": 100,
        "target_available": 30,
        "check_interval": 5,
        "enabled": False,
        "auto_schedule_enabled": True,
        "register_peak": dict(REGISTER_PEAK),
        "register_offpeak": dict(REGISTER_OFFPEAK),
        "stats": {
            "success": 0,
            "fail": 0,
            "done": 0,
            "running": 0,
            "threads": base["threads"],
            "elapsed_seconds": 0,
            "avg_seconds": 0,
            "success_rate": 0,
            "current_quota": 0,
            "current_available": 0,
            "pause_reason": "",
        },
    }


def _normalize_window(value: object, default: dict[str, object]) -> dict[str, object]:
    raw = value if isinstance(value, dict) else {}
    time_range = str(raw.get("time_range") or default["time_range"]).strip()
    parts = time_range.split("-")
    if len(parts) != 2:
        raise ValueError("注册时间范围必须使用 HH:MM-HH:MM")
    for part in parts:
        hour, separator, minute = part.partition(":")
        if separator != ":" or not hour.isdigit() or not minute.isdigit():
            raise ValueError("注册时间范围必须使用 HH:MM-HH:MM")
        if not 0 <= int(hour) <= 23 or not 0 <= int(minute) <= 59:
            raise ValueError("注册时间范围超出有效范围")
    return {
        "time_range": time_range,
        "target_available": _bounded_int(
            raw.get("target_available"),
            int(default["target_available"]),
            minimum=1,
        ),
        "threads": _bounded_int(
            raw.get("threads"),
            int(default["threads"]),
            minimum=1,
            maximum=16,
        ),
    }


def _normalize_window_for_load(value: object, default: dict[str, object]) -> dict[str, object]:
    try:
        return _normalize_window(value, default)
    except ValueError:
        raw = value if isinstance(value, dict) else {}
        return {
            "time_range": str(default["time_range"]),
            "target_available": _bounded_int(
                raw.get("target_available"),
                int(default["target_available"]),
                minimum=1,
            ),
            "threads": _bounded_int(
                raw.get("threads"),
                int(default["threads"]),
                minimum=1,
                maximum=16,
            ),
        }


def _window_minutes(time_range: str) -> set[int]:
    start_text, end_text = time_range.split("-", 1)
    start_hour, start_minute = (int(value) for value in start_text.split(":", 1))
    end_hour, end_minute = (int(value) for value in end_text.split(":", 1))
    start = start_hour * 60 + start_minute
    end = end_hour * 60 + end_minute
    if start == end:
        return set(range(24 * 60))
    if start < end:
        return set(range(start, end))
    return set(range(start, 24 * 60)) | set(range(0, end))


def _is_register_proxy_url(value: object) -> bool:
    return openai_register.is_register_proxy_url(value)


def _normalize_register_proxy(value: object) -> str:
    return openai_register.normalize_register_proxy(value)


def _normalize(raw: dict, *, recover_invalid_windows: bool = False) -> dict:
    cfg = _default_config()
    cfg.update({k: v for k, v in raw.items() if k not in {"stats", "logs"}})
    cfg["total"] = _bounded_int(cfg.get("total"), 1, minimum=1)
    cfg["threads"] = _bounded_int(
        cfg.get("threads"),
        1,
        minimum=1,
        maximum=REGISTER_THREADS_MAX,
    )
    cfg["mode"] = str(cfg.get("mode") or "total").strip() if str(cfg.get("mode") or "total").strip() in {"total", "quota", "available"} else "total"
    cfg["target_quota"] = _bounded_int(cfg.get("target_quota"), 1, minimum=1)
    cfg["target_available"] = _bounded_int(cfg.get("target_available"), 1, minimum=1)
    cfg["check_interval"] = _bounded_int(cfg.get("check_interval"), 5, minimum=1)
    cfg["auto_schedule_enabled"] = _safe_bool(cfg.get("auto_schedule_enabled"), True)
    window_normalizer = _normalize_window_for_load if recover_invalid_windows else _normalize_window
    cfg["register_peak"] = window_normalizer(cfg.get("register_peak"), REGISTER_PEAK)
    cfg["register_offpeak"] = window_normalizer(cfg.get("register_offpeak"), REGISTER_OFFPEAK)
    peak_minutes = _window_minutes(str(cfg["register_peak"]["time_range"]))
    offpeak_minutes = _window_minutes(str(cfg["register_offpeak"]["time_range"]))
    if peak_minutes & offpeak_minutes or len(peak_minutes | offpeak_minutes) != 24 * 60:
        raise ValueError("注册高峰和低峰窗口必须覆盖 24 小时且不能重叠")
    cfg["proxy"] = _normalize_register_proxy(cfg.get("proxy"))
    cfg["proxy_required"] = True
    cfg.pop("max_inflight_per_proxy", None)
    default_mail = _default_config()["mail"] if isinstance(_default_config().get("mail"), dict) else {}
    mail = cfg.get("mail") if isinstance(cfg.get("mail"), dict) else {}
    cfg["mail"] = {**default_mail, **mail}
    cfg["mail"]["providers"] = validate_provider_entries(cfg["mail"].get("providers"))
    cfg["mail"]["api_use_register_proxy"] = False
    _ensure_provider_ids_unique(cfg["mail"].get("providers"), assign_missing=False)
    try:
        wait_timeout = float(cfg["mail"].get("wait_timeout") or 30)
    except (TypeError, ValueError):
        wait_timeout = 30
    cfg["mail"]["wait_timeout"] = max(1.0, min(mail_provider.MAIL_WAIT_TIMEOUT_MAX, wait_timeout))
    try:
        wait_interval = float(cfg["mail"].get("wait_interval") or 2)
    except (TypeError, ValueError):
        wait_interval = 2
    cfg["mail"]["wait_interval"] = max(0.2, min(cfg["mail"]["wait_timeout"], wait_interval))
    cfg["mail"].pop("proxy", None)
    cfg["enabled"] = _safe_bool(cfg.get("enabled"), False)
    stats_raw = raw.get("stats") if isinstance(raw.get("stats"), dict) else {}
    stats = {**_default_config()["stats"], **stats_raw}
    if "threads" not in stats_raw:
        stats["threads"] = cfg["threads"]
    cfg["stats"] = stats
    return cfg


def _restore_masked_proxy(updates: dict, previous_proxy: object) -> None:
    if not isinstance(updates, dict) or "proxy" not in updates:
        return
    previous = str(previous_proxy or "").strip()
    incoming = str(updates.get("proxy") or "").strip()
    if not previous or not incoming:
        return
    if incoming == REGISTER_PROVIDER_SECRET_PLACEHOLDER:
        updates["proxy"] = previous
        return
    if incoming == redact_register_proxy(previous):
        updates["proxy"] = previous


class RegisterService:
    def __init__(self, store_file: Path):
        self._store_file = store_file
        self._lock = threading.RLock()
        self._outlook_reauth_active = False
        self._runner: threading.Thread | None = None
        self._auto_scheduler: threading.Thread | None = None
        self._shutdown_event = threading.Event()
        self._logs: list[dict] = []
        self._registration_runner = BoundedTaskRunner(
            name="chatgpt-2api-register",
            max_workers=REGISTER_THREADS_MAX,
            queue_size=REGISTER_QUEUE_SIZE,
            error_handler=lambda exc: self._append_log(
                f"注册有界运行器异常: {exc}",
                "error",
            ),
        )
        self._registration_executor = _RegistrationFutureAdapter(self._registration_runner)
        self._registration_executor_shutdown = False
        self._futures_lock = threading.Lock()
        self._active_futures: set = set()
        self._registration_capacity = self._registration_runner.max_workers
        self._owner_id = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        self._run_id = ""
        self._store = create_register_config_store(store_file)
        openai_register.register_log_sink = self._append_log
        self._config = self._load()
        self._fallback_resource_controller = None
        openai_register.config.pop("max_inflight_per_proxy", None)
        openai_register.config.update({
            key: self._config[key]
            for key in (
                "mail",
                "proxy",
                "proxy_required",
                "total",
                "threads",
            )
        })

    def _lock_path(self) -> Path:
        return self._store_file.with_name(f"{self._store_file.name}.lock")

    def _load_unlocked(self) -> dict:
        loaded = self._store.load()
        if not isinstance(loaded, dict):
            loaded = {}
        normalized = _normalize(loaded, recover_invalid_windows=True)
        stored_proxy = str(loaded.get("proxy") or "").strip()
        stored_mail = loaded.get("mail") if isinstance(loaded.get("mail"), dict) else {}
        if (
            stored_proxy != str(normalized.get("proxy") or "").strip()
            or stored_mail.get("api_use_register_proxy") is True
            or "max_inflight_per_proxy" in loaded
        ):
            self._config = normalized
            self._save_unlocked()
        return normalized

    def _save_unlocked(self) -> None:
        self._store.save(self._config)

    def _save_stats_unlocked(self) -> None:
        stats = self._config.get("stats") if isinstance(self._config.get("stats"), dict) else {}
        update_stats = getattr(self._store, "update_stats", None)
        if not callable(update_stats):
            self._save_unlocked()
            return
        runtime = self._config.get("runtime") if isinstance(self._config.get("runtime"), dict) else None
        saved = _normalize(update_stats(stats))
        if runtime is not None:
            saved["runtime"] = runtime
        self._config = saved

    def _load(self) -> dict:
        with file_lock(self._lock_path()):
            return self._load_unlocked()

    def _reload_locked(self) -> None:
        self._config = self._load()

    def _ensure_registration_executor(self) -> None:
        with self._lock:
            if not self._registration_executor_shutdown:
                return
            self._registration_runner.start()
            self._registration_executor_shutdown = False

    def set_registration_submitter(self, submitter) -> None:
        """Compatibility hook; registration owns its own executor now."""
        del submitter

    def _integrations_ready(self) -> bool:
        """Return whether at least one enabled mailbox source can actually run.

        The UI validates this before enabling the start button, but the API is
        also callable directly.  Do not start a registration loop that can
        only produce deterministic configuration failures.
        """
        mail = self._config.get("mail") if isinstance(self._config.get("mail"), dict) else {}
        providers = mail.get("providers") if isinstance(mail.get("providers"), list) else []
        for provider in providers:
            if not isinstance(provider, dict) or not _safe_bool(provider.get("enable", True), True):
                continue
            provider_type = str(provider.get("type") or "").strip().lower()
            if provider_type in {"yyds_mail", "remail"}:
                if str(provider.get("api_key") or "").strip():
                    return True
                continue
            if provider_type == "icloud_api":
                if (
                    str(provider.get("api_base") or "").strip()
                    and str(provider.get("api_key") or "").strip()
                ):
                    return True
                continue
            if provider_type == "outlook_token":
                credentials = mail_provider.parse_outlook_credentials(
                    str(provider.get("mailboxes") or "")
                )
                pool_stats = mail_provider.outlook_token_pool_stats(credentials, provider)
                if int(pool_stats.get("available") or 0) > 0:
                    return True
        return False

    def resume_if_enabled(self) -> dict:
        with self._lock:
            self._reload_locked()
            enabled = bool(self._config.get("enabled"))
        return self.start() if enabled else self.get()

    def start_auto_scheduler(self, stop_event: threading.Event, *, poll_seconds: float | None = None) -> threading.Thread:
        interval = max(0.1, float(poll_seconds if poll_seconds is not None else 5.0))
        with self._lock:
            if self._auto_scheduler is not None and self._auto_scheduler.is_alive():
                return self._auto_scheduler

        def loop() -> None:
            while not stop_event.is_set():
                try:
                    self.reconcile_pending_core_results(limit=4)
                    snapshot = self.get()
                    enabled = bool(snapshot.get("enabled"))
                    running = bool(self._runner and self._runner.is_alive())
                    if enabled and not running and not self._outlook_reauth_active:
                        self.resume_if_enabled()
                    elif not enabled and running:
                        self.stop()
                except ValueError as exc:
                    if "重授权仍在进行" not in str(exc):
                        self._append_log(f"注册自动调度出错：{exc}", "error")
                except Exception as exc:
                    self._append_log(f"注册自动调度出错：{exc}", "error")
                if stop_event.wait(interval):
                    break

        thread = threading.Thread(target=loop, daemon=True, name="openai-register-auto-scheduler")
        with self._lock:
            self._auto_scheduler = thread
        thread.start()
        return thread

    def _submit_registration(self, index: int, local_executor=None):
        if local_executor is not None:
            future = local_executor.submit(lambda: openai_register.worker(index))
        else:
            future = self._registration_runner.submit_future(
                lambda: openai_register.worker(index)
            )
        with self._futures_lock:
            self._active_futures.add(future)
        return future

    def _cancel_pending_registration_futures(self) -> int:
        cancelled = 0
        with self._futures_lock:
            futures = tuple(self._active_futures)
        for future in futures:
            if future.cancel():
                cancelled += 1
        return cancelled

    @staticmethod
    def _minutes(value: str) -> int:
        hour, minute = value.split(":", 1)
        return int(hour) * 60 + int(minute)

    @classmethod
    def _in_time_range(cls, current: int, time_range: str) -> bool:
        start_text, end_text = time_range.split("-", 1)
        start = cls._minutes(start_text)
        end = cls._minutes(end_text)
        if start < end:
            return start <= current < end
        return current >= start or current < end

    def resolve_registration_window(self, now: datetime | None = None) -> RegistrationWindow:
        current = now or datetime.now(timezone(timedelta(hours=8)))
        minute = current.hour * 60 + current.minute
        peak = self._config["register_peak"]
        selected = peak if self._in_time_range(minute, str(peak["time_range"])) else self._config["register_offpeak"]
        name = "peak" if selected is peak else "offpeak"
        return RegistrationWindow(
            name=name,
            target_available=_bounded_int(selected["target_available"], 1, minimum=1),
            time_range=str(selected["time_range"]),
            threads=_bounded_int(
                selected["threads"],
                1,
                minimum=1,
                maximum=REGISTER_THREADS_MAX,
            ),
        )

    @staticmethod
    def _active_target_available(cfg: dict, auto_schedule: bool, window: RegistrationWindow) -> int:
        if auto_schedule:
            return _bounded_int(window.target_available, 1, minimum=1)
        return _bounded_int(cfg.get("target_available"), 1, minimum=1)

    @staticmethod
    def _active_threads(
        cfg: dict,
        auto_schedule: bool,
        window: RegistrationWindow,
        capacity: int = REGISTER_THREADS_MAX,
    ) -> int:
        if auto_schedule:
            requested = _bounded_int(window.threads, 1, minimum=1)
        else:
            requested = _bounded_int(cfg.get("threads"), 1, minimum=1)
        return max(1, min(REGISTER_THREADS_MAX, max(1, _bounded_int(capacity, 1, minimum=1)), requested))

    def should_submit_registration(self) -> bool:
        with self._lock:
            self._reload_locked()
            proxy = str(self._config.get("proxy") or "").strip()
        if not _is_register_proxy_url(proxy):
            self._bump(pause_reason="proxy_required")
            return False
        if not self._integrations_ready():
            self._bump(pause_reason="mail_provider_unavailable")
            return False
        from services.backup_service import backup_service as live_backup
        if callable(getattr(live_backup, "is_restore_active", None)) and live_backup.is_restore_active():
            self._bump(pause_reason="backup_restore")
            return False
        try:
            controller = self._resource_controller()
        except Exception as exc:
            from utils.log import logger

            logger.warning({"event": "register_resource_controller_error", "error": str(exc)})
            self._bump(pause_reason="resource_controller_error")
            return False
        if controller is None:
            self._bump(pause_reason="")
            return True
        decision = controller.allow_new_registration()
        if not decision.allowed:
            self._bump(pause_reason=decision.reason or "resource_pressure")
            return False
        self._bump(pause_reason="")
        return True

    def _resource_controller(self):
        from services.image_task_service import image_task_service

        if image_task_service is None:
            return None
        getter = getattr(image_task_service, "_resource_controller", None)
        if not callable(getter):
            return None
        return getter()


    def _save(self) -> None:
        with file_lock(self._lock_path()):
            self._save_unlocked()

    @staticmethod
    def _parse_datetime(value: object) -> datetime | None:
        try:
            parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
        except Exception:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _runtime_lease_active_locked(self) -> bool:
        runtime = self._config.get("runtime") if isinstance(self._config.get("runtime"), dict) else {}
        if str(runtime.get("state") or "") not in {"running", "stopping"}:
            return False
        expires_at = self._parse_datetime(runtime.get("lease_expires_at"))
        return bool(expires_at and expires_at > datetime.now(timezone.utc))

    def _runtime_owner_locked(self) -> str:
        runtime = self._config.get("runtime") if isinstance(self._config.get("runtime"), dict) else {}
        return str(runtime.get("owner_id") or "").strip()

    def _set_runtime_lease_locked(self, state: str = "running") -> bool:
        now = datetime.now(timezone.utc)
        runtime = self._config.setdefault("runtime", {})
        if not isinstance(runtime, dict):
            runtime = {}
            self._config["runtime"] = runtime
        self._run_id = self._run_id or str(runtime.get("run_id") or uuid.uuid4().hex)
        lease_store = getattr(self._store, "try_acquire_runtime_lease", None)
        if callable(lease_store):
            if not lease_store(self._owner_id, self._run_id, state=state, lease_seconds=REGISTER_RUNTIME_LEASE_SECONDS):
                return False
        runtime.update({
            "owner_id": self._owner_id,
            "run_id": self._run_id,
            "state": state,
            "heartbeat_at": now.isoformat(),
            "lease_expires_at": (now + timedelta(seconds=REGISTER_RUNTIME_LEASE_SECONDS)).isoformat(),
            "updated_at": now.isoformat(),
        })
        if state == "stopping":
            runtime["stop_requested_at"] = now.isoformat()
        else:
            runtime.pop("stop_requested_at", None)
        return True

    def _mark_runtime_stopping_locked(self) -> bool:
        runtime = self._config.setdefault("runtime", {})
        if not isinstance(runtime, dict):
            runtime = {}
            self._config["runtime"] = runtime
        self._run_id = self._run_id or str(runtime.get("run_id") or "")
        lease_store = getattr(self._store, "touch_runtime_lease", None)
        if callable(lease_store):
            if not lease_store(self._owner_id, self._run_id, state="stopping", lease_seconds=REGISTER_RUNTIME_LEASE_SECONDS):
                return False
        now = datetime.now(timezone.utc)
        runtime["state"] = "stopping"
        runtime["stop_requested_at"] = now.isoformat()
        runtime["lease_expires_at"] = (now + timedelta(seconds=REGISTER_RUNTIME_LEASE_SECONDS)).isoformat()
        runtime["updated_at"] = now.isoformat()
        return True

    def _clear_runtime_lease_locked(self) -> bool:
        runtime = self._config.get("runtime") if isinstance(self._config.get("runtime"), dict) else {}
        if not runtime:
            return False
        owner_matches = str(runtime.get("owner_id") or "") == self._owner_id
        run_matches = not self._run_id or str(runtime.get("run_id") or "") == self._run_id
        if owner_matches and run_matches:
            lease_store = getattr(self._store, "release_runtime_lease", None)
            if callable(lease_store):
                if not lease_store(self._owner_id, self._run_id or str(runtime.get("run_id") or "")):
                    return False
            runtime.update({
                "state": "idle",
                "finished_at": _now(),
                "lease_expires_at": _now(),
                "updated_at": _now(),
            })
            runtime.pop("stop_requested_at", None)
            return True
        return False

    def _state_locked(self) -> str:
        runner_alive = bool(self._runner and self._runner.is_alive())
        if runner_alive and self._shutdown_event.is_set():
            return "stopping"
        if not runner_alive and self._runtime_lease_active_locked():
            runtime = self._config.get("runtime") if isinstance(self._config.get("runtime"), dict) else {}
            if str(runtime.get("state") or "") == "stopping":
                return "stopping"
        if not _is_register_proxy_url(self._config.get("proxy")) and (
            runner_alive
            or bool(self._config.get("enabled"))
            or self._runtime_lease_active_locked()
        ):
            return "paused"
        if runner_alive:
            return "running"
        if self._runtime_lease_active_locked():
            return "running"
        if bool(self._config.get("enabled")) and not self._integrations_ready():
            return "paused"
        if bool(self._config.get("enabled")) and str(self._config.get("stats", {}).get("pause_reason") or ""):
            return "paused"
        return "idle"

    def _snapshot(self, *, redact: bool = True, reload: bool = False) -> dict:
        with self._lock:
            if reload:
                self._reload_locked()
            snapshot = json.loads(json.dumps({**self._config, "logs": self._logs[-300:]}, ensure_ascii=False))
            snapshot.pop(_OUTLOOK_REAUTH_ROLLBACK_KEY, None)
            snapshot["state"] = self._state_locked()
        if redact:
            self._redact_outlook_pools(snapshot)
            mail = snapshot.get("mail")
            if isinstance(mail, dict):
                _redact_provider_display_keys(mail.get("providers"))
            redact_register_snapshot_inplace(snapshot)
        return snapshot

    def get(self) -> dict:
        return self._snapshot(redact=True, reload=True)

    def reconcile_pending_core_results(
        self,
        *,
        force: bool = False,
        email: str = "",
        limit: int = 20,
    ) -> dict:
        from services.register.core_result_recovery import reconcile_pending_core_results

        with self._lock:
            self._reload_locked()
            register_proxy = str(self._config.get("proxy") or "")
        result = reconcile_pending_core_results(
            register_proxy=register_proxy,
            force=force,
            email=email,
            limit=limit,
        )
        for error in result.get("errors") or []:
            self._append_log(f"注册核心结果自动收口: {error}", "error")
        return result

    def _runtime_config(self) -> dict:
        return self._snapshot(redact=False, reload=True)

    def _redact_outlook_pools(self, snapshot: dict) -> None:
        """整理 outlook_token 邮箱池的对外展示字段，同时保留原始邮箱凭据。"""
        mail = snapshot.get("mail")
        if not isinstance(mail, dict):
            return
        providers = mail.get("providers")
        if not isinstance(providers, list):
            return
        for index, provider in enumerate(providers):
            if not isinstance(provider, dict) or provider.get("type") != "outlook_token":
                continue
            pool_text = str(provider.get("mailboxes") or "")
            base_credentials = mail_provider.parse_outlook_credentials(pool_text)
            pool_stats = mail_provider.outlook_token_pool_stats(base_credentials, provider)
            provider["mailboxes_configured"] = bool(pool_text.strip())
            provider["mailboxes_count"] = len(base_credentials)
            provider["mailboxes_base_count"] = len(base_credentials)
            provider["mailboxes_alias_count"] = int(pool_stats.get("submitted_alias") or 0)
            provider["mailboxes_preview"] = [c["email"] for c in base_credentials]
            provider["mailboxes_stats"] = pool_stats
            provider["mailboxes_parse_stats"] = mail_provider.inspect_outlook_credentials(pool_text)

    def _drop_mail_proxy(self) -> None:
        if isinstance(self._config.get("mail"), dict):
            self._config["mail"].pop("proxy", None)

    def _merge_provider_secrets(self, updates: dict) -> None:
        mail = updates.get("mail")
        if not isinstance(mail, dict) or not isinstance(mail.get("providers"), list):
            return
        _ensure_provider_ids_unique(mail["providers"])
        old_mail = self._config.get("mail") if isinstance(self._config.get("mail"), dict) else {}
        old_providers = old_mail.get("providers") if isinstance(old_mail.get("providers"), list) else []
        old_by_key = {
            (str(provider.get("type") or ""), _provider_id(provider)): provider
            for provider in old_providers
            if isinstance(provider, dict) and _provider_id(provider)
        }
        old_by_type_order: dict[str, list[dict]] = {}
        for provider in old_providers:
            if not isinstance(provider, dict):
                continue
            old_by_type_order.setdefault(str(provider.get("type") or ""), []).append(provider)
        old_ids_by_type: dict[str, set[str]] = {}
        for provider in old_providers:
            if not isinstance(provider, dict):
                continue
            provider_id = _provider_id(provider)
            if provider_id:
                old_ids_by_type.setdefault(str(provider.get("type") or ""), set()).add(provider_id)
        for provider in mail["providers"]:
            if not isinstance(provider, dict):
                continue
            incoming_had_id = bool(_provider_id(provider))
            _ensure_provider_id(provider)
            provider_type = str(provider.get("type") or "")
            provider_id = _provider_id(provider)
            old = old_by_key.get((provider_type, provider_id))
            typed = old_by_type_order.get(provider_type, [])
            # An ID-less update can inherit a secret only when the type has a
            # single persisted provider.  Array position is not identity and
            # becomes unsafe as soon as two providers share a type.
            if old is None and not incoming_had_id and len(typed) == 1:
                old = typed[0]
            if not isinstance(old, dict):
                for key in REGISTER_PROVIDER_SECRET_FIELDS:
                    if str(provider.get(key) or "").strip() == REGISTER_PROVIDER_SECRET_PLACEHOLDER:
                        provider[key] = ""
                _restore_provider_secret_placeholders(provider)
                continue
            for key in REGISTER_PROVIDER_SECRET_FIELDS:
                old_value = old.get(key)
                incoming = str(provider.get(key) or "").strip()
                if not str(old_value or "").strip():
                    if incoming == REGISTER_PROVIDER_SECRET_PLACEHOLDER:
                        provider[key] = ""
                    continue
                if key not in provider or not incoming or incoming == REGISTER_PROVIDER_SECRET_PLACEHOLDER:
                    provider[key] = old_value
            _restore_provider_secret_placeholders(provider, old)

    def _provider_with_merged_secrets(self, provider: dict | None) -> dict | None:
        if not isinstance(provider, dict):
            return provider
        updates = {"mail": {"providers": [dict(provider)]}}
        self._merge_provider_secrets(updates)
        providers = updates.get("mail", {}).get("providers", [])
        return dict(providers[0]) if providers and isinstance(providers[0], dict) else dict(provider)

    def _merge_outlook_pools(self, updates: dict) -> list[str]:
        """对 outlook_token provider：前端提交的 mailboxes 视为完整列表。

        留空且没有 outlook_pool_clear 表示不改动。页面清空已保存的池时带上该标记，写成空池。
        非空则先检查这次提交的全部 Outlook 池；任一无法识别行或重复凭据冲突都整次拒绝，然后再覆盖。
        同一邮箱多行会合并，辅助邮箱保留；密码、应用编号、主令牌或辅助邮箱不一致则拒绝。
        返回需要在配置成功落库后清理停用或失效状态的邮箱。这里不写状态文件。
        只改密码、应用编号、辅助邮箱或辅助令牌不在返回值里，失效和停用状态继续留给重授权。
        邮箱已经离开池后，只有再次导入了不同主令牌才进入返回值；同一枚已记住的主令牌不进入。
        加号行进入、离开或更换令牌时，主号不进入返回值。
        不同池里同一邮箱的主令牌不一致则整次拒绝，不进入返回值。
        同邮箱若密码留空，沿用已保存密码。
        只按稳定 provider ID 合并；无 ID 仅允许池中唯一的同类型 provider 兼容旧配置。
        """
        mail = updates.get("mail")
        if not isinstance(mail, dict) or not isinstance(mail.get("providers"), list):
            return []
        refreshed_addresses: list[str] = []
        old_mail = self._config.get("mail") if isinstance(self._config.get("mail"), dict) else {}
        old_providers = old_mail.get("providers") if isinstance(old_mail.get("providers"), list) else []
        old_outlook_by_id = {
            _provider_id(provider): provider
            for provider in old_providers
            if isinstance(provider, dict) and provider.get("type") == "outlook_token" and _provider_id(provider)
        }
        old_outlook_by_order = [
            provider
            for provider in old_providers
            if isinstance(provider, dict) and provider.get("type") == "outlook_token"
        ]
        prepared: list[tuple[dict, str, str, bool]] = []
        for provider in mail["providers"]:
            if not isinstance(provider, dict):
                continue
            incoming_had_id = bool(_provider_id(provider))
            _ensure_provider_id(provider)
            if provider.get("type") != "outlook_token":
                continue
            provider_id = _provider_id(provider)
            old = old_outlook_by_id.get(provider_id) or {}
            if not old and not incoming_had_id and len(old_outlook_by_order) == 1:
                old = old_outlook_by_order[0]
            old_text = str(old.get("mailboxes") or "") if old.get("type") == "outlook_token" else ""
            clear_requested = provider.pop("outlook_pool_clear", None) is True
            new_text = str(provider.get("mailboxes") or "")
            prepared.append((provider, old_text, new_text, clear_requested))
        for _provider, _old_text, new_text, _clear_requested in prepared:
            if new_text.strip():
                _reject_unrecognized_outlook_pool(new_text)
        for _provider, _old_text, new_text, _clear_requested in prepared:
            if new_text.strip():
                _reject_conflicting_outlook_pool(new_text)
        _reject_cross_pool_outlook_token_conflicts([
            _projected_outlook_pool_text(old_text, new_text, clear_requested)
            for _provider, old_text, new_text, clear_requested in prepared
        ])
        global_old_credentials = _outlook_pool_credentials(self._config)
        state_store = mail_provider._load_outlook_token_state()
        for provider, old_text, new_text, clear_requested in prepared:
            old_credentials = {
                credential["email"].strip().lower(): credential
                for credential in mail_provider.parse_outlook_credentials(old_text or "")
            }
            if new_text.strip():
                provider["mailboxes"] = _merge_outlook_pool(old_text, new_text)
                merged_credentials = mail_provider.parse_outlook_credentials(provider["mailboxes"])
                restored_reauth_token = _restore_pending_reauth_tokens(self._config, old_credentials, merged_credentials)
                restored_reauth_token = _restore_reauth_rollbacks(self._config, old_credentials, merged_credentials) or restored_reauth_token
                if restored_reauth_token:
                    provider["mailboxes"] = _serialize_outlook_pool_preserving(merged_credentials, str(provider.get("mailboxes") or ""))
                refreshed_credentials = [
                    credential
                    for credential in merged_credentials
                    if _outlook_state_reset_requested(
                        old_credentials.get(credential["email"].strip().lower())
                        or global_old_credentials.get(credential["email"].strip().lower()),
                        credential,
                        state_store,
                    )
                ]
                if refreshed_credentials:
                    refreshed_addresses.extend(_outlook_refresh_reset_addresses(refreshed_credentials))
            elif clear_requested:
                provider["mailboxes"] = ""
            elif old_text:
                provider["mailboxes"] = _merge_outlook_pool(old_text, "")
            else:
                provider["mailboxes"] = ""
            for key in ("mailboxes_count", "mailboxes_base_count", "mailboxes_alias_count", "mailboxes_preview", "mailboxes_stats", "mailboxes_parse_stats"):
                provider.pop(key, None)
        new_credentials = [
            credential
            for provider, _old_text, _new_text, _clear_requested in prepared
            for credential in mail_provider.parse_outlook_credentials(str(provider.get("mailboxes") or ""))
        ]
        return _drop_reset_addresses_whose_token_remains(
            refreshed_addresses,
            global_old_credentials,
            new_credentials,
        )

    def _prune_unused_outlook_pools(self) -> int:
        mail = self._config.get("mail")
        if not isinstance(mail, dict):
            return 0
        providers = mail.get("providers")
        if not isinstance(providers, list):
            return 0
        total_removed = 0
        for provider in providers:
            if not isinstance(provider, dict) or provider.get("type") != "outlook_token":
                continue
            original_text = str(provider.get("mailboxes") or "")
            credentials = mail_provider.parse_outlook_credentials(original_text)
            kept, removed = mail_provider.prune_outlook_unused_credentials(credentials, provider)
            if removed:
                provider["mailboxes"] = _serialize_outlook_pool_preserving(kept, original_text)
                total_removed += removed
            for key in ("mailboxes_count", "mailboxes_base_count", "mailboxes_alias_count", "mailboxes_preview", "mailboxes_stats", "mailboxes_parse_stats"):
                provider.pop(key, None)
        return total_removed

    def _reject_if_outlook_reauth_active_locked(self, action: str) -> None:
        if getattr(self, "_outlook_reauth_active", False):
            raise ValueError(f"辅助邮箱重授权仍在进行，请稍后再{action}")

    def update(self, updates: dict) -> dict:
        if isinstance(updates, dict):
            updates.pop(_OUTLOOK_REAUTH_ROLLBACK_KEY, None)
            updates.pop(_OUTLOOK_REAUTH_PENDING_CLEAR_KEY, None)
        with self._lock:
            self._reject_if_outlook_reauth_active_locked("保存")
            with file_lock(self._lock_path()):
                self._config = self._load_unlocked()
                previous_config = self._config
                _restore_masked_proxy(updates, self._config.get("proxy"))
                self._merge_provider_secrets(updates)
                refreshed_addresses = self._merge_outlook_pools(updates)
                self._config = _normalize({**self._config, **updates})
                self._drop_mail_proxy()
                if not (self._runner and self._runner.is_alive()) and not self._runtime_lease_active_locked():
                    self._config["stats"]["threads"] = self._config["threads"]
                openai_register.config.pop("max_inflight_per_proxy", None)
                openai_register.config.update({k: self._config[k] for k in ("mail", "proxy", "proxy_required", "total", "threads")})
                self._save_unlocked()
                removed_tokens = {
                    email: str(credential.get("refresh_token") or "")
                    for email, credential in _outlook_pool_credentials(previous_config).items()
                    if email not in _outlook_pool_credentials(self._config)
                    and str(credential.get("refresh_token") or "").strip()
                }
                if removed_tokens:
                    mail_provider.remember_outlook_removed_tokens(removed_tokens)
                if refreshed_addresses:
                    mail_provider.clear_outlook_token_states(
                        refreshed_addresses,
                        states=mail_provider.OUTLOOK_REFRESHED_CREDENTIAL_RESET_STATES,
                    )
            return self.get()

    def start(self) -> dict:
        start_runner = False
        start_log = ""
        with self._lock:
            self._reject_if_outlook_reauth_active_locked("启动注册")
            with file_lock(self._lock_path()):
                self._config = self._load_unlocked()
                if self._runner and self._runner.is_alive():
                    if not self._shutdown_event.is_set():
                        self._config["enabled"] = True
                        if not _is_register_proxy_url(self._config.get("proxy")):
                            self._config["stats"].update({
                                "pause_reason": "proxy_required",
                                "updated_at": _now(),
                            })
                        self._save_unlocked()
                elif (
                    self._runtime_lease_active_locked()
                    and self._runtime_owner_locked() != self._owner_id
                ):
                    # Another worker owns the shared runtime lease. Do not
                    # overwrite its persisted status from this non-owner.
                    pass
                else:
                    self._ensure_registration_executor()
                    self._config["enabled"] = True
                    self._shutdown_event.clear()
                    self._drop_mail_proxy()
                    if not _is_register_proxy_url(self._config.get("proxy")):
                        self._config["stats"].update({
                            "pause_reason": "proxy_required",
                            "updated_at": _now(),
                        })
                        self._save_unlocked()
                    elif not self._integrations_ready():
                        self._config["stats"].update({
                            "running": 0,
                            "pause_reason": "mail_provider_unavailable",
                            "updated_at": _now(),
                        })
                        self._save_unlocked()
                    else:
                        self._logs = []
                        metrics = self._pool_metrics()
                        window = self.resolve_registration_window()
                        auto_schedule = bool(self._config.get("auto_schedule_enabled"))
                        target_available = self._active_target_available(self._config, auto_schedule, window)
                        active_threads = self._active_threads(
                            self._config,
                            auto_schedule,
                            window,
                            self._registration_capacity,
                        )
                        self._config["stats"] = {
                            "job_id": uuid.uuid4().hex,
                            "success": 0,
                            "fail": 0,
                            "done": 0,
                            "running": 0,
                            "threads": active_threads,
                            "registration_window": window.name,
                            "registration_time_range": window.time_range,
                            "target_available": target_available,
                            "pause_reason": "",
                            **metrics,
                            "started_at": _now(),
                            "updated_at": _now(),
                        }
                        openai_register.config.update({k: self._config[k] for k in ("mail", "proxy", "total")})
                        openai_register.config["threads"] = active_threads
                        with openai_register.stats_lock:
                            openai_register.stats.update({"done": 0, "success": 0, "fail": 0, "start_time": time.time()})
                        self._run_id = uuid.uuid4().hex
                        if self._set_runtime_lease_locked("running"):
                            self._save_unlocked()
                            start_runner = True
                            start_log = f"注册任务已启动：模式={self._config['mode']}，线程={active_threads}"
                        else:
                            # The compare-and-set lost a race to another
                            # worker. Its shared state is authoritative.
                            self._config = self._load_unlocked()
            if start_runner:
                self._runner = threading.Thread(target=self._run, daemon=True, name="openai-register")
                self._runner.start()
        if start_log:
            self._append_log(start_log, "yellow")
        return self.get()

    def stop(self) -> dict:
        with self._lock:
            with file_lock(self._lock_path()):
                self._config = self._load_unlocked()
                self._config["enabled"] = False
                self._shutdown_event.set()
                self._config["stats"]["pause_reason"] = ""
                self._config["stats"]["updated_at"] = _now()
                if self._runtime_lease_active_locked() or (self._runner and self._runner.is_alive()):
                    self._mark_runtime_stopping_locked()
                self._save_unlocked()
        self._append_log("已请求停止注册，正在等待进行中的任务结束", "yellow")
        return self.get()

    def shutdown(self, timeout: float | None = None) -> dict | bool:
        self._shutdown_event.set()
        cancelled = self._cancel_pending_registration_futures()
        if cancelled:
            self._append_log(f"注册关闭已取消 {cancelled} 个排队任务", "yellow")
        with self._lock:
            runner = self._runner
        deadline = None if timeout is None else time.monotonic() + max(0.0, float(timeout))
        if runner is not None and runner.is_alive():
            remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
            runner.join(remaining)
        if runner is not None and runner.is_alive():
            self._append_log(
                "注册关闭超时，后台注册任务仍在收尾",
                "red",
            )
            return False
        with self._lock:
            executor_shutdown = self._registration_executor_shutdown
        if not executor_shutdown:
            remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
            finished = self._registration_runner.shutdown(wait=True, timeout=remaining)
            if finished is False:
                self._append_log(
                    "注册关闭超时，后台注册任务仍在收尾",
                    "red",
                )
                return False
            with self._lock:
                self._registration_executor_shutdown = True
        try:
            return self.get()
        except Exception as exc:
            # Shutdown must not re-raise merely because the application
            # database is unavailable.  The executor and runner have already
            # been stopped; return the last in-memory projection so the App
            # lifespan can continue releasing the other services.
            self._append_log(f"注册关闭时无法读取快照：{exc}", "error")
            return self._snapshot(redact=True, reload=False)

    def reset(self) -> dict:
        pool_metrics = self._pool_metrics()
        with self._lock:
            with file_lock(self._lock_path()):
                self._config = self._load_unlocked()
                if self._runner and self._runner.is_alive() or self._runtime_lease_active_locked():
                    raise ValueError("注册任务仍在运行，请先停止再重置")
                self._logs = []
                self._config["stats"] = {"success": 0, "fail": 0, "done": 0, "running": 0, "threads": self._config["threads"], "elapsed_seconds": 0, "avg_seconds": 0, "success_rate": 0, **pool_metrics, "updated_at": _now()}
                with openai_register.stats_lock:
                    openai_register.stats.update({"done": 0, "success": 0, "fail": 0, "start_time": 0.0})
                self._save_unlocked()
            return self.get()

    def _registration_running_locked(self) -> bool:
        return bool(self._runner and self._runner.is_alive()) or self._runtime_lease_active_locked()

    def reauthorize_outlook_pool(self, session=None) -> dict:
        """用辅助邮箱重取主令牌。整个动作持有同一把锁，注册还在跑时直接拒绝。"""
        from services.register.outlook_reauth import (
            OUTLOOK_REAUTH_LOCK,
            OutlookReauthError,
            default_outlook_reauth_session,
            outlook_reauth_skip_reason,
            public_reauth_reason,
        )

        if not OUTLOOK_REAUTH_LOCK.acquire(blocking=False):
            raise ValueError("辅助邮箱重授权仍在进行，请稍后再试")
        authorizer = session or default_outlook_reauth_session()
        try:
            with self._lock:
                self._reload_locked()
                if self._registration_running_locked():
                    raise ValueError("注册任务仍在运行，请先停止再用辅助邮箱重授权")
                self._outlook_reauth_active = True
            try:
                prepare = getattr(authorizer, "ensure_ready", None)
                if callable(prepare):
                    try:
                        prepare()
                    except OutlookReauthError as exc:
                        raise ValueError(str(exc)) from exc
                with self._lock:
                    self._reload_locked()
                    healed = self._finish_outlook_reauth_pending_clears()
                    proxy = str(self._config.get("proxy") or "")
                    queued = self._outlook_reauth_queue()
                results: list[dict] = [{"email": email, "status": "replaced", "reason": ""} for email in healed]
                healed_keys = {email.lower() for email in healed}
                pending: list[dict] = []
                chosen: dict[str, dict] = {}
                deferred: list[tuple[dict, str]] = []
                for item in queued:
                    credential = item["credential"]
                    email = str(credential.get("email") or "")
                    email_key = email.strip().lower()
                    if not email_key or email_key in healed_keys:
                        continue
                    reason = outlook_reauth_skip_reason(item["store"], credential)
                    if reason:
                        deferred.append((item, reason))
                        continue
                    if email_key not in chosen:
                        chosen[email_key] = item
                authorized: set[str] = set()
                for email_key, item in chosen.items():
                    credential = item["credential"]
                    email = str(credential.get("email") or "")
                    try:
                        new_token = str(authorizer.authorize(credential, proxy=proxy) or "").strip()
                    except Exception as exc:
                        results.append({
                            "email": email,
                            "status": "failed",
                            "reason": public_reauth_reason(exc, credential),
                        })
                        continue
                    if not _acceptable_outlook_refresh_token(new_token, str(credential.get("refresh_token") or "")):
                        results.append({"email": email, "status": "failed", "reason": "没有换到新的主令牌"})
                        continue
                    pending.append({**item, "new_token": new_token})
                    authorized.add(email_key)
                for item, reason in deferred:
                    credential = item["credential"]
                    email = str(credential.get("email") or "")
                    email_key = email.strip().lower()
                    chosen_item = chosen.get(email_key)
                    if (
                        email_key in authorized
                        and chosen_item is not None
                        and str(chosen_item.get("old_token") or "") == str(item.get("old_token") or "")
                    ):
                        continue
                    results.append({"email": email, "status": "skipped", "reason": reason})
                with self._lock:
                    applied = self._commit_outlook_reauth(
                        pending,
                        results,
                        clear_state=not self._registration_running_locked(),
                    )
                    del applied
                    summary = _reauth_summary(results)
                    self._append_log(
                        "Outlook 辅助邮箱重授权：更换 "
                        f"{summary['replaced']}，失败 {summary['failed']}，跳过 {summary['skipped']}",
                        "yellow" if summary["failed"] else "green",
                    )
                    return {"register": self.get(), "reauth": summary}
            finally:
                with self._lock:
                    self._outlook_reauth_active = False
        finally:
            OUTLOOK_REAUTH_LOCK.release()

    def _outlook_reauth_queue(self) -> list[dict]:
        store = mail_provider._load_outlook_token_state()
        mail = self._config.get("mail") if isinstance(self._config.get("mail"), dict) else {}
        providers = mail.get("providers") if isinstance(mail.get("providers"), list) else []
        queued = []
        for index, provider in enumerate(providers):
            if not isinstance(provider, dict) or str(provider.get("type") or "") != "outlook_token":
                continue
            for credential in mail_provider.parse_outlook_credentials(str(provider.get("mailboxes") or "")):
                queued.append({
                    "provider_index": index,
                    "provider_id": str(provider.get("id") or ""),
                    "credential": dict(credential),
                    "old_token": str(credential.get("refresh_token") or ""),
                    "store": store,
                })
        return queued

    def _publish_register_runtime_config_locked(self) -> None:
        openai_register.config.pop("max_inflight_per_proxy", None)
        openai_register.config.update({
            "mail": deepcopy(self._config.get("mail")),
            "proxy": self._config.get("proxy"),
            "proxy_required": self._config.get("proxy_required"),
            "total": self._config.get("total"),
            "threads": self._config.get("threads"),
        })

    def _commit_outlook_reauth(self, pending: list[dict], results: list[dict], *, clear_state: bool = True) -> list[dict]:
        from services.register.outlook_reauth import _outlook_reauth_busy

        applied: list[dict] = []
        previous_by_email: dict[str, str] = {}
        with file_lock(self._lock_path()):
            self._config = self._load_unlocked()
            if not pending:
                return applied
            store = mail_provider._load_outlook_token_state()
            old_credentials = _outlook_pool_credentials(self._config)
            pending_by_email: dict[str, dict] = {}
            for item in pending:
                email_key = str(item.get("credential", {}).get("email") or "").strip().lower()
                if email_key and email_key not in pending_by_email:
                    pending_by_email[email_key] = item
            mail = self._config.get("mail") if isinstance(self._config.get("mail"), dict) else {}
            providers = mail.get("providers") if isinstance(mail.get("providers"), list) else []
            changed_emails: set[str] = set()
            busy_emails: set[str] = set()
            for provider in providers:
                if not isinstance(provider, dict) or str(provider.get("type") or "") != "outlook_token":
                    continue
                original_text = str(provider.get("mailboxes") or "")
                current = mail_provider.parse_outlook_credentials(original_text)
                updated: list[dict] = []
                changed = False
                for credential in current:
                    email_key = str(credential.get("email") or "").strip().lower()
                    item = pending_by_email.get(email_key)
                    if not item or email_key in busy_emails:
                        updated.append(credential)
                        continue
                    if str(credential.get("refresh_token") or "") != str(item.get("old_token") or ""):
                        updated.append(credential)
                        continue
                    if _outlook_reauth_busy(store, credential):
                        busy_emails.add(email_key)
                        updated.append(credential)
                        continue
                    previous_by_email.setdefault(email_key, str(credential.get("refresh_token") or ""))
                    replaced = dict(credential)
                    replaced["refresh_token"] = str(item.get("new_token") or "")
                    updated.append(replaced)
                    applied.append(replaced)
                    changed_emails.add(email_key)
                    changed = True
                if changed:
                    provider["mailboxes"] = _serialize_outlook_pool_preserving(updated, original_text)
            for email_key, item in pending_by_email.items():
                if email_key in changed_emails:
                    continue
                results.append({
                    "email": str(item.get("credential", {}).get("email") or ""),
                    "status": "skipped",
                    "reason": "主号仍在使用" if email_key in busy_emails else "邮箱池已变化",
                })
            if not applied:
                return applied
            new_credentials: list[dict] = []
            for provider in providers:
                if isinstance(provider, dict) and str(provider.get("type") or "") == "outlook_token":
                    new_credentials.extend(
                        mail_provider.parse_outlook_credentials(str(provider.get("mailboxes") or ""))
                    )
            addresses = _reauth_clear_addresses(applied, old_credentials, new_credentials)
            emails = _unique_text_list([str(item.get("email") or "") for item in applied])
            tokens: dict[str, dict] = {}
            for item in applied:
                email_key = str(item.get("email") or "").strip().lower()
                if not email_key or email_key in tokens:
                    continue
                tokens[email_key] = {
                    "saved": _outlook_token_fingerprint(item.get("refresh_token")),
                    "previous": _outlook_token_fingerprint(previous_by_email.get(email_key, "")),
                    "addresses": _reauth_clear_addresses([item], old_credentials, new_credentials),
                }
            self._config[_OUTLOOK_REAUTH_PENDING_CLEAR_KEY] = {
                "emails": emails,
                "addresses": addresses,
                "tokens": tokens,
            }
            _remember_reauth_rollbacks(self._config, applied, previous_by_email)
            try:
                self._save_unlocked()
            except Exception:
                self._config = self._load_unlocked()
                applied.clear()
                raise
            self._publish_register_runtime_config_locked()
            if not clear_state:
                seen_failed: set[str] = set()
                for credential in applied:
                    email = str(credential.get("email") or "")
                    email_key = email.strip().lower()
                    if not email_key or email_key in seen_failed:
                        continue
                    seen_failed.add(email_key)
                    results.append({
                        "email": email,
                        "status": "failed",
                        "reason": "主令牌已更换，但注册任务仍在运行，未解除失效标记",
                    })
                return applied
            try:
                mail_provider.clear_outlook_token_states(
                    addresses,
                    states=mail_provider.OUTLOOK_REFRESHED_CREDENTIAL_RESET_STATES,
                )
            except Exception:
                raise
            self._config.pop(_OUTLOOK_REAUTH_PENDING_CLEAR_KEY, None)
            self._save_unlocked()
        seen_replaced: set[str] = set()
        for credential in applied:
            email = str(credential.get("email") or "")
            email_key = email.strip().lower()
            if not email_key or email_key in seen_replaced:
                continue
            seen_replaced.add(email_key)
            results.append({"email": email, "status": "replaced", "reason": ""})
        return applied

    def _finish_outlook_reauth_pending_clears(self) -> list[str]:
        emails, _addresses = _outlook_reauth_pending_clear(self._config)
        if not emails and not _addresses:
            return []
        with file_lock(self._lock_path()):
            self._config = self._load_unlocked()
            emails, addresses = _outlook_reauth_pending_clear(self._config)
            if not emails and not addresses:
                return []
            raw = self._config.get(_OUTLOOK_REAUTH_PENDING_CLEAR_KEY)
            if isinstance(raw, dict) and "tokens" in raw:
                matched_emails, matched_addresses = self._matched_pending_reauth_clears(emails)
                if not matched_emails:
                    self._config.pop(_OUTLOOK_REAUTH_PENDING_CLEAR_KEY, None)
                    self._save_unlocked()
                    return []
                emails, addresses = matched_emails, matched_addresses
            mail_provider.clear_outlook_token_states(
                addresses or emails,
                states=mail_provider.OUTLOOK_REFRESHED_CREDENTIAL_RESET_STATES,
            )
            self._config.pop(_OUTLOOK_REAUTH_PENDING_CLEAR_KEY, None)
            self._save_unlocked()
        return emails or addresses

    def _matched_pending_reauth_clears(self, emails: list[str]) -> tuple[list[str], list[str]]:
        records = _outlook_reauth_pending_token_records(self._config)
        current = _outlook_pool_credentials(self._config)
        matched_emails: list[str] = []
        matched_addresses: list[str] = []
        for email in emails:
            key = email.strip().lower()
            record = records.get(key) or {}
            saved = str(record.get("saved") or "")
            credential = current.get(key) or {}
            if not saved or _outlook_token_fingerprint(credential.get("refresh_token")) != saved:
                continue
            matched_emails.append(email)
            matched_addresses.extend(_unique_text_list(record.get("addresses")) or [email])
        return matched_emails, _unique_text_list(matched_addresses)

    def reset_outlook_pool(self, scope: str = "all") -> dict:
        scope = str(scope or "all").strip().lower()
        with self._lock:
            self._reject_if_outlook_reauth_active_locked("重置 Outlook 邮箱池")
            self._reload_locked()
            if (
                (self._runner and self._runner.is_alive())
                or self._runtime_lease_active_locked()
            ):
                raise ValueError("注册任务仍在运行，请先停止再重置 Outlook 邮箱池")
            if scope == "unused":
                with file_lock(self._lock_path()):
                    self._config = self._load_unlocked()
                    removed = self._prune_unused_outlook_pools()
                    openai_register.config.pop("max_inflight_per_proxy", None)
                    openai_register.config.update({k: self._config[k] for k in ("mail", "proxy", "proxy_required", "total", "threads")})
                    self._save_unlocked()
                    self._append_log(f"已清空 Outlook 邮箱池未使用邮箱，移除 {removed} 个", "yellow")
            else:
                scope_aliases = {"failed": "retryable", "retryable": "retryable", "invalid": "invalid", "all": "all"}
                if scope not in scope_aliases:
                    raise ValueError(f"不支持的 Outlook 邮箱池重置范围: {scope}")
                scope = scope_aliases[scope]
                cleared = mail_provider.reset_outlook_token_pool_state(scope)
                scope_label = {"retryable": "占用/临时失败", "invalid": "异常", "all": "全部"}[scope]
                self._append_log(
                    f"已重置 Outlook 邮箱池状态（范围={scope_label}），清除 {cleared} 条记录；已提交加号标签保留",
                    "yellow",
                )
        return self.get()

    def _append_log(self, text: str, color: str = "") -> None:
        with self._lock:
            self._logs.append({"time": _now(), "text": redact_register_log_text(text), "level": str(color or "info")})
            self._logs = self._logs[-300:]

    def _append_core_result_failure_log(self, worker_result: dict) -> None:
        core_result = worker_result.get("result") if isinstance(worker_result, dict) else None
        if not isinstance(core_result, dict) or not str(core_result.get("access_token") or "").strip():
            return
        payload = {
            key: core_result.get(key)
            for key in (
                "email",
                "password",
                "access_token",
                "refresh_token",
                "id_token",
                "register_proxy",
                "source_type",
                "created_at",
            )
            if core_result.get(key) not in (None, "")
        }
        if isinstance(core_result.get("fp"), dict):
            payload["fp"] = core_result["fp"]
        recovery_file = str(worker_result.get("recovery_file") or "").strip()
        original_parts = []
        if payload:
            original_parts.append(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
        if recovery_file:
            original_parts.append(f"核心结果暂存文件={recovery_file}")
        index = worker_result.get("index")
        try:
            index = int(index) if index is not None else None
        except (TypeError, ValueError):
            index = None
        self._append_log(
            RegisterError(
                "unknown",
                str(worker_result.get("error") or "").strip() or "注册核心结果未入库，等待自动收口",
                stage="入库",
                original="，".join(original_parts),
                label="核心结果未入库",
            ).format_log(index=index),
            "error",
        )

    def _pool_metrics(
        self,
        *,
        refresh_stale: bool = False,
        target_quota: int | None = None,
        target_available: int | None = None,
    ) -> dict:
        return account_service.evaluate_account_pool(
            refresh_stale=refresh_stale,
            target_quota=target_quota,
            target_available=target_available,
        )

    def _target_reached(self, cfg: dict, submitted: int) -> bool:
        mode = str(cfg.get("mode") or "total")
        metrics = self._pool_metrics(
            refresh_stale=mode in {"quota", "available"},
            target_quota=_bounded_int(cfg.get("target_quota"), 1, minimum=1) if mode == "quota" else None,
            target_available=_bounded_int(cfg.get("target_available"), 1, minimum=1) if mode == "available" else None,
        )
        self._bump(**metrics)
        if mode == "quota":
            reached = metrics["current_quota"] >= _bounded_int(cfg.get("target_quota"), 1, minimum=1)
            self._append_log(f"检查号池：当前正常账号={metrics['current_available']}，当前剩余额度={metrics['current_quota']}，目标额度={cfg.get('target_quota')}，{'跳过注册' if reached else '继续注册'}", "yellow")
            return reached
        if mode == "available":
            reached = metrics["current_available"] >= _bounded_int(cfg.get("target_available"), 1, minimum=1)
            self._append_log(f"检查号池：当前正常账号={metrics['current_available']}，目标账号={cfg.get('target_available')}，当前剩余额度={metrics['current_quota']}，{'跳过注册' if reached else '继续注册'}", "yellow")
            return reached
        return submitted >= _bounded_int(cfg.get("total"), 1, minimum=1)

    def _bump(self, **updates) -> None:
        with self._lock:
            with file_lock(self._lock_path()):
                self._config = self._load_unlocked()
                stats = self._config["stats"]
                stats.update(updates)
                self._update_runtime_stats_locked(stats)
                if self._runner and self._runner.is_alive():
                    runtime_state = (
                        "stopping"
                        if self._shutdown_event.is_set() or not bool(self._config.get("enabled"))
                        else "running"
                    )
                    if not self._set_runtime_lease_locked(runtime_state):
                        self._shutdown_event.set()
                        return
                self._save_stats_unlocked()

    @staticmethod
    def _update_runtime_stats_locked(stats: dict) -> None:
        started_at = str(stats.get("started_at") or "")
        if started_at:
            try:
                elapsed = max(0.0, (datetime.now(timezone.utc) - datetime.fromisoformat(started_at)).total_seconds())
            except Exception:
                elapsed = 0.0
            success = int(stats.get("success") or 0)
            fail = int(stats.get("fail") or 0)
            stats["elapsed_seconds"] = round(elapsed, 1)
            stats["avg_seconds"] = round(elapsed / success, 1) if success else 0
            stats["success_rate"] = round(success * 100 / max(1, success + fail), 1)
        stats["updated_at"] = _now()

    def _run(self) -> None:
        submitted, done, success, fail = 0, 0, 0, 0
        futures = set()
        run_failed = False

        def collect_finished(finished) -> None:
            nonlocal done, success, fail
            for future in finished:
                with self._futures_lock:
                    self._active_futures.discard(future)
                done += 1
                try:
                    result = future.result()
                    ok = bool(result.get("ok")) if isinstance(result, dict) else False
                    success += 1 if ok else 0
                    fail += 0 if ok else 1
                    if isinstance(result, dict) and not ok and result.get("core_ok"):
                        self._append_core_result_failure_log(result)
                except Exception as exc:
                    fail += 1
                    self._append_log(f"注册子任务异常: {exc}", "error")

        def finish_runtime() -> None:
            finished_at = _now()
            try:
                self._bump(running=0, done=done, success=success, fail=fail, finished_at=finished_at)
            except Exception:
                pass
            try:
                with self._lock:
                    with file_lock(self._lock_path()):
                        self._config = self._load_unlocked()
                        runtime = self._config.get("runtime") if isinstance(self._config.get("runtime"), dict) else {}
                        if (
                            str(runtime.get("owner_id") or "") != self._owner_id
                            or str(runtime.get("run_id") or "") != self._run_id
                        ):
                            return
                        stats = self._config.setdefault("stats", {})
                        stats.update({
                            "running": 0,
                            "done": done,
                            "success": success,
                            "fail": fail,
                            "finished_at": stats.get("finished_at") or finished_at,
                        })
                        self._update_runtime_stats_locked(stats)
                        if not self._shutdown_event.is_set():
                            self._config["enabled"] = False
                        self._clear_runtime_lease_locked()
                        self._save_unlocked()
            except Exception as exc:
                # The state store may be unavailable during shutdown.  Do not
                # let that secondary failure escape the worker thread; the next
                # scheduler pass can retry the persisted runtime cleanup.
                self._append_log(f"注册运行状态收口失败: {exc}", "error")

        try:
            while not self._shutdown_event.is_set():
                cfg = self._runtime_config()
                auto_schedule = bool(cfg.get("auto_schedule_enabled"))
                window = self.resolve_registration_window()
                active_threads = self._active_threads(
                    cfg,
                    auto_schedule,
                    window,
                    self._registration_capacity,
                )
                target_available = self._active_target_available(cfg, auto_schedule, window)
                runtime_cfg = {
                    **cfg,
                    "mode": "available" if auto_schedule else str(cfg.get("mode") or "total"),
                    "target_available": target_available,
                    "threads": active_threads,
                }
                openai_register.config.pop("max_inflight_per_proxy", None)
                openai_register.config.update({k: runtime_cfg[k] for k in ("mail", "proxy", "proxy_required", "total", "threads")})
                self._bump(
                    threads=active_threads,
                    registration_window=window.name,
                    registration_time_range=window.time_range,
                    target_available=target_available,
                )
                target_reached = False
                while (
                    not self._shutdown_event.is_set()
                    and
                    self._runtime_config()["enabled"]
                    and len(futures) < active_threads
                ):
                    target_reached = self._target_reached(runtime_cfg, submitted)
                    if target_reached:
                        break
                    if not self.should_submit_registration():
                        break
                    submitted += 1
                    futures.add(self._submit_registration(submitted, None))
                self._bump(running=len(futures), done=done, success=success, fail=fail)
                if not futures and (
                    self._shutdown_event.is_set()
                    or not self._runtime_config()["enabled"]
                    or (
                        not auto_schedule
                        and target_reached
                    )
                ):
                    break
                if not futures:
                    self._shutdown_event.wait(
                        min(
                            max(1, _bounded_int(cfg.get("check_interval"), 5, minimum=1)),
                            REGISTER_RUNTIME_HEARTBEAT_SECONDS,
                        )
                    )
                    continue
                finished, futures = wait(
                    futures,
                    timeout=REGISTER_RUNTIME_HEARTBEAT_SECONDS,
                    return_when=FIRST_COMPLETED,
                )
                if not finished:
                    self._bump(running=len(futures), done=done, success=success, fail=fail)
                    continue
                collect_finished(finished)
            while futures:
                self._bump(running=len(futures), done=done, success=success, fail=fail)
                finished, futures = wait(
                    futures,
                    timeout=REGISTER_RUNTIME_HEARTBEAT_SECONDS,
                    return_when=FIRST_COMPLETED,
                )
                if not finished:
                    continue
                collect_finished(finished)
        except Exception as exc:
            run_failed = True
            self._append_log(f"注册任务异常退出: {exc}", "error")
            raise
        finally:
            while futures:
                self._bump(running=len(futures), done=done, success=success, fail=fail)
                finished, futures = wait(
                    futures,
                    timeout=REGISTER_RUNTIME_HEARTBEAT_SECONDS,
                    return_when=FIRST_COMPLETED,
                )
                if not finished:
                    continue
                collect_finished(finished)
            finish_runtime()
            if not run_failed:
                self._append_log(f"注册任务结束，成功{success}，失败{fail}", "yellow")


register_service = RegisterService(REGISTER_FILE)
