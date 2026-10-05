from __future__ import annotations

import base64
import hashlib
import imaplib
import itertools
import logging
import random
import re
import secrets
import socket
import string
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email import message_from_bytes, message_from_string, policy
from email.header import decode_header, make_header
from email.utils import getaddresses, parsedate_to_datetime
from threading import Lock
from typing import Any, Callable, TypeVar
from urllib.parse import quote, unquote, urljoin, urlsplit

from curl_cffi import requests


from services.browser_fingerprint import CHROME146_IMPERSONATE, CHROME146_USER_AGENT, chrome146_headers
from services.config import DATA_DIR
from services.file_lock import file_lock
from services.http_target import http_target_session_request
from services.json_file import read_json_file, write_json_file
from services.proxy_service import proxy_settings
from services.register.log_redaction import redact_register_log_text
from services.register.provider_catalog import ALLOWED_MAIL_PROVIDER_TYPES, validate_provider_entries
from utils.diagnostics import sanitize_diagnostic_text

logger = logging.getLogger(__name__)

OUTLOOK_TOKEN_USED_FILE = DATA_DIR / "outlook_token_used.json"
_outlook_token_state_lock = Lock()
# in_use 超过该秒数视为陈旧（注册进程崩溃残留），可被重新领用
OUTLOOK_IN_USE_STALE_SECONDS = 3600
OUTLOOK_ALIAS_TAG_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
OUTLOOK_ALIAS_TAG_MIN_LENGTH = 2
OUTLOOK_ALIAS_LOCAL_PART_MAX_BYTES = 64
OUTLOOK_ALIAS_NO_CODE_RETIRE_STREAK = 3
OUTLOOK_ALIAS_TAG_SAMPLE_ATTEMPTS = 128
OUTLOOK_CODE_BOUNDARY_SKEW_SECONDS = 120
OUTLOOK_CODE_SEARCH_MAX_MESSAGES = 200
OUTLOOK_NO_CODE_TIMEOUT_CODES = {"mailbox_wait_timeout", "mailbox_login_wait_timeout"}
OUTLOOK_OCCUPIED_TAG_STATES = {"used", "in_use", "failed", "retired", "login_required", "token_invalid"}
OUTLOOK_GRAPH_INBOX_MESSAGES_URL = "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages"
OUTLOOK_GRAPH_JUNK_MESSAGES_URL = "https://graph.microsoft.com/v1.0/me/mailFolders/junkemail/messages"
OUTLOOK_GRAPH_MESSAGE_SELECT = "subject,receivedDateTime,from,toRecipients,ccRecipients,body,bodyPreview,internetMessageHeaders"
OUTLOOK_IMAP_JUNK_NAMES = ("Junk", "Junk Email", "垃圾邮件")
OUTLOOK_RECORDED_STATES = {"used", "in_use", "login_required", "token_invalid", "failed", "retired"}
OUTLOOK_UNAVAILABLE_STATES = {"used", "login_required", "token_invalid", "failed", "retired"}
OUTLOOK_BUSY_STATES = {"in_use"}
OUTLOOK_RETRYABLE_STATES = {"failed"}
OUTLOOK_INVALID_STATES = {"login_required", "token_invalid"}
OUTLOOK_RETIRED_STATES = {"retired"}
OUTLOOK_CREDENTIAL_FATAL_STATES = OUTLOOK_INVALID_STATES | OUTLOOK_RETIRED_STATES
OUTLOOK_REFRESHED_CREDENTIAL_RESET_STATES = OUTLOOK_RETRYABLE_STATES | OUTLOOK_INVALID_STATES | OUTLOOK_RETIRED_STATES


def _outlook_token_state_file_lock_path():
    return OUTLOOK_TOKEN_USED_FILE.with_name(f"{OUTLOOK_TOKEN_USED_FILE.name}.lock")


def _outlook_state_lock():
    return file_lock(_outlook_token_state_file_lock_path())


@contextmanager
def _outlook_state_transaction():
    with _outlook_token_state_lock:
        with _outlook_state_lock():
            yield


def _normalize_submitted_tags(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    tags: list[str] = []
    seen: set[str] = set()
    for item in value:
        tag = str(item or "").strip().lower()
        if not tag or tag in seen or any(char not in OUTLOOK_ALIAS_TAG_ALPHABET for char in tag):
            continue
        seen.add(tag)
        tags.append(tag)
    return tags


def _normalize_family_lease(value: Any) -> dict[str, str] | None:
    if not isinstance(value, dict):
        return None
    address = str(value.get("address") or "").strip().lower()
    if not address:
        return None
    return {"address": address, "updated_at": str(value.get("updated_at") or "").strip()}


def _normalize_no_code_streak(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _outlook_state_record(value: Any) -> dict[str, Any]:
    """保留已提交标签、主号租约和连续未收码计数；旧记录缺省状态仍视为 used。"""
    if isinstance(value, dict):
        raw_state = value.get("state")
        has_alias_meta = any(key in value for key in ("submitted_tags", "family_lease", "no_code_streak"))
        if raw_state is None and not has_alias_meta:
            state_name = "used"
        else:
            state_name = str(raw_state or "").strip()
        record: dict[str, Any] = {
            "state": state_name,
            "reason": str(value.get("reason") or ""),
            "updated_at": str(value.get("updated_at") or ""),
        }
        tags = _normalize_submitted_tags(value.get("submitted_tags"))
        if tags:
            record["submitted_tags"] = tags
        lease = _normalize_family_lease(value.get("family_lease"))
        if lease:
            record["family_lease"] = lease
        streak = _normalize_no_code_streak(value.get("no_code_streak"))
        if streak:
            record["no_code_streak"] = streak
        return record
    return {"state": str(value or "used").strip() or "used", "reason": "", "updated_at": ""}


def _outlook_record_empty(record: dict[str, Any]) -> bool:
    return not (
        str(record.get("state") or "").strip()
        or record.get("submitted_tags")
        or record.get("family_lease")
        or record.get("no_code_streak")
    )


def _load_outlook_token_state() -> dict[str, dict[str, Any]]:
    """读取邮箱池状态文件，返回 {email_lower: record}。

    兼容旧格式：纯字符串列表（历史的“已用邮箱”）会被解释为 used。
    主号记录上的 submitted_tags、family_lease、no_code_streak 必须保留。
    """
    data = read_json_file(
        OUTLOOK_TOKEN_USED_FILE,
        name="outlook_token_used.json",
        default_factory=dict,
        expected_types=(dict, list),
    )
    state: dict[str, dict[str, Any]] = {}
    if isinstance(data, list):
        for item in data:
            key = str(item).strip().lower()
            if key:
                state[key] = {"state": "used", "reason": "", "updated_at": ""}
    elif isinstance(data, dict):
        for key, value in data.items():
            email = str(key).strip().lower()
            if email:
                state[email] = _outlook_state_record(value)
    return state


def _save_outlook_token_state(state: dict[str, dict[str, Any]]) -> None:
    OUTLOOK_TOKEN_USED_FILE.parent.mkdir(parents=True, exist_ok=True)
    ordered = {key: state[key] for key in sorted(state)}
    write_json_file(OUTLOOK_TOKEN_USED_FILE, ordered)


def _outlook_entry_available(entry: dict[str, Any] | None) -> bool:
    """该邮箱当前是否可领用：未记录、或 in_use 已陈旧、或非终态时可用。"""
    if not isinstance(entry, dict):
        return True
    current = str(entry.get("state") or "")
    if current in OUTLOOK_UNAVAILABLE_STATES:
        return False
    if current == "in_use":
        updated_at = str(entry.get("updated_at") or "")
        try:
            ts = datetime.fromisoformat(updated_at)
            age = (datetime.now(timezone.utc) - (ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc))).total_seconds()
            return age >= OUTLOOK_IN_USE_STALE_SECONDS
        except Exception:
            return True
    return True


def _outlook_credential_state(store: dict[str, dict[str, Any]], credential: dict[str, Any]) -> str:
    """返回地址自身状态；如果原登录邮箱 token 已失效，则别名也继承该致命状态。"""
    key = str(credential.get("email") or "").strip().lower()
    entry = store.get(key) if key else None
    state = str(entry.get("state") or "") if isinstance(entry, dict) else ""
    if state:
        return state
    login_email = str(credential.get("login_email") or credential.get("alias_of") or "").strip().lower()
    if login_email and login_email != key:
        parent = store.get(login_email)
        parent_state = str(parent.get("state") or "") if isinstance(parent, dict) else ""
        if parent_state in OUTLOOK_CREDENTIAL_FATAL_STATES:
            return parent_state
    return ""


def _outlook_credential_available(store: dict[str, dict[str, Any]], credential: dict[str, Any]) -> bool:
    key = str(credential.get("email") or "").strip().lower()
    entry = store.get(key) if key else None
    if not _outlook_entry_available(entry):
        return False
    state = _outlook_credential_state(store, credential)
    return state not in OUTLOOK_CREDENTIAL_FATAL_STATES


def _outlook_timestamp_stale(updated_at: str) -> bool:
    text = str(updated_at or "").strip()
    if not text:
        return True
    try:
        ts = datetime.fromisoformat(text)
    except Exception:
        return True
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - ts).total_seconds() >= OUTLOOK_IN_USE_STALE_SECONDS


def _family_lease_active(entry: dict[str, Any] | None) -> bool:
    if not isinstance(entry, dict):
        return False
    lease = _normalize_family_lease(entry.get("family_lease"))
    if not lease:
        return False
    return not _outlook_timestamp_stale(lease.get("updated_at") or "")


def outlook_alias_parent_email(email: str) -> str:
    text = str(email or "").strip().lower()
    local, sep, domain = text.partition("@")
    if not sep or not local or not domain:
        return text
    return f"{local.split('+', 1)[0]}@{domain}"


def outlook_alias_tag_from_address(address: str, parent: str = "") -> str:
    target = str(address or "").strip().lower()
    parent_email = outlook_alias_parent_email(parent or target)
    local, sep, domain = parent_email.partition("@")
    if not sep:
        return ""
    prefix = f"{local}+"
    suffix = f"@{domain}"
    if not target.startswith(prefix) or not target.endswith(suffix) or len(target) <= len(prefix) + len(suffix):
        return ""
    tag = target[len(prefix):-len(suffix)]
    if not tag or "+" in tag or any(char not in OUTLOOK_ALIAS_TAG_ALPHABET for char in tag):
        return ""
    return tag


def _credential_parent_email(credential: dict[str, Any]) -> str:
    email = str(credential.get("email") or "").strip().lower()
    login = str(credential.get("login_email") or credential.get("alias_of") or "").strip().lower()
    if login and login != email:
        return outlook_alias_parent_email(login)
    return outlook_alias_parent_email(email or login)


def _outlook_record(store: dict[str, dict[str, Any]], address: str) -> dict[str, Any]:
    current = store.get(str(address or "").strip().lower())
    if isinstance(current, dict):
        return _outlook_state_record(current)
    return {"state": "", "reason": "", "updated_at": ""}


def _store_outlook_record(store: dict[str, dict[str, Any]], address: str, record: dict[str, Any]) -> None:
    key = str(address or "").strip().lower()
    if not key:
        return
    cleaned = _outlook_state_record(record)
    if _outlook_record_empty(cleaned):
        store.pop(key, None)
        return
    store[key] = cleaned


def _clear_family_lease(store: dict[str, dict[str, Any]], parent: str, address: str) -> None:
    parent_key = outlook_alias_parent_email(parent)
    target = str(address or "").strip().lower()
    entry = store.get(parent_key)
    lease = _normalize_family_lease(entry.get("family_lease") if isinstance(entry, dict) else None)
    if not lease or lease["address"] != target:
        return
    record = _outlook_state_record(entry)
    record.pop("family_lease", None)
    record["updated_at"] = datetime.now(timezone.utc).isoformat()
    _store_outlook_record(store, parent_key, record)


def _outlook_sibling_alias_in_use(store: dict[str, dict[str, Any]], parent_email: str) -> bool:
    local, sep, domain = outlook_alias_parent_email(parent_email).partition("@")
    if not sep:
        return False
    prefix = f"{local}+"
    suffix = f"@{domain}"
    for key, value in store.items():
        if not str(key).startswith(prefix) or not str(key).endswith(suffix) or not isinstance(value, dict):
            continue
        if str(value.get("state") or "") == "in_use" and not _outlook_entry_available(value):
            return True
    return False


def _outlook_family_blocked(store: dict[str, dict[str, Any]], parent_email: str) -> bool:
    parent = outlook_alias_parent_email(parent_email)
    entry = store.get(parent)
    if isinstance(entry, dict):
        state = str(entry.get("state") or "")
        if state in OUTLOOK_CREDENTIAL_FATAL_STATES:
            return True
        if state == "in_use" and not _outlook_entry_available(entry):
            return True
        if _family_lease_active(entry):
            return True
    return _outlook_sibling_alias_in_use(store, parent)


def outlook_occupied_alias_tags(parent_email: str, store: dict[str, dict[str, Any]] | None = None) -> set[str]:
    parent = outlook_alias_parent_email(parent_email)
    if store is None:
        with _outlook_state_transaction():
            store = _load_outlook_token_state()
    tags: set[str] = set()
    entry = store.get(parent) if isinstance(store, dict) else None
    if isinstance(entry, dict):
        tags.update(_normalize_submitted_tags(entry.get("submitted_tags")))
        if _family_lease_active(entry):
            leased = outlook_alias_tag_from_address(str((entry.get("family_lease") or {}).get("address") or ""), parent)
            if leased:
                tags.add(leased)
    local, sep, domain = parent.partition("@")
    if not sep:
        return tags
    prefix = f"{local}+"
    suffix = f"@{domain}"
    for key, value in store.items():
        if not str(key).startswith(prefix) or not str(key).endswith(suffix):
            continue
        tag = outlook_alias_tag_from_address(str(key), parent)
        if not tag or not isinstance(value, dict):
            continue
        state = str(value.get("state") or "")
        if state == "in_use" and _outlook_entry_available(value):
            continue
        if state in OUTLOOK_OCCUPIED_TAG_STATES:
            tags.add(tag)
    return tags


def outlook_no_code_streak(parent_email: str) -> int:
    parent = outlook_alias_parent_email(parent_email)
    with _outlook_state_transaction():
        store = _load_outlook_token_state()
    entry = store.get(parent)
    if not isinstance(entry, dict):
        return 0
    return _normalize_no_code_streak(entry.get("no_code_streak"))


def _set_outlook_token_state(address: str, state: str, reason: str = "") -> None:
    target = str(address or "").strip().lower()
    if not target:
        return
    with _outlook_state_transaction():
        store = _load_outlook_token_state()
        record = _outlook_record(store, target)
        record["state"] = str(state)
        record["reason"] = str(reason or "")
        record["updated_at"] = datetime.now(timezone.utc).isoformat()
        _store_outlook_record(store, target, record)
        _save_outlook_token_state(store)


def _release_outlook_token_state(address: str) -> None:
    """把 in_use 释放回未使用，并清掉指向该地址的主号租约。已提交标签保留。"""
    target = str(address or "").strip().lower()
    if not target:
        return
    parent = outlook_alias_parent_email(target)
    with _outlook_state_transaction():
        store = _load_outlook_token_state()
        entry = store.get(target)
        changed = False
        if isinstance(entry, dict) and str(entry.get("state") or "") == "in_use":
            record = _outlook_state_record(entry)
            record["state"] = ""
            record["reason"] = ""
            record["updated_at"] = datetime.now(timezone.utc).isoformat()
            _store_outlook_record(store, target, record)
            changed = True
        before = store.get(parent)
        _clear_family_lease(store, parent, target)
        if store.get(parent) != before:
            changed = True
        if changed:
            _save_outlook_token_state(store)


def clear_outlook_token_states(addresses: list[str] | set[str], states: set[str] | None = None) -> int:
    """清除指定邮箱的状态标记。

    states 为空时清除任意状态；否则只清除指定状态。已提交标签不删除。
    不应清除 used，避免已经成功消费的邮箱被误用。
    """
    targets = {str(item or "").strip().lower() for item in addresses}
    targets.discard("")
    if not targets:
        return 0
    with _outlook_state_transaction():
        store = _load_outlook_token_state()
        cleared = 0
        now = datetime.now(timezone.utc).isoformat()
        for key in targets:
            entry = store.get(key)
            if not isinstance(entry, dict):
                continue
            current = str(entry.get("state") or "")
            if states is not None and current not in states:
                continue
            record = _outlook_state_record(entry)
            if current == "retired":
                record.pop("no_code_streak", None)
            record.pop("family_lease", None)
            record["state"] = ""
            record["reason"] = ""
            record["updated_at"] = now
            _store_outlook_record(store, key, record)
            cleared += 1
        if cleared:
            _save_outlook_token_state(store)
        return cleared


def reset_outlook_token_pool_state(scope: str = "all") -> int:
    """重置邮箱池状态文件。

    scope=all 清除占用、失败、已用和停用，但保留已提交标签；
    scope=retryable/failed 仅释放 in_use 与 failed，并清掉主号租约；
    scope=invalid 释放 login_required、token_invalid 和 retired。
    已提交标签在任何范围内都不交还。
    """
    normalized = str(scope or "all").strip().lower()
    allowed_scopes = {
        "failed",
        "retryable",
        "invalid",
        "reauth",
        "busy",
        "in_use",
        "all",
    }
    if normalized not in allowed_scopes:
        raise ValueError(f"unsupported Outlook token reset scope: {normalized or '<empty>'}")
    with _outlook_state_transaction():
        store = _load_outlook_token_state()
        if not store:
            return 0
        now = datetime.now(timezone.utc).isoformat()
        if normalized == "all":
            preserved: dict[str, dict[str, Any]] = {}
            changed = 0
            for key, value in store.items():
                tags = _normalize_submitted_tags(value.get("submitted_tags") if isinstance(value, dict) else None)
                had_other = False
                if isinstance(value, dict):
                    had_other = bool(value.get("state") or value.get("family_lease") or value.get("no_code_streak") or value.get("reason"))
                if tags:
                    preserved[key] = {"state": "", "reason": "", "updated_at": "", "submitted_tags": tags}
                    if had_other:
                        changed += 1
                else:
                    changed += 1
            _save_outlook_token_state(preserved)
            return changed
        if normalized in {"failed", "retryable"}:
            target_states = OUTLOOK_RETRYABLE_STATES | OUTLOOK_BUSY_STATES
            clear_lease = True
        elif normalized in {"invalid", "reauth"}:
            target_states = OUTLOOK_INVALID_STATES | OUTLOOK_RETIRED_STATES
            clear_lease = False
        else:
            target_states = OUTLOOK_BUSY_STATES
            clear_lease = True
        changed = 0
        for key, value in list(store.items()):
            if not isinstance(value, dict):
                continue
            record = _outlook_state_record(value)
            state = str(record.get("state") or "")
            touched = False
            if state in target_states:
                if state == "retired":
                    record.pop("no_code_streak", None)
                record["state"] = ""
                record["reason"] = ""
                touched = True
            if record.get("family_lease") and (clear_lease or state in target_states):
                record.pop("family_lease", None)
                touched = True
            if touched:
                record["updated_at"] = now
                _store_outlook_record(store, key, record)
                changed += 1
        _save_outlook_token_state(store)
        return changed


def _outlook_credential_has_history(store: dict[str, dict[str, Any]], credential: dict[str, Any]) -> bool:
    parent = _credential_parent_email(credential)
    entry = store.get(parent)
    if isinstance(entry, dict):
        if _normalize_submitted_tags(entry.get("submitted_tags")):
            return True
        if str(entry.get("state") or "") in OUTLOOK_RECORDED_STATES or _family_lease_active(entry):
            return True
    local, sep, domain = parent.partition("@")
    if not sep:
        return False
    prefix = f"{local}+"
    suffix = f"@{domain}"
    for key, value in store.items():
        if not str(key).startswith(prefix) or not str(key).endswith(suffix):
            continue
        state = str(value.get("state") or "") if isinstance(value, dict) else ""
        if state in OUTLOOK_RECORDED_STATES:
            return True
    return False


def prune_outlook_unused_credentials(credentials: list[dict[str, str]], entry: dict | None = None) -> tuple[list[dict[str, str]], int]:
    """保留已有状态、已提交标签或停用记录的主号，不预展开别名。"""
    del entry
    with _outlook_state_transaction():
        store = _load_outlook_token_state()
    kept: list[dict[str, str]] = []
    removed = 0
    for credential in credentials:
        if _outlook_credential_has_history(store, credential):
            kept.append(credential)
        else:
            removed += 1
    return kept, removed


def _empty_outlook_pool_counts() -> dict[str, int]:
    return {
        "unused": 0,
        "in_use": 0,
        "used": 0,
        "login_required": 0,
        "token_invalid": 0,
        "failed": 0,
        "retired": 0,
        "submitted_alias": 0,
    }


def _count_outlook_family(counts: dict[str, int], store: dict[str, dict[str, Any]], credential: dict[str, Any]) -> None:
    parent = _credential_parent_email(credential)
    entry = store.get(parent) if isinstance(store.get(parent), dict) else {}
    counts["submitted_alias"] += len(_normalize_submitted_tags(entry.get("submitted_tags")))
    if not _outlook_family_blocked(store, parent):
        counts["unused"] += 1
        return
    state = str(entry.get("state") or "")
    if state in {"login_required", "token_invalid", "retired"}:
        counts[state] += 1
        return
    counts["in_use"] += 1


def _count_outlook_family_usage(counts: dict[str, int], store: dict[str, dict[str, Any]], parent: str) -> None:
    parent_key = outlook_alias_parent_email(parent)
    local, sep, domain = parent_key.partition("@")
    if not sep:
        return
    prefix = f"{local}+"
    suffix = f"@{domain}"
    for key, value in store.items():
        if not isinstance(value, dict):
            continue
        if key != parent_key and not (str(key).startswith(prefix) and str(key).endswith(suffix)):
            continue
        state = str(value.get("state") or "")
        if state == "used":
            counts["used"] += 1
        elif state == "failed":
            counts["failed"] += 1


def outlook_token_pool_stats(pool: list[dict[str, str]] | None = None, entry: dict | None = None) -> dict[str, int]:
    """统计邮箱池各状态数量。启用别名时按主号统计，不把未生成的标签算进池子。"""
    alias_enabled = _normalize_bool(entry.get("alias_enabled"), False) if isinstance(entry, dict) else False
    with _outlook_state_transaction():
        store = _load_outlook_token_state()
        counts = _empty_outlook_pool_counts()
        if pool:
            seen_parents: set[str] = set()
            for credential in pool:
                parent = _credential_parent_email(credential)
                if alias_enabled and outlook_alias_supported(parent):
                    if parent in seen_parents:
                        continue
                    seen_parents.add(parent)
                    _count_outlook_family(counts, store, credential)
                    _count_outlook_family_usage(counts, store, parent)
                    continue
                state = _outlook_credential_state(store, credential)
                if state == "retired":
                    counts["retired"] += 1
                elif state in counts:
                    counts[state] += 1
                else:
                    counts["unused"] += 1
        else:
            for value in store.values():
                state = str(value.get("state") or "") if isinstance(value, dict) else ""
                if state == "retired":
                    counts["retired"] += 1
                elif state in counts:
                    counts[state] += 1
                counts["submitted_alias"] += len(_normalize_submitted_tags(value.get("submitted_tags") if isinstance(value, dict) else None))
        counts["available"] = counts["unused"]
        counts["busy"] = counts["in_use"]
        counts["retryable"] = counts["failed"]
        counts["invalid"] = counts["login_required"] + counts["token_invalid"]
        counts["abnormal"] = counts["retryable"] + counts["invalid"] + counts["retired"]
        return counts


ResultT = TypeVar("ResultT")
domain_lock = Lock()
provider_lock = Lock()
domain_index = 0
provider_index = 0
REMAIL_DEFAULT_API_BASE = "https://remail.aishop6.com"
REMAIL_DEFAULT_PROJECT_ID = 2
REMAIL_DEFAULT_PRODUCT_ID = 5
REMAIL_DEAD_MAILBOXES_FILE = DATA_DIR / "remail_dead_mailboxes.json"
REMAIL_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
REMAIL_ORDER_STATUS_CHECK_INTERVAL = 5.0
MAIL_WAIT_DEADLINE_KEY = "_mail_wait_deadline_at"
REMAIL_PROVIDER_SNAPSHOT_KEY = "_remail_provider_snapshot"
REMAIL_TERMINAL_ORDER_STATUS = {"closed", "refunded", "failed", "completed"}
REMAIL_TERMINAL_FAILURE_CODES = {
    "service_token_failed",
    "activation_failed",
    "account_deactivated",
}
_remail_dead_lock = Lock()


class ReMailHttpError(RuntimeError):
    def __init__(self, status_code: int, method: str, path: str, detail: str = ""):
        self.status_code = int(status_code)
        self.method = method.upper()
        self.path = path
        self.detail = str(detail or "")
        message = f"Remail request failed: {self.method} {self.path}, HTTP {self.status_code}"
        if self.detail:
            message = f"{message}, body={self.detail}"
        super().__init__(message)


class ReMailServiceTokenInvalidError(RuntimeError):
    pass


def _remail_text(text: object, *sensitive_values: object) -> str:
    return redact_register_log_text(
        sanitize_diagnostic_text(text, sensitive_values=sensitive_values)
    )


def _sanitize_remail_dead_reason(reason: object, _mailbox: dict[str, Any] | None = None) -> str:
    return _remail_text(reason).strip()


def _load_remail_dead_mailboxes() -> list[dict[str, Any]]:
    data = read_json_file(
        REMAIL_DEAD_MAILBOXES_FILE,
        name="remail_dead_mailboxes.json",
        default_factory=list,
        expected_types=(list, dict),
    )
    if isinstance(data, dict):
        rows = data.get("items")
        return [item for item in rows if isinstance(item, dict)] if isinstance(rows, list) else []
    return [item for item in data if isinstance(item, dict)] if isinstance(data, list) else []


def _save_remail_dead_mailboxes(items: list[dict[str, Any]]) -> None:
    write_json_file(REMAIL_DEAD_MAILBOXES_FILE, items)


def _record_remail_dead_mailbox(mailbox: dict[str, Any], reason: str) -> None:
    email = str(mailbox.get("address") or mailbox.get("email") or "").strip()
    if not email:
        return
    order_no = str(mailbox.get("order_no") or mailbox.get("orderNo") or "").strip()
    purchase_id = str(mailbox.get("purchase_id") or mailbox.get("id") or "").strip()
    item = {
        "email": email,
        "order_no": order_no,
        "purchase_id": purchase_id,
        "reason": _sanitize_remail_dead_reason(reason, mailbox),
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }
    with _remail_dead_lock:
        rows = _load_remail_dead_mailboxes()
        key = (email.lower(), order_no, purchase_id)
        rows = [
            row
            for row in rows
            if (
                str(row.get("email") or "").strip().lower(),
                str(row.get("order_no") or "").strip(),
                str(row.get("purchase_id") or "").strip(),
            ) != key
        ]
        rows.append(item)
        _save_remail_dead_mailboxes(rows)


def _remail_dead_reason(error: Exception | str | None) -> str:
    text = str(error or "").strip()
    lowered = text.lower()
    status_match = re.search(r"remail_terminal_status=([a-z0-9_\-]+)", lowered)
    if status_match:
        status = status_match.group(1)
        if status in REMAIL_TERMINAL_ORDER_STATUS:
            return f"order status {status}"
    failure_match = re.search(r"remail_terminal_failure_code=([a-z0-9_\-]+)", lowered)
    if failure_match:
        failure_code = failure_match.group(1)
        if failure_code in REMAIL_TERMINAL_FAILURE_CODES:
            return f"failure code {failure_code}"
    return ""


def _is_remail_service_token_error(value: object) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    compact = re.sub(r"[\s\-]+", "_", text)
    if "credential_invalid" in compact:
        return True
    markers = (
        "credential is invalid",
        "credential invalid",
        "credential expired",
        "invalid or expired",
        "service token expired",
        "service token invalid",
        "service token is invalid",
        "token expired",
        "token invalid",
        "token is invalid",
        "invalid token",
        "expired token",
    )
    return any(marker in text for marker in markers)


def _remail_required_positive_int(value: Any, default: int, label: str) -> int:
    text = str(value if value is not None else "").strip()
    if not text:
        return int(default)
    if isinstance(value, bool):
        raise RuntimeError(f"Remail {label} must be a positive integer")
    try:
        parsed = float(text)
    except (TypeError, ValueError):
        raise RuntimeError(f"Remail {label} must be a positive integer")
    if not parsed.is_integer() or parsed < 1:
        raise RuntimeError(f"Remail {label} must be a positive integer")
    return int(parsed)


def _mailbox_wait_deadline(mailbox: dict[str, Any]) -> float | None:
    try:
        deadline = float(mailbox.get(MAIL_WAIT_DEADLINE_KEY) or 0)
    except (TypeError, ValueError):
        return None
    return deadline if deadline > 0 else None


def _remail_receive_until_deadline(mailbox: dict[str, Any]) -> float | None:
    raw = str(mailbox.get("receive_until") or mailbox.get("receiveUntil") or "").strip()
    if not raw:
        return None
    try:
        receive_until = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if receive_until.tzinfo is None:
        receive_until = receive_until.replace(tzinfo=timezone.utc)
    remaining = (receive_until - datetime.now(timezone.utc)).total_seconds()
    return time.monotonic() + remaining


def _chrome146_user_agent(value: object = "") -> str:
    return CHROME146_USER_AGENT


def _config(mail_config: dict) -> dict:
    try:
        wait_timeout = float(mail_config.get("wait_timeout") or 30)
    except (TypeError, ValueError):
        wait_timeout = 30.0
    wait_timeout = max(1.0, min(MAIL_WAIT_TIMEOUT_MAX, wait_timeout))
    try:
        wait_interval = float(mail_config.get("wait_interval") or 2)
    except (TypeError, ValueError):
        wait_interval = 2.0
    return {
        "request_timeout": float(mail_config.get("request_timeout") or 30),
        "wait_timeout": wait_timeout,
        "wait_interval": max(0.2, min(wait_timeout, wait_interval)),
        "user_agent": _chrome146_user_agent(mail_config.get("user_agent")),
        "proxy": str(mail_config.get("proxy") or "").strip(),
    }


def _random_mailbox_name() -> str:
    return f"{''.join(random.choices(string.ascii_lowercase, k=5))}{''.join(random.choices(string.digits, k=random.randint(1, 3)))}{''.join(random.choices(string.ascii_lowercase, k=random.randint(1, 3)))}"


def _random_subdomain_label() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(4, 10)))


def _next_domain(domains: list[str]) -> str:
    global domain_index
    domains = [str(item).strip() for item in domains if str(item).strip()]
    if not domains:
        raise RuntimeError("mail.domain 不能为空")
    if len(domains) == 1:
        return domains[0]
    with domain_lock:
        value = domains[domain_index % len(domains)]
        domain_index = (domain_index + 1) % len(domains)
        return value


def _normalize_string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value or "").strip()
    return [text] if text else []


def _mail_session_proxy(*sources: Any) -> str:
    for source in sources:
        if not isinstance(source, dict):
            continue
        for key in ("proxy", "_icloud_proxy"):
            value = str(source.get(key) or "").strip()
            if value:
                return value
    return "direct"


def _mail_imap_proxy(*sources: Any) -> str:
    for source in sources:
        if not isinstance(source, dict):
            continue
        for key in ("_register_proxy", "register_proxy"):
            value = str(source.get(key) or "").strip()
            if value:
                return value
    return "direct"


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise RuntimeError("IMAP 代理连接已关闭。")
        chunks.extend(chunk)
    return bytes(chunks)


def _open_proxied_tcp_socket(host: str, port: int, timeout: float, proxy: str) -> socket.socket:
    target_host = str(host or "").strip()
    target_port = int(port)
    proxy_url = str(proxy or "").strip()
    if not proxy_url or proxy_url == "direct":
        return socket.create_connection((target_host, target_port), timeout=timeout)
    parsed = urlsplit(proxy_url if "://" in proxy_url else f"http://{proxy_url}")
    scheme = (parsed.scheme or "http").lower()
    proxy_host = unquote(parsed.hostname or "")
    proxy_port = int(parsed.port or (443 if scheme == "https" else 80))
    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    if not proxy_host:
        raise RuntimeError("IMAP 代理地址无效。")
    host_bytes = b""
    if scheme.startswith("socks"):
        user_bytes = username.encode("utf-8")
        pass_bytes = password.encode("utf-8")
        if len(user_bytes) > 255 or len(pass_bytes) > 255:
            raise RuntimeError("IMAP SOCKS5 用户名或密码过长。")
        try:
            host_bytes = target_host.encode("idna")
        except UnicodeError as exc:
            raise RuntimeError("IMAP SOCKS5 主机名过长。") from exc
        if len(host_bytes) > 255:
            raise RuntimeError("IMAP SOCKS5 主机名过长。")
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        if scheme.startswith("socks"):
            if username:
                sock.sendall(b"\x05\x02\x00\x02")
            else:
                sock.sendall(b"\x05\x01\x00")
            greeting = _recv_exact(sock, 2)
            if greeting[:1] != b"\x05":
                raise RuntimeError("IMAP SOCKS5 握手失败。")
            if greeting[1:2] == b"\x02":
                user_bytes = username.encode("utf-8")
                pass_bytes = password.encode("utf-8")
                sock.sendall(
                    bytes([1, len(user_bytes)])
                    + user_bytes
                    + bytes([len(pass_bytes)])
                    + pass_bytes
                )
                auth = _recv_exact(sock, 2)
                if auth[1:2] != b"\x00":
                    raise RuntimeError("IMAP SOCKS5 认证失败。")
            elif greeting[1:2] != b"\x00":
                raise RuntimeError("IMAP SOCKS5 握手被拒绝。")
            request = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + target_port.to_bytes(2, "big")
            sock.sendall(request)
            reply = _recv_exact(sock, 4)
            if reply[:1] != b"\x05" or reply[1:2] != b"\x00":
                raise RuntimeError("IMAP SOCKS5 连接失败。")
            atyp = reply[3]
            if atyp == 1:
                _recv_exact(sock, 6)
            elif atyp == 3:
                domain_len = _recv_exact(sock, 1)[0]
                _recv_exact(sock, domain_len + 2)
            elif atyp == 4:
                _recv_exact(sock, 18)
            else:
                raise RuntimeError("IMAP SOCKS5 地址类型无效。")
            return sock
        auth_header = ""
        if username or password:
            token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            auth_header = f"Proxy-Authorization: Basic {token}\r\n"
        request = (
            f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
            f"Host: {target_host}:{target_port}\r\n"
            f"{auth_header}"
            "\r\n"
        )
        sock.sendall(request.encode("ascii"))
        buffer = bytearray()
        while True:
            chunk = sock.recv(1)
            if not chunk:
                raise RuntimeError("IMAP HTTP 代理连接已关闭。")
            buffer.extend(chunk)
            if buffer.endswith(b"\r\n\r\n"):
                break
            if len(buffer) > 65536:
                raise RuntimeError("IMAP HTTP 代理响应过长。")
        header = bytes(buffer)
        status_line = header.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = status_line.split(" ", 2)
        if len(parts) < 2 or not parts[1].startswith("2"):
            raise RuntimeError(f"IMAP HTTP 代理 CONNECT 失败：{status_line}")
        return sock
    except Exception:
        sock.close()
        raise


class _ProxiedIMAP4SSL(imaplib.IMAP4_SSL):
    def __init__(self, host: str = "", port=imaplib.IMAP4_SSL_PORT, *, timeout=None, proxy: str = ""):
        self._tcp_proxy = str(proxy or "").strip()
        super().__init__(host=host, port=port, timeout=timeout)

    def _create_socket(self, timeout):
        if not self._tcp_proxy or self._tcp_proxy == "direct":
            return super()._create_socket(timeout)
        sock = _open_proxied_tcp_socket(self.host, self.port, timeout, self._tcp_proxy)
        return self.ssl_context.wrap_socket(sock, server_hostname=self.host)


def _create_session(conf: dict):
    kwargs = proxy_settings.build_session_kwargs(
        proxy=_mail_session_proxy(conf),
        upstream=True,
        impersonate=CHROME146_IMPERSONATE,
        verify=not proxy_settings.should_skip_ssl_verify(),
    )
    session = requests.Session(**kwargs)
    session.headers.update(chrome146_headers())
    return session


def _parse_received_at(value: Any) -> datetime | None:
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except Exception:
            return None
    text = str(value or "").strip()
    if not text:
        return None
    try:
        date = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
        return date if date.tzinfo else date.replace(tzinfo=timezone.utc)
    except Exception:
        pass
    try:
        date = parsedate_to_datetime(text)
        return date if date.tzinfo else date.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _extract_content(data: dict[str, Any]) -> tuple[str, str]:
    text_content = str(data.get("text_content") or data.get("text") or data.get("body") or data.get("content") or "")
    html_content = str(data.get("html_content") or data.get("html") or data.get("html_body") or data.get("body_html") or "")
    if text_content or html_content:
        return text_content, html_content
    raw = data.get("raw")
    if not isinstance(raw, str) or not raw.strip():
        return "", ""
    try:
        parsed = message_from_string(raw, policy=policy.default)
    except Exception:
        return raw, ""
    plain: list[str] = []
    html: list[str] = []
    for part in parsed.walk() if parsed.is_multipart() else [parsed]:
        if part.get_content_maintype() == "multipart":
            continue
        try:
            payload = part.get_content()
        except Exception:
            payload = ""
        if not payload:
            continue
        if part.get_content_type() == "text/html":
            html.append(str(payload))
        else:
            plain.append(str(payload))
    return "\n".join(plain).strip(), "\n".join(html).strip()


def _extract_text_candidates(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        out: list[str] = []
        for key in ("address", "email", "name", "value"):
            if value.get(key):
                out.extend(_extract_text_candidates(value.get(key)))
        return out
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(_extract_text_candidates(item))
        return out
    return []


def _mail_recipient_matches(mailbox: dict[str, Any], candidates: Any) -> bool:
    target = str(
        (mailbox or {}).get("email")
        or (mailbox or {}).get("address")
        or ""
    ).strip().lower()
    if not target:
        return False
    values = [item for item in _extract_text_candidates(candidates) if str(item or "").strip()]
    if not values:
        return False
    for _display_name, address in getaddresses(values):
        normalized = str(address or "").strip().lower()
        if normalized and normalized == target:
            return True
    return False


def _message_matches_email(data: dict[str, Any], email: str) -> bool:
    target = str(email or "").strip()
    candidates: list[str] = []
    for key in (
        "to",
        "toEmail",
        "mailTo",
        "receiver",
        "receivers",
        "address",
        "email",
        "envelope_to",
        "delivered_to",
        "x_forwarded_to",
        "x_original_to",
        "cc",
    ):
        if key in data:
            candidates.extend(_extract_text_candidates(data.get(key)))
    return _mail_recipient_matches({"email": target}, candidates)


def _extract_code(message: dict[str, Any]) -> str | None:
    verification_code = str(
        message.get("verificationCode")
        or message.get("verification_code")
        or message.get("code")
        or ""
    ).strip()
    if verification_code:
        match = re.search(r"\b(\d{4,10})\b", verification_code)
        if match:
            return match.group(1)
    content = f"{message.get('subject', '')}\n{message.get('text_content', '')}\n{message.get('html_content', '')}\n{message.get('body', '')}".strip()
    if not content:
        return None
    match = re.search(r"background-color:\s*#F3F3F3[^>]*>[\s\S]*?(\d{6})[\s\S]*?</p>", content, re.I)
    if match:
        return match.group(1)
    match = re.search(r"(?:Verification code|code is|代码为|验证码)[:\s]*(\d{6})", content, re.I)
    if match:
        return match.group(1)
    lowered = content.casefold()
    if not any(
        marker in lowered
        for marker in (
            "verification code",
            "code is",
            "验证码",
            "代码为",
            "otp",
            "one-time password",
            "mail code",
        )
    ):
        return None
    for code in re.findall(r">\s*(\d{6})\s*<|(?<![#&])\b(\d{6})\b", content):
        value = code[0] or code[1]
        if value:
            return value
    return None


def _message_tracking_ref(message: dict[str, Any]) -> str:
    provider = str(message.get("provider") or "").strip()
    mailbox = str(message.get("mailbox") or "").strip()
    message_id = str(message.get("message_id") or "").strip()
    if message_id:
        return f"id:{provider}:{mailbox}:{message_id}"
    received_at = message.get("received_at")
    received_value = received_at.isoformat() if isinstance(received_at, datetime) else str(received_at or "")
    content = "\n".join(str(message.get(key) or "") for key in ("subject", "sender", "text_content", "html_content"))
    digest = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
    return f"content:{provider}:{mailbox}:{received_value}:{digest}"


def _mailbox_code_boundary(mailbox: dict[str, Any]) -> datetime | None:
    boundaries: list[datetime] = []
    claimed_at = mailbox.get("_code_not_before")
    if isinstance(claimed_at, datetime):
        boundaries.append(claimed_at)
    received_after = mailbox.get("_received_after")
    if received_after:
        try:
            parsed = datetime.fromisoformat(str(received_after))
        except (TypeError, ValueError):
            parsed = None
        if parsed is not None:
            boundaries.append(parsed)
    if not boundaries:
        return None
    boundary = max(
        item if item.tzinfo else item.replace(tzinfo=timezone.utc)
        for item in boundaries
    )
    return boundary.astimezone(timezone.utc)


def _effective_code_boundary(mailbox: dict[str, Any] | None) -> datetime | None:
    """Outlook 收信边界放宽固定时钟误差；其他供应商仍用原来的严格边界。"""
    boundary = _mailbox_code_boundary(mailbox or {})
    if not isinstance(boundary, datetime):
        return None
    if str((mailbox or {}).get("provider") or "") != "outlook_token":
        return boundary
    return boundary - timedelta(seconds=OUTLOOK_CODE_BOUNDARY_SKEW_SECONDS)


def _message_before_code_boundary(mailbox: dict[str, Any], message: dict[str, Any]) -> bool:
    boundary = _effective_code_boundary(mailbox)
    received_at = message.get("received_at")
    if not isinstance(boundary, datetime) or not isinstance(received_at, datetime):
        return False
    current = received_at if received_at.tzinfo else received_at.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc) < boundary


def _as_utc(value: datetime | None) -> datetime | None:
    if not isinstance(value, datetime):
        return None
    current = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc)


def _oldest_graph_received_at(items: list[dict[str, Any]]) -> datetime | None:
    oldest: datetime | None = None
    for item in items:
        current = _as_utc(_parse_received_at(item.get("receivedDateTime")))
        if current is not None and (oldest is None or current < oldest):
            oldest = current
    return oldest


def _oldest_message_received_at(messages: list[dict[str, Any]]) -> datetime | None:
    oldest: datetime | None = None
    for item in messages:
        current = _as_utc(item.get("received_at"))
        if current is not None and (oldest is None or current < oldest):
            oldest = current
    return oldest


def _message_before_received_after(mailbox: dict[str, Any], message: dict[str, Any]) -> bool:
    received_after = mailbox.get("_received_after")
    if not received_after:
        return False
    boundary = _mailbox_code_boundary(mailbox)
    received_at = message.get("received_at")
    if not isinstance(boundary, datetime) or not isinstance(received_at, datetime):
        return False
    current = received_at if received_at.tzinfo else received_at.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc) < boundary


class _MailWaitDeadlineExceeded(RuntimeError):
    pass


class BaseMailProvider:
    name = "unknown"

    def __init__(self, conf: dict, provider_ref: str = ""):
        self.conf = conf
        self.provider_ref = provider_ref
        self._wait_deadline: float | None = None

    def _start_wait_window(self, deadline_at: float | None = None) -> float | None:
        previous_deadline = self._wait_deadline
        deadline = deadline_at if deadline_at is not None else time.monotonic() + max(0.001, float(self.conf["wait_timeout"]))
        self._wait_deadline = min(previous_deadline, deadline) if previous_deadline is not None else deadline
        return previous_deadline

    def _restore_wait_window(self, previous_deadline: float | None) -> None:
        self._wait_deadline = previous_deadline

    def _remaining_wait_seconds(self) -> float | None:
        if self._wait_deadline is None:
            return None
        return self._wait_deadline - time.monotonic()

    def _mailbox_wait_deadline(self, mailbox: dict[str, Any]) -> float | None:
        return _mailbox_wait_deadline(mailbox)

    def _request_timeout(self) -> float:
        configured_timeout = max(0.001, float(self.conf["request_timeout"]))
        remaining = self._remaining_wait_seconds()
        if remaining is None:
            return configured_timeout
        if remaining <= 0:
            raise _MailWaitDeadlineExceeded("mail code wait deadline exceeded")
        return min(configured_timeout, remaining)

    def _sleep_with_deadline(self, delay: float) -> bool:
        wait_seconds = max(0.0, float(delay))
        remaining = self._remaining_wait_seconds()
        if remaining is not None:
            if remaining <= 0:
                return False
            wait_seconds = min(wait_seconds, remaining)
        if wait_seconds > 0:
            time.sleep(wait_seconds)
        remaining_after = self._remaining_wait_seconds()
        return remaining_after is None or remaining_after > 0

    def wait_for(self, mailbox: dict[str, Any], on_message: Callable[[dict[str, Any]], ResultT | None]) -> ResultT | None:
        previous_deadline = self._start_wait_window(self._mailbox_wait_deadline(mailbox))
        try:
            while True:
                remaining = self._remaining_wait_seconds()
                if remaining is not None and remaining <= 0:
                    return None
                try:
                    message = self.fetch_latest_message(mailbox)
                except _MailWaitDeadlineExceeded:
                    return None
                if message:
                    result = on_message(message)
                    if result is not None:
                        return result
                if not self._sleep_with_deadline(max(0.2, self.conf["wait_interval"])):
                    return None
        finally:
            self._restore_wait_window(previous_deadline)

    def wait_for_code(self, mailbox: dict[str, Any]) -> str | None:
        seen_value = mailbox.setdefault("_seen_code_message_refs", [])
        if not isinstance(seen_value, list):
            seen_value = []
            mailbox["_seen_code_message_refs"] = seen_value
        seen_refs = {str(item) for item in seen_value}

        def extract_unseen_code(message: dict[str, Any]) -> str | None:
            if _message_before_code_boundary(mailbox, message):
                return None
            ref = _message_tracking_ref(message)
            if ref in seen_refs:
                return None
            code = _extract_code(message)
            if code:
                seen_value.append(ref)
                seen_refs.add(ref)
            return code

        return self.wait_for(mailbox, extract_unseen_code)

    def close(self) -> None:
        pass




class YydsMailProvider(BaseMailProvider):
    name = "yyds_mail"

    def __init__(self, entry: dict, conf: dict):
        super().__init__(conf, str(entry.get("provider_ref") or ""))
        self.api_base = str(entry.get("api_base") or "https://maliapi.215.im/v1").rstrip("/")
        self.api_key = str(entry["api_key"]).strip()
        self.domain = [str(item).strip() for item in (entry.get("domain") or []) if str(item).strip()]
        self.subdomain = str(entry.get("subdomain") or "").strip()
        self.wildcard = bool(entry.get("wildcard"))
        self.session = _create_session(conf)
        self.session.headers.update(chrome146_headers({
            "User-Agent": conf["user_agent"],
            "Accept": "application/json",
            "Content-Type": "application/json",
        }, include_defaults=False))

    def _request(self, method: str, path: str, token: str = "", params: dict | None = None, payload: dict | None = None, expected: tuple[int, ...] = (200, 201, 204)):
        headers = {"Authorization": f"Bearer {token}"} if token else {"X-API-Key": self.api_key}
        url = f"{self.api_base}{path}"
        with http_target_session_request(self.session, url) as request_options:
            resp = self.session.request(
                method.upper(),
                url,
                headers=headers,
                params=params,
                json=payload,
                timeout=self._request_timeout(),
                verify=not proxy_settings.should_skip_ssl_verify(),
                **request_options,
            )
        if resp.status_code not in expected:
            raise RuntimeError(f"YYDSMail 请求失败: {method} {path}, HTTP {resp.status_code}, body={resp.text}")
        if resp.status_code == 204:
            return {}
        data = resp.json()
        if isinstance(data, dict) and data.get("success") is False:
            raise RuntimeError(f"YYDSMail 请求失败: {data.get('errorCode') or data.get('error')}")
        return data.get("data") if isinstance(data, dict) and isinstance(data.get("data"), (dict, list)) else data

    @staticmethod
    def _items(data):
        return data if isinstance(data, list) else data.get("items") or data.get("messages") or data.get("data") or []

    def create_mailbox(self, username: str | None = None) -> dict[str, Any]:
        payload = {"localPart": username or _random_mailbox_name()}
        if self.domain:
            payload["domain"] = _next_domain(self.domain)
        if self.subdomain:
            payload["subdomain"] = self.subdomain
        data = self._request("POST", "/accounts/wildcard" if self.wildcard else "/accounts", payload=payload)
        address = str(data.get("address") or data.get("email") or "").strip()
        token = str(data.get("token") or data.get("temp_token") or data.get("tempToken") or data.get("access_token") or "").strip()
        if not address or not token:
            raise RuntimeError("YYDSMail 缺少 address 或 token")
        return {"provider": self.name, "provider_ref": self.provider_ref, "address": address, "token": token, "account_id": str(data.get("id") or "")}

    def fetch_latest_message(self, mailbox: dict[str, Any]) -> dict[str, Any] | None:
        data = self._request("GET", "/messages", token=str(mailbox.get("token") or ""), params={"address": mailbox["address"]})
        messages = [item for item in self._items(data) if isinstance(item, dict)]
        if not messages:
            return None
        item = max(messages, key=lambda value: ((_parse_received_at(value.get("createdAt") or value.get("created_at") or value.get("receivedAt") or value.get("date") or value.get("timestamp")) or datetime.fromtimestamp(0, tz=timezone.utc)).timestamp(), str(value.get("id") or "")))
        message_id = str(item.get("id") or item.get("message_id") or "").strip()
        if message_id:
            item = self._request("GET", f"/messages/{message_id}", token=str(mailbox.get("token") or ""), params={"address": mailbox["address"]})
        text_content, html_content = _extract_content(item)
        sender = item.get("from") or item.get("sender") or ""
        if isinstance(sender, dict):
            sender = sender.get("address") or sender.get("email") or sender.get("name") or ""
        return {"provider": self.name, "mailbox": mailbox["address"], "message_id": message_id, "subject": str(item.get("subject") or ""), "sender": str(sender), "text_content": text_content, "html_content": html_content, "received_at": _parse_received_at(item.get("createdAt") or item.get("created_at") or item.get("receivedAt") or item.get("date") or item.get("timestamp")), "raw": item}

    def close(self) -> None:
        self.session.close()


ICLOUD_API_DEFAULT_PROJECT = "openai"
ICLOUD_API_DEFAULT_PURPOSE = "register"
ICLOUD_API_DEFAULT_KEYWORD = "OpenAI"
MAIL_WAIT_TIMEOUT_MAX = 300.0
ICLOUD_API_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
ICLOUD_API_RETRYABLE_FINALIZE_STATUS = {429, 500, 502, 503, 504}


def _icloud_api_root(api_base: str) -> str:
    value = str(api_base or "").strip().rstrip("/")
    if value.endswith("/api/v1"):
        value = value[: -len("/api/v1")]
    return value.rstrip("/")


def _icloud_api_url(api_base: str, path: str) -> str:
    root = _icloud_api_root(api_base)
    suffix = str(path or "").strip().lstrip("/")
    return f"{root}/api/v1/{suffix}" if root else f"/api/v1/{suffix}"


def _icloud_validate_response_url(value: object, api_base: str, *, field_name: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    base_url = _icloud_api_url(api_base, "/")
    parsed_base = urlsplit(base_url)
    parsed = urlsplit(raw)
    if parsed.username or parsed.password:
        raise RuntimeError(f"iCloud Privacy Mail {field_name} 不能包含用户名或密码")
    if parsed.scheme or parsed.netloc:
        if parsed.scheme.lower() not in {"http", "https"}:
            raise RuntimeError(f"iCloud Privacy Mail {field_name} 只能使用 http/https URL")
        if (
            parsed.scheme.lower() != parsed_base.scheme.lower()
            or parsed.hostname != parsed_base.hostname
            or (parsed.port or 0) != (parsed_base.port or 0)
        ):
            raise RuntimeError(f"iCloud Privacy Mail {field_name} 必须位于配置的 API Base 内")
        return parsed.geturl()
    if raw.startswith("//"):
        raise RuntimeError(f"iCloud Privacy Mail {field_name} 必须位于配置的 API Base 内")
    resolved = urljoin(base_url, raw)
    parsed_resolved = urlsplit(resolved)
    if (
        parsed_resolved.scheme.lower() != parsed_base.scheme.lower()
        or parsed_resolved.hostname != parsed_base.hostname
        or (parsed_resolved.port or 0) != (parsed_base.port or 0)
    ):
        raise RuntimeError(f"iCloud Privacy Mail {field_name} 必须位于配置的 API Base 内")
    return resolved


def _icloud_mailbox_session(mailbox: dict[str, Any]) -> requests.Session:
    kwargs = proxy_settings.build_session_kwargs(
        proxy=_mail_session_proxy(mailbox),
        upstream=True,
        impersonate=CHROME146_IMPERSONATE,
        verify=not proxy_settings.should_skip_ssl_verify(),
    )
    session = requests.Session(**kwargs)
    session.headers.update(chrome146_headers({
        "User-Agent": _chrome146_user_agent(mailbox.get("_icloud_user_agent")),
    }, include_defaults=False))
    return session


def _icloud_api_request(
    session: requests.Session,
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    payload: dict[str, Any] | None = None,
    expected: tuple[int, ...] = (200,),
    timeout: float = 30,
) -> dict[str, Any]:
    try:
        request_headers = chrome146_headers({
            "Accept": "application/json",
            "Content-Type": "application/json",
            **(headers or {}),
        }, include_defaults=False)
        with http_target_session_request(session, url) as request_options:
            resp = session.request(
                method.upper(),
                url,
                headers=request_headers,
                params=params,
                json=payload,
                timeout=timeout,
                verify=not proxy_settings.should_skip_ssl_verify(),
                **request_options,
            )
    except requests.exceptions.RequestException as exc:
        safe_url = redact_register_log_text(url)
        raise RuntimeError(f"iCloud Privacy Mail 请求失败: {method.upper()} {safe_url}, {exc}") from exc
    if resp.status_code not in expected:
        detail = str(getattr(resp, "text", "") or "")
        safe_url = redact_register_log_text(url)
        raise RuntimeError(f"iCloud Privacy Mail 请求失败: {method.upper()} {safe_url}, HTTP {resp.status_code}, body={detail}")
    if resp.status_code == 204:
        return {}
    try:
        data = resp.json()
    except Exception:
        data = {}
    if not isinstance(data, dict):
        return {}
    if data.get("success") is False or data.get("ok") is False:
        code = str(data.get("code") or "").strip()
        message = str(data.get("message") or data.get("error") or "").strip()
        retryable = _normalize_bool(data.get("retryable"), False)
        detail = ", ".join(
            item
            for item in (
                f"code={code}" if code else "",
                f"retryable={str(retryable).lower()}",
                f"message={message}" if message else "",
            )
            if item
        )
        safe_url = redact_register_log_text(url)
        raise RuntimeError(f"iCloud Privacy Mail 请求失败: {method.upper()} {safe_url}, {detail}")
    return data


def _icloud_finalize_retryable_error(error: object) -> bool:
    text = str(error or "").strip()
    if not text:
        return False
    upper = text.upper()
    if any(f"HTTP {status}" in upper for status in ICLOUD_API_RETRYABLE_FINALIZE_STATUS):
        return True
    lowered = text.lower()
    if "retryable=true" in lowered or "retryable: true" in lowered:
        return True
    return any(
        keyword in lowered
        for keyword in (
            "timeout",
            "timed out",
            "temporarily unavailable",
            "connection reset",
            "connection aborted",
            "connection refused",
            "broken pipe",
            "bad gateway",
            "service unavailable",
        )
    )


def _icloud_mailbox_note(error: object | None = None, note: str = "") -> str:
    parts = [str(note or "").strip()]
    if error is not None:
        error_text = str(error or "").strip()
        if error_text:
            parts.append(error_text)
    return "；".join(item for item in parts if item)


def _icloud_mailbox_field(mailbox: dict[str, Any], *keys: str) -> str:
    if not isinstance(mailbox, dict):
        return ""
    for key in keys:
        value = str(mailbox.get(key) or "").strip()
        if value:
            return value
    return ""


def _icloud_mailbox_finalize(
    mailbox: dict[str, Any],
    *,
    success: bool,
    error: object | None = None,
    note: str = "",
    release_only: bool = False,
) -> bool:
    mailbox.pop("_icloud_finalize_error", None)
    api_key = str(mailbox.get("_icloud_api_key") or "").strip()
    if not api_key:
        mailbox["_icloud_finalize_error"] = "iCloud Privacy Mail 缺少 API Key，无法回写邮箱状态"
        return False
    claim_token = _icloud_mailbox_field(mailbox, "claim_token", "claimToken")
    email = _icloud_mailbox_field(mailbox, "address", "email")
    project = str(mailbox.get("_icloud_project") or ICLOUD_API_DEFAULT_PROJECT).strip() or ICLOUD_API_DEFAULT_PROJECT
    purpose = str(mailbox.get("_icloud_purpose") or ICLOUD_API_DEFAULT_PURPOSE).strip() or ICLOUD_API_DEFAULT_PURPOSE
    headers = {
        "Authorization": f"Bearer {api_key}",
    }
    payload_note = _icloud_mailbox_note(error, note)
    timeout = float(mailbox.get("_icloud_request_timeout") or 30)
    if not claim_token:
        mailbox["_icloud_finalize_error"] = "iCloud Privacy Mail 缺少 claim_token"
        return False
    if not email:
        mailbox["_icloud_finalize_error"] = "iCloud Privacy Mail 缺少 email"
        return False
    target_url = _icloud_validate_response_url(
        _icloud_mailbox_field(mailbox, "release_url", "releaseUrl")
        if release_only
        else _icloud_mailbox_field(mailbox, "result_url", "resultUrl"),
        str(mailbox.get("_icloud_api_base") or ""),
        field_name="release_url" if release_only else "result_url",
    )
    if not target_url:
        mailbox["_icloud_finalize_error"] = "iCloud Privacy Mail 缺少回写 URL"
        return False
    payload: dict[str, Any] = {"claim_token": claim_token, "email": email, "project": project, "purpose": purpose}
    if release_only:
        if payload_note:
            payload["note"] = payload_note
    else:
        payload["success"] = bool(success)
        if payload_note:
            payload["note"] = payload_note
        if not success and payload_note:
            payload["error"] = payload_note
    for attempt in range(3):
        session = _icloud_mailbox_session(mailbox)
        try:
            _icloud_api_request(session, "POST", target_url, headers=headers, payload=payload, expected=(200, 201, 204), timeout=timeout)
            mailbox.pop("_icloud_finalize_error", None)
            return True
        except Exception as exc:
            if attempt < 2 and _icloud_finalize_retryable_error(exc):
                time.sleep(min(0.5 * (attempt + 1), 1.5))
                continue
            mailbox["_icloud_finalize_error"] = str(exc) or exc.__class__.__name__
            return False
        finally:
            try:
                session.close()
            except Exception:
                pass


class ICloudApiProvider(BaseMailProvider):
    name = "icloud_api"

    def __init__(self, entry: dict, conf: dict):
        super().__init__(conf, str(entry.get("provider_ref") or ""))
        self.label = str(entry.get("label") or self.provider_ref)
        self.api_base = _icloud_api_root(str(entry.get("api_base") or ""))
        self.api_key = str(entry.get("api_key") or "").strip()
        if not self.api_base or not self.api_key:
            raise RuntimeError("iCloud Privacy Mail 需要 API Base 和 API Key")
        self.project = ICLOUD_API_DEFAULT_PROJECT
        self.purpose = ICLOUD_API_DEFAULT_PURPOSE
        self.keyword = ICLOUD_API_DEFAULT_KEYWORD
        kwargs = proxy_settings.build_session_kwargs(
            proxy=_mail_session_proxy(conf),
            upstream=True,
            impersonate=CHROME146_IMPERSONATE,
            verify=not proxy_settings.should_skip_ssl_verify(),
        )
        self.session = requests.Session(**kwargs)
        self.session.headers.update(chrome146_headers({
            "User-Agent": conf["user_agent"],
            "Accept": "application/json",
            "Content-Type": "application/json",
        }, include_defaults=False))

    def _headers(self) -> dict[str, str]:
        return chrome146_headers({
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": self.conf["user_agent"],
            "Accept": "application/json",
            "Content-Type": "application/json",
        }, include_defaults=False)

    def _claim_url(self) -> str:
        return _icloud_api_url(self.api_base, "/mailboxes/claim")

    def create_mailbox(self, username: str | None = None) -> dict[str, Any]:
        payload = {
            "project": self.project,
            "purpose": self.purpose,
            "count": 1,
        }
        request_timeout = self._request_timeout()
        data = _icloud_api_request(self.session, "POST", self._claim_url(), headers=self._headers(), payload=payload, expected=(200, 201), timeout=request_timeout)
        mailbox = data.get("mailbox") if isinstance(data, dict) else None
        if not isinstance(mailbox, dict):
            raise RuntimeError("iCloud Privacy Mail 领取响应缺少 mailbox")
        address = _icloud_mailbox_field(mailbox, "email", "address")
        api_url_raw = _icloud_mailbox_field(mailbox, "api_url", "apiUrl")
        messages_api_url_raw = _icloud_mailbox_field(mailbox, "messages_api_url", "messagesApiUrl")
        api_url = _icloud_validate_response_url(
            api_url_raw or messages_api_url_raw,
            self.api_base,
            field_name="api_url",
        )
        result_url = _icloud_validate_response_url(
            _icloud_mailbox_field(mailbox, "result_url", "resultUrl"),
            self.api_base,
            field_name="result_url",
        )
        release_url = _icloud_validate_response_url(
            _icloud_mailbox_field(mailbox, "release_url", "releaseUrl"),
            self.api_base,
            field_name="release_url",
        )
        messages_api_url = _icloud_validate_response_url(
            messages_api_url_raw or api_url,
            self.api_base,
            field_name="messages_api_url",
        )
        claim_token = _icloud_mailbox_field(mailbox, "claim_token", "claimToken")
        messages_api_url = messages_api_url or api_url
        if not address or not api_url or not result_url or not release_url or not claim_token or not messages_api_url:
            partial = {
                "provider": self.name,
                "provider_ref": self.provider_ref,
                "address": address,
                "result_url": result_url,
                "release_url": release_url,
                "claim_token": claim_token,
                "_icloud_api_key": self.api_key,
                "_icloud_proxy": self.conf["proxy"],
                "_icloud_user_agent": self.conf["user_agent"],
                "_icloud_request_timeout": request_timeout,
                "_icloud_api_base": self.api_base,
                "_icloud_project": self.project,
                "_icloud_purpose": self.purpose,
                "_code_received": False,
            }
            _icloud_mailbox_finalize(partial, success=False, note="iCloud 领取响应字段不完整", release_only=True)
            raise RuntimeError("iCloud Privacy Mail 领取响应缺少必要字段")
        return {
            "provider": self.name,
            "provider_ref": self.provider_ref,
            "address": address,
            "label": self.label,
            "api_url": api_url,
            "result_url": result_url,
            "release_url": release_url,
            "messages_api_url": messages_api_url,
            "claim_token": claim_token,
            "_icloud_api_key": self.api_key,
            "_icloud_proxy": self.conf["proxy"],
            "_icloud_user_agent": self.conf["user_agent"],
            "_icloud_request_timeout": request_timeout,
            "_icloud_api_base": self.api_base,
            "_icloud_project": self.project,
            "_icloud_purpose": self.purpose,
            "_code_received": False,
        }

    def fetch_latest_message(self, mailbox: dict[str, Any]) -> dict[str, Any] | None:
        code_url = _icloud_validate_response_url(
            _icloud_mailbox_field(mailbox, "api_url", "apiUrl", "messages_api_url", "messagesApiUrl"),
            str(mailbox.get("_icloud_api_base") or self.api_base),
            field_name="api_url",
        )
        if not code_url:
            raise RuntimeError("iCloud Privacy Mail 邮箱缺少 api_url")
        params: dict[str, Any] = {
            "allow_stale": "1",
            "keyword": self.keyword,
            "project": self.project,
        }
        remaining = self._remaining_wait_seconds()
        wait_ms = 12000 if remaining is None else max(1, min(12000, int(max(0.001, remaining) * 1000)))
        params["wait_ms"] = str(wait_ms)
        code_boundary = _mailbox_code_boundary(mailbox)
        if code_boundary is not None:
            params["after"] = code_boundary.isoformat()
        try:
            with http_target_session_request(self.session, code_url) as request_options:
                resp = self.session.request(
                    "GET",
                    code_url,
                    headers=self._headers(),
                    params=params,
                    timeout=self._request_timeout(),
                    verify=not proxy_settings.should_skip_ssl_verify(),
                    **request_options,
                )
        except requests.exceptions.RequestException as exc:
            if _icloud_finalize_retryable_error(exc):
                return None
            raise
        if resp.status_code in ICLOUD_API_RETRYABLE_STATUS:
            return None
        try:
            data = resp.json()
        except Exception:
            data = {}
        if not isinstance(data, dict):
            return None
        messages = data.get("messages")
        if isinstance(messages, list):
            for item in messages:
                if not isinstance(item, dict):
                    continue
                text_content = str(item.get("body") or item.get("text") or item.get("text_content") or item.get("content") or "").strip()
                html_content = str(item.get("html") or item.get("html_content") or "").strip()
                sender = item.get("from") or item.get("sender") or ""
                if isinstance(sender, dict):
                    sender = sender.get("address") or sender.get("email") or sender.get("name") or ""
                message = {
                    "provider": self.name,
                    "mailbox": str(mailbox.get("address") or data.get("email") or ""),
                    "message_id": str(item.get("id") or item.get("message_id") or item.get("messageId") or item.get("remote_id") or "").strip(),
                    "subject": str(item.get("subject") or "").strip(),
                    "sender": str(sender or ""),
                    "verificationCode": str(item.get("code") or item.get("verificationCode") or item.get("verification_code") or "").strip(),
                    "text_content": text_content,
                    "html_content": html_content,
                    "received_at": _parse_received_at(item.get("received_at") or item.get("receivedAt") or item.get("created_at") or item.get("createdAt")),
                    "raw": item,
                }
                if _extract_code(message):
                    return message
            return None
        code = str(data.get("code") or "").strip()
        retryable = _normalize_bool(data.get("retryable"), False)
        success = _normalize_bool(data.get("success"), _normalize_bool(data.get("ok"), False))
        if success and code:
            message_id = str(data.get("message_id") or data.get("messageId") or data.get("id") or code).strip() or code
            received_at = _parse_received_at(data.get("received_at") or data.get("receivedAt") or data.get("created_at") or data.get("createdAt"))
            subject = str(data.get("subject") or "").strip()
            text_content = str(data.get("message") or data.get("text") or data.get("content") or code).strip()
            return {
                "provider": self.name,
                "mailbox": str(mailbox.get("address") or ""),
                "message_id": message_id,
                "subject": subject,
                "sender": "",
                "verificationCode": code,
                "text_content": text_content,
                "html_content": "",
                "received_at": received_at,
                "raw": data,
            }
        if code == "no_code" or retryable:
            return None
        message = str(data.get("message") or data.get("error") or "").strip()
        if resp.status_code in (401, 403, 404) or data.get("code") in {"invalid_api_key", "mailbox_not_found", "api_disabled", "icloud_inactive", "remote_deleted"}:
            raise RuntimeError(message or f"iCloud Privacy Mail 请求失败: HTTP {resp.status_code}, code={data.get('code') or ''}")
        if message:
            raise RuntimeError(message)
        return None

    def close(self) -> None:
        self.session.close()


class ReMailProvider(BaseMailProvider):
    name = "remail"

    def __init__(self, entry: dict, conf: dict):
        super().__init__(conf, str(entry.get("provider_ref") or ""))
        self.provider_id = str(entry.get("id") or entry.get("provider_id") or "").strip()
        self.api_base = str(entry.get("api_base") or REMAIL_DEFAULT_API_BASE).rstrip("/")
        self.api_key = str(entry.get("api_key") or "").strip()
        if not self.api_key:
            raise RuntimeError("Remail API Key is required")
        self.service_mode = str(entry.get("service_mode") or "code").strip().lower() or "code"
        if self.service_mode not in {"code", "purchase"}:
            self.service_mode = "code"
        self.supply = str(entry.get("supply") or "private_first").strip().lower() or "private_first"
        if self.supply not in {"private_first", "public_only"}:
            self.supply = "private_first"
        self.project_id = _remail_required_positive_int(entry.get("project_id"), REMAIL_DEFAULT_PROJECT_ID, "Project ID")
        self.product_id = _remail_required_positive_int(entry.get("product_id"), REMAIL_DEFAULT_PRODUCT_ID, "Product ID")
        self.email_suffix = str(entry.get("email_suffix") or "").strip().lstrip("@")
        self.session = _create_session(conf)
        self.session.headers.update(chrome146_headers({
            "User-Agent": conf["user_agent"],
            "Accept": "application/json",
            "Content-Type": "application/json",
        }, include_defaults=False))

    def _mailbox_wait_deadline(self, mailbox: dict[str, Any]) -> float | None:
        base_deadline = super()._mailbox_wait_deadline(mailbox)
        if base_deadline is None:
            base_deadline = time.monotonic() + max(0.001, float(self.conf["wait_timeout"]))
        receive_until_deadline = _remail_receive_until_deadline(mailbox)
        if receive_until_deadline is None:
            return base_deadline
        return min(base_deadline, receive_until_deadline)

    def _headers(self, *, api_key: bool = False, idempotency_key: str = "") -> dict[str, str]:
        headers = chrome146_headers({
            "User-Agent": self.conf["user_agent"],
            "Accept": "application/json",
            "Content-Type": "application/json",
        }, include_defaults=False)
        if api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        return headers

    def _provider_snapshot(self) -> dict[str, Any]:
        snapshot: dict[str, Any] = {
            "type": self.name,
            "provider_ref": self.provider_ref,
            "api_base": self.api_base,
            "api_key": self.api_key,
            "service_mode": self.service_mode,
            "supply": self.supply,
            "project_id": self.project_id,
            "product_id": self.product_id,
            "email_suffix": self.email_suffix,
        }
        if self.provider_id:
            snapshot["id"] = self.provider_id
        return snapshot

    def _sanitize(self, value: object, *extra_secrets: object) -> str:
        return _remail_text(value, self.api_key, *extra_secrets)

    def _response_body(self, resp: Any, *extra_secrets: object) -> str:
        try:
            body = resp.text
        except Exception:
            body = ""
        return self._sanitize(body, *extra_secrets)

    @staticmethod
    def _unwrap_payload(data: Any) -> Any:
        if isinstance(data, dict):
            nested = data.get("data")
            if isinstance(nested, (dict, list)):
                return nested
            for key in ("order", "message"):
                nested = data.get(key)
                if isinstance(nested, dict):
                    return nested
        return data

    @staticmethod
    def _items(data: Any) -> list[dict[str, Any]]:
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if not isinstance(data, dict):
            return []
        for key in ("items", "messages", "data", "list", "records"):
            rows = data.get(key)
            if isinstance(rows, list):
                return [item for item in rows if isinstance(item, dict)]
        if data.get("id") or data.get("messageId") or data.get("message_id"):
            return [data]
        return []

    @staticmethod
    def _sender(value: Any) -> str:
        if isinstance(value, dict):
            return str(value.get("address") or value.get("email") or value.get("name") or "")
        return str(value or "")

    @staticmethod
    def _message_text_html(item: dict[str, Any]) -> tuple[str, str]:
        body = item.get("body")
        if isinstance(body, dict):
            text_content = str(
                body.get("text")
                or body.get("textContent")
                or body.get("plain")
                or body.get("content")
                or item.get("bodyPreview")
                or ""
            )
            html_content = str(body.get("html") or body.get("htmlContent") or "")
            if text_content or html_content:
                return text_content, html_content
        elif isinstance(body, str):
            return body, str(item.get("html") or item.get("html_content") or "")
        text_content, html_content = _extract_content(item)
        if not text_content and item.get("bodyPreview"):
            text_content = str(item.get("bodyPreview") or "")
        return text_content, html_content

    def _decode_response(self, resp: Any, *extra_secrets: object) -> Any:
        try:
            data = resp.json()
        except Exception:
            body = self._response_body(resp, *extra_secrets)
            detail = f": {body}" if body else ""
            raise RuntimeError(f"Remail API returned non-JSON response{detail}")
        if isinstance(data, dict) and (data.get("success") is False or data.get("ok") is False):
            detail = data.get("message") or data.get("error") or data.get("errorMessage") or "Remail API returned failure"
            code = data.get("code") or data.get("errorCode") or data.get("error_code") or ""
            combined = f"{code} {detail}"
            sanitized = self._sanitize(detail, *extra_secrets)
            if extra_secrets and _is_remail_service_token_error(combined):
                raise ReMailServiceTokenInvalidError(sanitized)
            raise RuntimeError(sanitized)
        return self._unwrap_payload(data)

    def _retry_delay(self, resp: Any | None, attempt: int) -> float:
        value = ""
        if resp is not None:
            try:
                value = str(resp.headers.get("Retry-After") or "").strip()
            except Exception:
                value = ""
        if value:
            try:
                return max(0.2, min(5.0, float(value)))
            except ValueError:
                pass
        return min(2.0, 0.4 * (attempt + 1))

    def _sleep_before_retry(self, resp: Any | None, attempt: int) -> None:
        delay = self._retry_delay(resp, attempt)
        if self._wait_deadline is None:
            time.sleep(delay)
            return
        if not self._sleep_with_deadline(delay):
            raise _MailWaitDeadlineExceeded("Remail request retry deadline exceeded")

    def _request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
        expected: tuple[int, ...] = (200,),
        retry: bool = False,
        secrets: tuple[object, ...] = (),
    ) -> Any:
        max_attempts = 3 if retry else 1
        last_error: Exception | None = None
        for attempt in range(max_attempts):
            try:
                url = f"{self.api_base}{path}"
                with http_target_session_request(self.session, url) as request_options:
                    resp = self.session.request(
                        method.upper(),
                        url,
                        headers=headers or self._headers(),
                        params=params,
                        json=payload,
                        timeout=self._request_timeout(),
                        verify=not proxy_settings.should_skip_ssl_verify(),
                        **request_options,
                    )
            except AssertionError:
                raise
            except _MailWaitDeadlineExceeded:
                raise
            except Exception as exc:
                last_error = exc
                if retry and attempt + 1 < max_attempts:
                    self._sleep_before_retry(None, attempt)
                    continue
                raise RuntimeError(f"Remail request failed: {method.upper()} {path}, {self._sanitize(exc, *secrets)}") from exc
            if resp.status_code in expected:
                return self._decode_response(resp, *secrets)
            detail = self._response_body(resp, *secrets)
            if retry and resp.status_code in REMAIL_RETRYABLE_STATUS and attempt + 1 < max_attempts:
                self._sleep_before_retry(resp, attempt)
                continue
            raise ReMailHttpError(resp.status_code, method, path, detail)
        if last_error:
            raise RuntimeError(f"Remail request failed: {method.upper()} {path}, {self._sanitize(last_error, *secrets)}") from last_error
        raise RuntimeError(f"Remail request failed: {method.upper()} {path}")

    def _order_detail(self, mailbox: dict[str, Any]) -> dict[str, Any]:
        order_ref = str(mailbox.get("order_no") or mailbox.get("orderNo") or mailbox.get("purchase_id") or "").strip()
        if not order_ref:
            raise RuntimeError("Remail service token expired and order reference is missing")
        data = self._request(
            "GET",
            f"/v1/open/orders/{quote(order_ref, safe='')}",
            headers=self._headers(api_key=True),
            expected=(200,),
            retry=True,
        )
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _terminal_reason(order: dict[str, Any]) -> str:
        status = str(order.get("status") or order.get("orderStatus") or "").strip().lower()
        if status in REMAIL_TERMINAL_ORDER_STATUS:
            return f"remail_terminal_status={status}"
        failure_code = str(order.get("failureCode") or order.get("failure_code") or "").strip().lower()
        if failure_code in REMAIL_TERMINAL_FAILURE_CODES:
            return f"remail_terminal_failure_code={failure_code}"
        return ""

    @staticmethod
    def _mailbox_from_order(order: dict[str, Any], mailbox: dict[str, Any] | None = None) -> dict[str, Any]:
        result = dict(mailbox or {})
        address = str(order.get("deliveryEmail") or order.get("delivery_email") or order.get("email") or order.get("address") or "").strip()
        order_no = str(order.get("orderNo") or order.get("order_no") or "").strip()
        purchase_id = str(order.get("id") or order.get("purchaseId") or order.get("purchase_id") or "").strip()
        token = str(order.get("serviceToken") or order.get("service_token") or order.get("token") or "").strip()
        if address:
            result["address"] = address
        if order_no:
            result["order_no"] = order_no
        if purchase_id:
            result["purchase_id"] = purchase_id
        if token:
            result["token"] = token
        result.setdefault("provider", ReMailProvider.name)
        return result

    @staticmethod
    def _order_message(order: dict[str, Any], mailbox: dict[str, Any]) -> dict[str, Any]:
        merged_mailbox = ReMailProvider._mailbox_from_order(order, mailbox)
        address = str(merged_mailbox.get("address") or "").strip()
        order_no = str(merged_mailbox.get("order_no") or order.get("orderNo") or order.get("order_no") or "").strip()
        verification_code = str(order.get("verificationCode") or order.get("verification_code") or "").strip()
        body_preview = str(order.get("bodyPreview") or order.get("body_preview") or "").strip()
        text_content = str(
            order.get("body")
            or order.get("text_content")
            or order.get("text")
            or body_preview
            or (f"Your verification code is {verification_code}" if verification_code else "")
        ).strip()
        return {
            "provider": ReMailProvider.name,
            "mailbox": address,
            "message_id": str(order.get("messageId") or order.get("message_id") or order.get("lastMessageId") or order.get("id") or order_no).strip(),
            "subject": str(order.get("subject") or "Remail verification code"),
            "sender": str(order.get("sender") or order.get("from") or ""),
            "text_content": text_content,
            "html_content": str(order.get("html_content") or order.get("html") or ""),
            "received_at": _parse_received_at(
                order.get("lastMailReceivedAt")
                or order.get("last_mail_received_at")
                or order.get("receivedAt")
                or order.get("updatedAt")
                or order.get("createdAt")
            ),
            "to": address,
            "raw": order,
            "verificationCode": verification_code,
        }

    def _order_message_with_code(self, order: dict[str, Any], mailbox: dict[str, Any]) -> dict[str, Any] | None:
        message = self._order_message(order, mailbox)
        if not _message_matches_email(message, str(mailbox.get("address") or "")):
            return None
        return message if _extract_code(message) else None

    def _raise_terminal_order(self, order: dict[str, Any], mailbox: dict[str, Any] | None = None, *, record: bool = False) -> None:
        terminal_reason = self._terminal_reason(order)
        if not terminal_reason:
            return
        if terminal_reason == "remail_terminal_status=completed" and mailbox is not None:
            if self._order_message_with_code(order, mailbox):
                return
        target = self._mailbox_from_order(order, mailbox)
        if record:
            dead_reason = _remail_dead_reason(f"Remail order terminal: {terminal_reason}") or terminal_reason
            _record_remail_dead_mailbox(target, dead_reason)
        raise RuntimeError(f"Remail order terminal: {terminal_reason}")

    def _order_detail_if_due(self, mailbox: dict[str, Any], *, force: bool = False) -> dict[str, Any] | None:
        if not force:
            try:
                next_check_at = float(mailbox.get("_remail_order_next_check_at") or 0)
            except (TypeError, ValueError):
                next_check_at = 0.0
            if next_check_at and time.monotonic() < next_check_at:
                return None
        order = self._order_detail(mailbox)
        mailbox["_remail_order_next_check_at"] = time.monotonic() + REMAIL_ORDER_STATUS_CHECK_INTERVAL
        return order

    def _raise_terminal_mailbox_order(self, mailbox: dict[str, Any], *, swallow_non_terminal_errors: bool = False) -> dict[str, Any] | None:
        try:
            order = self._order_detail_if_due(mailbox)
            if order is None:
                return None
            self._raise_terminal_order(order, mailbox)
            return order
        except RuntimeError as exc:
            if _remail_dead_reason(exc):
                raise
            if not swallow_non_terminal_errors:
                raise
        return None

    def _refresh_service_token(self, mailbox: dict[str, Any], order: dict[str, Any] | None = None) -> str:
        order = order if isinstance(order, dict) else self._order_detail(mailbox)
        self._raise_terminal_order(order, mailbox)
        token = str(order.get("serviceToken") or order.get("service_token") or order.get("token") or "").strip()
        if token:
            mailbox["token"] = token
            if order.get("orderNo") or order.get("order_no"):
                mailbox["order_no"] = str(order.get("orderNo") or order.get("order_no") or "")
            if order.get("id") is not None:
                mailbox["purchase_id"] = str(order.get("id"))
            if order.get("receiveUntil") or order.get("receive_until"):
                mailbox["receive_until"] = str(order.get("receiveUntil") or order.get("receive_until") or "")
            receive_until_deadline = _remail_receive_until_deadline(mailbox)
            if receive_until_deadline is not None:
                self._wait_deadline = receive_until_deadline if self._wait_deadline is None else min(self._wait_deadline, receive_until_deadline)
            return token
        raise RuntimeError("Remail service token expired and refresh returned no service token")

    def _pickup_request(self, mailbox: dict[str, Any], path: str, *, retry_after_refresh: bool = True) -> Any:
        address = str(mailbox.get("address") or "").strip()
        token = str(mailbox.get("token") or "").strip()
        if not address or not token:
            raise RuntimeError("Remail mailbox missing address or service token")
        params = {"email": address, "token": token}
        def retry_with_refreshed_token() -> Any:
            order = self._order_detail(mailbox)
            self._raise_terminal_order(order, mailbox)
            order_message = self._order_message_with_code(order, mailbox)
            if order_message:
                return {"items": [order_message]} if path == "/v1/pickup" else order_message
            refreshed_token = self._refresh_service_token(mailbox, order)
            params["token"] = refreshed_token
            return self._request(
                "GET",
                path,
                headers=self._headers(),
                params=params,
                expected=(200,),
                retry=True,
                secrets=(refreshed_token,),
            )

        try:
            return self._request(
                "GET",
                path,
                headers=self._headers(),
                params=params,
                expected=(200,),
                retry=True,
                secrets=(token,),
            )
        except ReMailServiceTokenInvalidError:
            if not retry_after_refresh:
                raise
            return retry_with_refreshed_token()
        except ReMailHttpError as exc:
            service_token_error = exc.status_code == 401 or (
                exc.status_code in {403, 404, 409, 422}
                and _is_remail_service_token_error(exc.detail)
            )
            if not service_token_error or not retry_after_refresh:
                raise
            return retry_with_refreshed_token()

    def _normalize_message(self, item: dict[str, Any], mailbox: dict[str, Any]) -> dict[str, Any]:
        text_content, html_content = self._message_text_html(item)
        message_id = str(item.get("id") or item.get("messageId") or item.get("message_id") or "").strip()
        sender = item.get("sender") or item.get("from") or item.get("fromAddress") or ""
        recipient = item.get("recipient") or item.get("to") or item.get("toEmail") or str(mailbox.get("address") or "")
        return {
            "provider": self.name,
            "mailbox": str(mailbox.get("address") or ""),
            "message_id": message_id,
            "subject": str(item.get("subject") or ""),
            "sender": self._sender(sender),
            "text_content": text_content,
            "html_content": html_content,
            "received_at": _parse_received_at(item.get("receivedAt") or item.get("received_at") or item.get("date") or item.get("timestamp")),
            "to": recipient,
            "raw": item,
            "verificationCode": str(item.get("verificationCode") or item.get("verification_code") or "").strip(),
        }

    def create_mailbox(self, username: str | None = None) -> dict[str, Any]:
        previous_deadline = self._start_wait_window()
        try:
            idempotency_key = str(uuid.uuid4())
            payload: dict[str, Any] = {"projectId": self.project_id, "productId": self.product_id}
            if self.email_suffix:
                payload["emailSuffix"] = self.email_suffix
            data = self._request(
                "POST",
                "/v1/open/orders",
                headers=self._headers(api_key=True, idempotency_key=idempotency_key),
                params={"serviceMode": self.service_mode, "supply": self.supply},
                payload=payload,
                expected=(200, 201),
                retry=True,
            )
            order = data if isinstance(data, dict) else {}
        finally:
            self._restore_wait_window(previous_deadline)
        mailbox = self._mailbox_from_order(order)
        self._raise_terminal_order(order, mailbox, record=True)
        address = str(mailbox.get("address") or "").strip()
        token = str(mailbox.get("token") or "").strip()
        if not address or not token:
            terminal_reason = self._terminal_reason(order)
            detail = f", {terminal_reason}" if terminal_reason else ""
            if terminal_reason and not self._order_message_with_code(order, mailbox):
                _record_remail_dead_mailbox(mailbox, _remail_dead_reason(f"Remail order terminal: {terminal_reason}") or terminal_reason)
            raise RuntimeError(f"Remail order missing deliveryEmail or serviceToken{detail}")
        order_no = str(order.get("orderNo") or order.get("order_no") or "").strip()
        purchase_id = str(order.get("id") or order.get("purchaseId") or order.get("purchase_id") or "").strip()
        mailbox.update({
            "provider": self.name,
            "provider_ref": self.provider_ref,
            "address": address,
            "token": token,
            "order_no": order_no,
            "purchase_id": purchase_id,
            "service_mode": str(order.get("serviceMode") or order.get("service_mode") or self.service_mode),
            "receive_until": str(order.get("receiveUntil") or order.get("receive_until") or ""),
            REMAIL_PROVIDER_SNAPSHOT_KEY: self._provider_snapshot(),
        })
        return mailbox

    def fetch_latest_message(self, mailbox: dict[str, Any]) -> dict[str, Any] | None:
        data = self._pickup_request(mailbox, "/v1/pickup")
        messages = self._items(data)
        if not messages:
            order = self._raise_terminal_mailbox_order(mailbox, swallow_non_terminal_errors=True)
            if isinstance(order, dict):
                order_message = self._order_message_with_code(order, mailbox)
                if order_message:
                    return order_message
            return None
        target_address = str(mailbox.get("address") or "")

        def sort_key(message: dict[str, Any]) -> tuple[float, str]:
            received_at = message.get("received_at")
            if not isinstance(received_at, datetime):
                received_at = datetime.fromtimestamp(0, tz=timezone.utc)
            elif not received_at.tzinfo:
                received_at = received_at.replace(tzinfo=timezone.utc)
            return received_at.timestamp(), str(message.get("message_id") or "")

        candidates: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for item in messages:
            message = self._normalize_message(item, mailbox)
            if _message_matches_email(message, target_address):
                candidates.append((message, item))
        if not candidates:
            return None
        candidates.sort(key=lambda pair: sort_key(pair[0]), reverse=True)
        for message, _item in candidates:
            if _extract_code(message):
                return message
        latest_message = candidates[0][0]
        latest_detail = latest_message
        for message, item in candidates:
            message_id = message.get("message_id")
            if not message_id:
                continue
            detail = self._pickup_request(mailbox, f"/v1/pickup/messages/{quote(str(message_id), safe='')}")
            if not isinstance(detail, dict):
                continue
            detailed_message = self._normalize_message({**item, **detail}, mailbox)
            if not _message_matches_email(detailed_message, target_address):
                continue
            if message is latest_message:
                latest_detail = detailed_message
            if _extract_code(detailed_message):
                return detailed_message
        order = self._raise_terminal_mailbox_order(mailbox, swallow_non_terminal_errors=True)
        if isinstance(order, dict):
            order_message = self._order_message_with_code(order, mailbox)
            if order_message:
                return order_message
        return latest_detail

    def wait_for_code(self, mailbox: dict[str, Any]) -> str | None:
        seen_value = mailbox.setdefault("_seen_code_message_refs", [])
        if not isinstance(seen_value, list):
            seen_value = []
            mailbox["_seen_code_message_refs"] = seen_value
        seen_refs = {str(item) for item in seen_value}

        def extract_unseen_code(message: dict[str, Any]) -> str | None:
            if _message_before_received_after(mailbox, message):
                return None
            ref = _message_tracking_ref(message)
            if ref in seen_refs:
                return None
            code = _extract_code(message)
            if code:
                seen_value.append(ref)
                seen_refs.add(ref)
            return code

        return self.wait_for(mailbox, extract_unseen_code)

    def close(self) -> None:
        self.session.close()


OUTLOOK_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
OUTLOOK_GRAPH_MESSAGES_URL = "https://graph.microsoft.com/v1.0/me/messages"
OUTLOOK_GRAPH_SCOPE = "offline_access https://graph.microsoft.com/Mail.Read"
OUTLOOK_IMAP_SCOPE = "offline_access https://outlook.office.com/IMAP.AccessAsUser.All"
OUTLOOK_DEFAULT_IMAP_HOST = "outlook.office365.com"


def _is_outlook_scope_denied(error: Exception | str) -> bool:
    text = str(error or "").lower()
    return (
        "aadsts70000" in text
        or ("scope" in text and ("unauthorized" in text or "expired" in text or "grant" in text))
    )


class OutlookTokenError(RuntimeError):
    """refresh_token 换取 access_token 失败（凭据失效/权限不对），与“读邮件失败”区分。"""


class OutlookTokenRateLimitError(OutlookTokenError):
    """Microsoft OAuth 临时限流，不代表 refresh_token 已失效。"""


class OutlookAliasTagBusyError(RuntimeError):
    """同一长度的加号标签随机抽取多次冲突，本次领用应稍后重试。"""


class OutlookFolderMissing(RuntimeError):
    """Graph 或 IMAP 垃圾箱不存在时只跳过该文件夹。"""


class OutlookMailboxReadError(RuntimeError):
    """IMAP 文件夹列表失败。不能把它当成没有垃圾箱。"""


def _clean_outlook_value(value: str) -> str:
    return str(value or "").replace("﻿", "").replace(" ", " ").strip()


def _format_outlook_email(email: str) -> str:
    return str(email or "").strip()


def _add_outlook_parse_issue(issues: list[dict[str, Any]], line_no: int, reason: str, email: str = "") -> None:
    if len(issues) >= 5:
        return
    issue: dict[str, Any] = {"line": line_no, "reason": reason}
    if email:
        issue["email"] = _format_outlook_email(email)
    issues.append(issue)


def _parse_outlook_credentials_with_report(text: str) -> tuple[list[dict[str, str]], dict[str, Any]]:
    """解析邮箱池文本，每行格式：email----password----client_id----refresh_token。"""
    credentials: list[dict[str, str]] = []
    seen: set[str] = set()
    report: dict[str, Any] = {
        "raw_lines": 0,
        "non_empty": 0,
        "valid": 0,
        "duplicates": 0,
        "invalid": 0,
        "skipped": 0,
        "issues": [],
    }
    issues = report["issues"]
    for line_no, raw_line in enumerate(str(text or "").splitlines(), start=1):
        report["raw_lines"] += 1
        line = _clean_outlook_value(raw_line)
        if not line:
            continue
        report["non_empty"] += 1
        if "----" not in line:
            report["invalid"] += 1
            _add_outlook_parse_issue(issues, line_no, "缺少 ---- 分隔符")
            continue
        parts = [_clean_outlook_value(part) for part in line.split("----", 3)]
        if len(parts) != 4:
            report["invalid"] += 1
            _add_outlook_parse_issue(issues, line_no, "字段不足")
            continue
        email, password, client_id, refresh_token = parts
        if "@" not in email:
            report["invalid"] += 1
            _add_outlook_parse_issue(issues, line_no, "邮箱格式不正确", email)
            continue
        if not client_id:
            report["invalid"] += 1
            _add_outlook_parse_issue(issues, line_no, "缺少 client_id", email)
            continue
        if not refresh_token:
            report["invalid"] += 1
            _add_outlook_parse_issue(issues, line_no, "缺少 refresh_token", email)
            continue
        key = email.lower()
        if key in seen:
            report["duplicates"] += 1
            _add_outlook_parse_issue(issues, line_no, "重复邮箱，已合并", email)
            continue
        seen.add(key)
        credentials.append({"email": email, "password": password, "client_id": client_id, "refresh_token": refresh_token})
    report["valid"] = len(credentials)
    report["skipped"] = int(report["duplicates"]) + int(report["invalid"])
    return credentials, report


def parse_outlook_credentials(text: str) -> list[dict[str, str]]:
    return _parse_outlook_credentials_with_report(text)[0]


def inspect_outlook_credentials(text: str) -> dict[str, Any]:
    return _parse_outlook_credentials_with_report(text)[1]


def _normalize_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on", "y", "enabled"}:
        return True
    if text in {"0", "false", "no", "off", "n", "disabled", "none", "null", ""}:
        return False
    return default


def _normalize_int(value: Any, default: int = 0, minimum: int | None = None, maximum: int | None = None) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        result = default
    if minimum is not None:
        result = max(minimum, result)
    if maximum is not None:
        result = min(maximum, result)
    return result


def outlook_alias_supported(email: str) -> bool:
    _, sep, domain = str(email or "").strip().lower().partition("@")
    if not sep:
        return False
    return (
        domain == "outlook.com"
        or domain == "hotmail.com"
        or domain == "live.com"
        or domain == "msn.com"
        or domain.startswith("hotmail.")
        or domain.startswith("outlook.")
    )


def outlook_alias_address(email: str, tag: str) -> str:
    local, sep, domain = str(email or "").strip().partition("@")
    if not sep:
        return email
    base_local = local.split("+", 1)[0]
    return f"{base_local}+{tag}@{domain}"


def outlook_alias_tag(prefix: str, index: int) -> str:
    clean_prefix = re.sub(r"[^A-Za-z0-9._-]+", "", str(prefix or "").strip()) or "c2api"
    return f"{clean_prefix}{index}"


def outlook_alias_max_tag_length(email: str) -> int:
    parent = outlook_alias_parent_email(email)
    local, sep, _domain = parent.partition("@")
    if not sep or not local:
        return 0
    remaining = OUTLOOK_ALIAS_LOCAL_PART_MAX_BYTES - len(local.encode("utf-8")) - 1
    return remaining if remaining >= OUTLOOK_ALIAS_TAG_MIN_LENGTH else 0


def generate_outlook_alias_tag(email: str, occupied: set[str] | None = None) -> str | None:
    """按需生成随机加号标签。2 位用尽后才加长，不预生成全部组合。"""
    max_length = outlook_alias_max_tag_length(email)
    if max_length < OUTLOOK_ALIAS_TAG_MIN_LENGTH:
        return None
    used = {str(item or "").strip().lower() for item in (occupied or set())}
    used.discard("")
    alphabet = OUTLOOK_ALIAS_TAG_ALPHABET
    for length in range(OUTLOOK_ALIAS_TAG_MIN_LENGTH, max_length + 1):
        capacity = len(alphabet) ** length
        used_at_length = sum(1 for tag in used if len(tag) == length)
        if used_at_length >= capacity:
            continue
        if length <= 2:
            candidates = ["".join(chars) for chars in itertools.product(alphabet, repeat=length)]
            free = [tag for tag in candidates if tag not in used]
            if free:
                return secrets.choice(free)
            continue
        for _ in range(OUTLOOK_ALIAS_TAG_SAMPLE_ATTEMPTS):
            tag = "".join(secrets.choice(alphabet) for _ in range(length))
            if tag not in used:
                return tag
        raise OutlookAliasTagBusyError("加号标签抽取冲突，请稍后重试")
    return None


def expand_outlook_aliases(credentials: list[dict[str, str]], entry: dict | None = None) -> list[dict[str, str]]:
    """保留导入的主号。加号别名只在领用时生成，保存和预览不再预展开。"""
    del entry
    expanded: list[dict[str, str]] = []
    seen: set[str] = set()
    for credential in credentials:
        email = str(credential.get("email") or "").strip()
        email_key = email.lower()
        if not email_key or email_key in seen:
            continue
        seen.add(email_key)
        expanded.append(dict(credential))
    return expanded


def _remember_submitted_alias(store: dict[str, dict[str, Any]], mailbox: dict[str, Any]) -> bool:
    """把已发出的加号写进当前状态。调用方必须已经持有状态锁。"""
    if not _normalize_bool(mailbox.get("_platform_email_sent"), False):
        return False
    address = str(mailbox.get("address") or "").strip().lower()
    parent = outlook_alias_parent_email(str(mailbox.get("login_email") or mailbox.get("alias_of") or address))
    tag = outlook_alias_tag_from_address(address, parent)
    if not tag or not parent:
        return False
    record = _outlook_record(store, parent)
    tags = _normalize_submitted_tags(record.get("submitted_tags"))
    if tag not in tags:
        tags.append(tag)
    record["submitted_tags"] = tags
    record["updated_at"] = datetime.now(timezone.utc).isoformat()
    _store_outlook_record(store, parent, record)
    return True


def mark_outlook_alias_submitted(mailbox: dict[str, Any]) -> bool:
    """平台请求发出后记住加号标签。原地址和未发出的领用不记。"""
    address = str(mailbox.get("address") or "").strip().lower()
    parent = outlook_alias_parent_email(str(mailbox.get("login_email") or mailbox.get("alias_of") or address))
    if not outlook_alias_tag_from_address(address, parent):
        return False
    noted = dict(mailbox)
    noted["_platform_email_sent"] = True
    with _outlook_state_transaction():
        store = _load_outlook_token_state()
        _remember_submitted_alias(store, noted)
        _save_outlook_token_state(store)
    return True


def _is_outlook_token_rate_limited(status_code: int, detail: str) -> bool:
    text = str(detail or "").lower()
    return status_code == 429 or "aadsts90055" in text or "excessive request rate" in text


def _retry_after_seconds(resp: Any, fallback: float) -> float:
    value = ""
    try:
        value = str(resp.headers.get("Retry-After") or "").strip()
    except Exception:
        value = ""
    if value:
        try:
            return max(0.5, min(30.0, float(value)))
        except ValueError:
            pass
    return fallback


def _normalize_outlook_pool(value: Any, entry: dict | None = None) -> list[dict[str, str]]:
    """邮箱池既支持纯文本，也支持对象列表。加号别名不在这里预展开。"""
    source = entry if isinstance(entry, dict) else {}
    items: list[dict[str, str]] = []
    if isinstance(value, str):
        items = parse_outlook_credentials(value)
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                items.extend(parse_outlook_credentials(item))
            elif isinstance(item, dict):
                email = _clean_outlook_value(item.get("email") or item.get("address") or "")
                client_id = _clean_outlook_value(item.get("client_id") or "")
                refresh_token = _clean_outlook_value(item.get("refresh_token") or "")
                if "@" in email and client_id and refresh_token:
                    login_email = _clean_outlook_value(item.get("login_email") or item.get("alias_of") or email)
                    payload = {
                        "email": email,
                        "password": _clean_outlook_value(item.get("password") or ""),
                        "client_id": client_id,
                        "refresh_token": refresh_token,
                    }
                    if login_email and login_email != email:
                        payload["login_email"] = login_email
                        payload["alias_of"] = _clean_outlook_value(item.get("alias_of") or login_email)
                    items.append(payload)
    return expand_outlook_aliases(items, source)


def _graph_folder_missing(status_code: int, detail: str) -> bool:
    text = str(detail or "").lower()
    return int(status_code) == 404 or "erroritemnotfound" in text or "errorfoldernotfound" in text


def _parse_imap_list_line(line: Any) -> tuple[str, str] | None:
    text = line.decode("utf-8", "replace") if isinstance(line, bytes) else str(line or "")
    match = re.search(r'\(([^)]*)\)\s+(?:NIL|"[^"]*")\s+(?:"((?:\\"|[^"])*)"|(\S+))\s*$', text)
    if not match:
        return None
    name = (match.group(2) or match.group(3) or "").replace('\\"', '"')
    if not name:
        return None
    return match.group(1) or "", name


def _decode_imap_modified_utf7(value: str) -> str:
    text = str(value or "")
    decoded: list[str] = []
    index = 0
    while index < len(text):
        if text[index] != "&":
            decoded.append(text[index])
            index += 1
            continue
        end = text.find("-", index + 1)
        if end < 0:
            decoded.append(text[index:])
            break
        token = text[index + 1:end]
        index = end + 1
        if not token:
            decoded.append("&")
            continue
        encoded = token.replace(",", "+")
        padding = "=" * ((4 - len(encoded) % 4) % 4)
        try:
            decoded.append(base64.b64decode(encoded + padding).decode("utf-16-be"))
        except Exception:
            decoded.append(f"&{token}-")
    return "".join(decoded)


def _encode_imap_modified_utf7(value: str) -> str:
    text = str(value or "")
    encoded: list[str] = []
    pending: list[str] = []

    def flush() -> None:
        if not pending:
            return
        raw = "".join(pending).encode("utf-16-be")
        token = base64.b64encode(raw).decode("ascii").rstrip("=").replace("/", ",")
        encoded.append(f"&{token}-")
        pending.clear()

    for char in text:
        code = ord(char)
        if 0x20 <= code <= 0x7E:
            flush()
            encoded.append("&-" if char == "&" else char)
        else:
            pending.append(char)
    flush()
    return "".join(encoded)


def imap_command_mailbox(name: str) -> str:
    """imaplib 不会给邮箱名加引号，也不会把非 ASCII 编成 modified UTF-7。

    LIST 返回的 ASCII 名已经是线上形式，里面的 & 不能再编一次。
    """
    text = str(name or "")
    if any(ord(char) < 0x20 or ord(char) > 0x7E for char in text):
        text = _encode_imap_modified_utf7(text)
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def imap_junk_mailbox_name(boxes: list[tuple[str, str]]) -> str | None:
    for flags, name in boxes:
        if "\\Junk" in str(flags or ""):
            return name
    wanted = {item.lower() for item in OUTLOOK_IMAP_JUNK_NAMES}
    for _flags, name in boxes:
        leaf = _decode_imap_modified_utf7(str(name or "")).replace("\\", "/").split("/")[-1].strip().strip('"')
        if leaf.lower() in wanted or leaf in OUTLOOK_IMAP_JUNK_NAMES:
            return name
    return None


def _merge_mail_messages(*groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for group in groups:
        for item in group or []:
            if not isinstance(item, dict):
                continue
            key = str(item.get("message_id") or "") or f"anon:{id(item)}"
            if key in seen:
                continue
            seen.add(key)
            merged.append(item)

    def sort_key(item: dict[str, Any]) -> float:
        received = item.get("received_at")
        if isinstance(received, datetime):
            current = received if received.tzinfo else received.replace(tzinfo=timezone.utc)
            return current.timestamp()
        return 0.0

    merged.sort(key=sort_key, reverse=True)
    return merged


def _messages_include_target(messages: list[dict[str, Any]], mailbox: dict[str, Any]) -> bool:
    target = str(mailbox.get("address") or "").strip()
    if not target:
        return True
    return any(_message_matches_email(item, target) for item in messages)


def _outlook_messages_have_current_code(messages: list[dict[str, Any]], mailbox: dict[str, Any]) -> bool:
    target = str(mailbox.get("address") or "").strip()
    for item in messages:
        if _message_before_code_boundary(mailbox, item):
            continue
        if target and not _message_matches_email(item, target):
            continue
        if _extract_code(item):
            return True
    return False


class OutlookTokenProvider(BaseMailProvider):
    """使用 refresh_token 读取 Outlook/Hotmail 邮箱验证码。

    邮箱池在应用配置里维护（mailboxes 字段，每行 email----password----client_id----refresh_token），
    create_mailbox() 从池中取下一个未使用的邮箱，wait_for_code() 用 refresh_token 换取 access_token
    后通过 Graph/IMAP 读取最新邮件。
    """

    name = "outlook_token"

    def __init__(self, entry: dict, conf: dict):
        super().__init__(conf, str(entry.get("provider_ref") or ""))
        self.label = str(entry.get("label") or self.provider_ref)
        self.pool = _normalize_outlook_pool(entry.get("mailboxes") or entry.get("pool"), entry)
        self.mode = str(entry.get("mode") or "auto").strip().lower() or "auto"
        if self.mode not in {"graph", "imap", "auto"}:
            self.mode = "auto"
        self.imap_host = str(entry.get("imap_host") or OUTLOOK_DEFAULT_IMAP_HOST).strip() or OUTLOOK_DEFAULT_IMAP_HOST
        self.message_limit = max(1, int(entry.get("message_limit") or 10))
        self.alias_enabled = _normalize_bool(entry.get("alias_enabled"), False)
        self.alias_include_original = _normalize_bool(entry.get("alias_include_original"), False)
        self._graph_junk_missing_logged = False
        self.session = _create_session(conf)

    def close(self) -> None:
        self.session.close()

    def _exchange_refresh_token(self, client_id: str, refresh_token: str, scope: str) -> str:
        max_attempts = 3
        last_detail = ""
        last_status = 0
        for attempt in range(max_attempts):
            timeout = self._request_timeout()
            with http_target_session_request(self.session, OUTLOOK_TOKEN_URL) as request_options:
                resp = self.session.post(
                    OUTLOOK_TOKEN_URL,
                    data={"client_id": client_id, "grant_type": "refresh_token", "refresh_token": refresh_token, "scope": scope},
                    headers=chrome146_headers({
                        "Content-Type": "application/x-www-form-urlencoded",
                        "User-Agent": self.conf["user_agent"],
                    }, include_defaults=False),
                    timeout=timeout,
                    verify=not proxy_settings.should_skip_ssl_verify(),
                    **request_options,
                )
            try:
                data = resp.json()
            except Exception:
                data = {}
            if resp.status_code == 200:
                access_token = str(data.get("access_token") or "").strip()
                if not access_token:
                    raise OutlookTokenError("OutlookToken 刷新响应缺少 access_token")
                return access_token

            detail = str(data.get("error_description") or data.get("error") or resp.text)
            last_detail = detail
            last_status = int(resp.status_code)
            if _is_outlook_token_rate_limited(last_status, detail) and attempt < max_attempts - 1:
                delay = _retry_after_seconds(resp, 1.5 * (attempt + 1) + random.uniform(0.5, 1.5))
                if not self._sleep_with_deadline(delay):
                    raise OutlookTokenRateLimitError(f"OutlookToken 刷新被 Microsoft 限流: HTTP {last_status}, {detail}")
                continue
            if _is_outlook_token_rate_limited(last_status, detail):
                raise OutlookTokenRateLimitError(f"OutlookToken 刷新被 Microsoft 限流: HTTP {last_status}, {detail}")
            raise OutlookTokenError(f"OutlookToken 刷新失败: HTTP {last_status}, {detail}")
        raise OutlookTokenRateLimitError(f"OutlookToken 刷新被 Microsoft 限流: HTTP {last_status}, {last_detail}")

    def _access_token(self, mailbox: dict[str, Any], client_id: str, refresh_token: str, scope: str) -> str:
        """缓存 access_token 复用：避免 wait_for_code 轮询时每次都换 token 触发限流。"""
        cache = mailbox.get("_outlook_token_cache")
        if not isinstance(cache, dict):
            cache = {}
            mailbox["_outlook_token_cache"] = cache
        cached = cache.get(scope)
        if isinstance(cached, tuple) and len(cached) == 2 and time.monotonic() < cached[1]:
            return str(cached[0])
        token = self._exchange_refresh_token(client_id, refresh_token, scope)
        cache[scope] = (token, time.monotonic() + 600)
        return token

    def _mailbox_payload(self, credential: dict[str, str], address: str, login_email: str, alias_of: str = "") -> dict[str, Any]:
        return {
            "provider": self.name,
            "provider_ref": self.provider_ref,
            "address": address,
            "login_email": login_email,
            "alias_of": alias_of,
            "label": self.label,
            "password": credential.get("password", ""),
            "client_id": credential["client_id"],
            "refresh_token": credential["refresh_token"],
        }

    def _claim_outlook_address(self, store: dict[str, dict[str, Any]], credential: dict[str, str], address: str, parent: str) -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        key = str(address or "").strip().lower()
        record = _outlook_record(store, key)
        record["state"] = "in_use"
        record["reason"] = ""
        record["updated_at"] = now
        _store_outlook_record(store, key, record)
        if self.alias_enabled and outlook_alias_supported(parent):
            parent_record = _outlook_record(store, parent)
            parent_record["family_lease"] = {"address": key, "updated_at": now}
            parent_record["updated_at"] = now
            _store_outlook_record(store, parent, parent_record)
        login_email = parent if key != parent else str(credential.get("login_email") or parent)
        alias_of = parent if key != parent else str(credential.get("alias_of") or "")
        payload = self._mailbox_payload(credential, key, login_email, alias_of)
        payload["alias_enabled"] = bool(self.alias_enabled and outlook_alias_supported(parent))
        return payload

    def _claim_outlook_credential(self, store: dict[str, dict[str, Any]], credential: dict[str, str]) -> dict[str, Any] | None:
        parent = _credential_parent_email(credential)
        if not self.alias_enabled or not outlook_alias_supported(parent):
            if not _outlook_credential_available(store, credential):
                return None
            address = str(credential.get("email") or "").strip()
            return self._claim_outlook_address(store, credential, address, outlook_alias_parent_email(address))
        if _outlook_family_blocked(store, parent):
            return None
        if self.alias_include_original:
            original = dict(credential)
            original["email"] = parent
            original.pop("login_email", None)
            original.pop("alias_of", None)
            if _outlook_credential_available(store, original):
                return self._claim_outlook_address(store, credential, parent, parent)
        occupied = set(outlook_occupied_alias_tags(parent, store))
        occupied.update(self._imported_plus_tags(parent))
        tag = generate_outlook_alias_tag(parent, occupied)
        if not tag:
            logger.warning("OutlookToken 主号 %s 的本地部分放不下 2 位加号标签，已跳过", parent)
            return None
        return self._claim_outlook_address(store, credential, outlook_alias_address(parent, tag), parent)

    def create_mailbox(self, username: str | None = None) -> dict[str, Any]:
        if not self.pool:
            raise RuntimeError("OutlookToken 邮箱池为空，请在邮箱配置中导入 email----password----client_id----refresh_token")
        with _outlook_state_transaction():
            store = _load_outlook_token_state()
            mailbox = None
            for credential in self.pool:
                mailbox = self._claim_outlook_credential(store, credential)
                if mailbox is not None:
                    break
            if mailbox is None:
                raise RuntimeError(f"[{self.label}] OutlookToken 邮箱池暂无可用邮箱（共 {len(self.pool)} 个，已用尽或全部占用/失效），请导入新邮箱或重置池状态")
            _save_outlook_token_state(store)
        return mailbox

    def _imported_plus_tags(self, parent: str) -> set[str]:
        parent_key = outlook_alias_parent_email(parent)
        tags: set[str] = set()
        for credential in self.pool:
            email = str(credential.get("email") or "")
            if outlook_alias_parent_email(email) != parent_key:
                continue
            tag = outlook_alias_tag_from_address(email, parent_key)
            if tag:
                tags.add(tag)
        return tags

    def _read_graph_page(self, access_token: str, url: str, params: dict[str, Any] | None) -> tuple[list[dict[str, Any]], str]:
        with http_target_session_request(self.session, url) as request_options:
            resp = self.session.get(
                url,
                headers=chrome146_headers({
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                    "User-Agent": self.conf["user_agent"],
                }, include_defaults=False),
                params=params,
                timeout=self._request_timeout(),
                verify=not proxy_settings.should_skip_ssl_verify(),
                **request_options,
            )
        try:
            data = resp.json()
        except Exception:
            data = {}
        if resp.status_code != 200:
            detail = data.get("error", {}).get("message") if isinstance(data.get("error"), dict) else resp.text
            if _graph_folder_missing(resp.status_code, str(detail or "")):
                raise OutlookFolderMissing(str(detail or resp.status_code))
            raise RuntimeError(f"OutlookToken Graph 失败: HTTP {resp.status_code}, {detail}")
        items = data.get("value") if isinstance(data, dict) else None
        messages = [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []
        next_url = str(data.get("@odata.nextLink") or "").strip() if isinstance(data, dict) else ""
        return messages, next_url

    def _read_graph_folder(self, access_token: str, url: str) -> list[dict[str, Any]]:
        """按 message_limit 翻页，直到早于验证码边界或达到安全上限。"""
        mailbox = getattr(self, "_graph_fetch_mailbox", None)
        boundary = _effective_code_boundary(mailbox if isinstance(mailbox, dict) else None)
        collected: list[dict[str, Any]] = []
        next_url = ""
        reached = boundary is None
        seen_urls: set[str] = set()
        saw_folder = False
        hops = 0
        while len(collected) < OUTLOOK_CODE_SEARCH_MAX_MESSAGES:
            hops += 1
            if hops > OUTLOOK_CODE_SEARCH_MAX_MESSAGES:
                reached = False
                break
            request_url = next_url or url
            if request_url in seen_urls:
                reached = False
                break
            seen_urls.add(request_url)
            params = None if next_url else {
                "$top": self.message_limit,
                "$orderby": "receivedDateTime desc",
                "$select": OUTLOOK_GRAPH_MESSAGE_SELECT,
            }
            try:
                items, next_url = self._read_graph_page(access_token, request_url, params)
            except Exception:
                # 第一页失败仍向外抛。后面的页失败时保留已读邮件，并算未查完。
                if saw_folder:
                    reached = False
                    break
                raise
            saw_folder = True
            if not items:
                if next_url and boundary is not None:
                    continue
                reached = True
                break
            collected.extend(items)
            if boundary is None:
                reached = True
                break
            oldest = _oldest_graph_received_at(items)
            if oldest is not None and oldest < boundary:
                reached = True
                break
            if not next_url:
                reached = True
                break
        self._last_folder_reached = reached
        return collected[:OUTLOOK_CODE_SEARCH_MAX_MESSAGES]

    def _read_graph(self, access_token: str) -> list[dict[str, Any]]:
        return self._read_graph_folder(access_token, OUTLOOK_GRAPH_INBOX_MESSAGES_URL)

    @staticmethod
    def _graph_sender(message: dict[str, Any]) -> str:
        sender = message.get("from") or {}
        if isinstance(sender, dict):
            address = sender.get("emailAddress") or {}
            if isinstance(address, dict):
                return str(address.get("address") or address.get("name") or "")
        return ""

    @staticmethod
    def _graph_recipients(message: dict[str, Any]) -> list[str]:
        recipients: list[str] = []
        for key in ("toRecipients", "ccRecipients"):
            values = message.get(key)
            if not isinstance(values, list):
                continue
            for item in values:
                address = item.get("emailAddress") if isinstance(item, dict) and isinstance(item.get("emailAddress"), dict) else {}
                value = str(address.get("address") or address.get("name") or "").strip()
                if value:
                    recipients.append(value)
        return recipients

    @staticmethod
    def _graph_header_values(message: dict[str, Any], names: set[str]) -> list[str]:
        headers = message.get("internetMessageHeaders")
        if not isinstance(headers, list):
            return []
        values: list[str] = []
        for header in headers:
            if not isinstance(header, dict):
                continue
            name = str(header.get("name") or "").strip().lower()
            if name not in names:
                continue
            value = str(header.get("value") or "").strip()
            if value:
                values.append(value)
        return values

    def _normalize_graph_item(self, mailbox: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
        body = item.get("body") if isinstance(item.get("body"), dict) else {}
        content_type = str(body.get("contentType") or "").lower()
        content = str(body.get("content") or "")
        text_content = content if content_type != "html" else str(item.get("bodyPreview") or "")
        html_content = content if content_type == "html" else ""
        recipients = self._graph_recipients(item)
        recipients.extend(self._graph_header_values(item, {"to", "cc"}))
        return {
            "provider": self.name,
            "mailbox": mailbox["address"],
            "message_id": str(item.get("id") or ""),
            "subject": str(item.get("subject") or ""),
            "sender": self._graph_sender(item),
            "to": recipients,
            "cc": self._graph_header_values(item, {"cc"}),
            "delivered_to": self._graph_header_values(item, {"delivered-to"}),
            "x_forwarded_to": self._graph_header_values(item, {"x-forwarded-to"}),
            "x_original_to": self._graph_header_values(item, {"x-original-to"}),
            "text_content": text_content,
            "html_content": html_content,
            "received_at": _parse_received_at(item.get("receivedDateTime")),
            "raw": item,
        }

    def _graph_messages(self, mailbox: dict[str, Any], access_token: str) -> list[dict[str, Any]]:
        """收件箱和垃圾箱翻到验证码边界后按时间合并。垃圾箱不存在时只读收件箱。"""
        previous = getattr(self, "_graph_fetch_mailbox", None)
        self._graph_fetch_mailbox = mailbox
        self._graph_junk_missing = False
        try:
            self._last_folder_reached = True
            inbox_items = self._read_graph_folder(access_token, OUTLOOK_GRAPH_INBOX_MESSAGES_URL)
            self._graph_inbox_reached = bool(self._last_folder_reached)
            junk_items: list[dict[str, Any]] = []
            try:
                self._last_folder_reached = True
                junk_items = self._read_graph_folder(access_token, OUTLOOK_GRAPH_JUNK_MESSAGES_URL)
            except OutlookFolderMissing:
                self._graph_junk_missing = True
                self._graph_junk_reached = False
                if not self._graph_junk_missing_logged:
                    logger.warning("OutlookToken Graph 垃圾箱不可用，仅使用收件箱")
                    self._graph_junk_missing_logged = True
            except Exception:
                if not inbox_items:
                    raise
                self._graph_junk_reached = False
            else:
                self._graph_junk_reached = bool(self._last_folder_reached)
        finally:
            self._graph_fetch_mailbox = previous
        inbox = [self._normalize_graph_item(mailbox, item) for item in inbox_items]
        junk = [self._normalize_graph_item(mailbox, item) for item in junk_items]
        return _merge_mail_messages(inbox, junk)

    def _open_imap_ssl(self, proxy: str = ""):
        return _ProxiedIMAP4SSL(
            self.imap_host,
            timeout=self._request_timeout(),
            proxy=proxy,
        )

    def _imap_list_mailboxes(self, imap) -> list[tuple[str, str]]:
        try:
            status, data = imap.list()
        except Exception as exc:
            raise OutlookMailboxReadError("OutlookToken IMAP 无法列出文件夹") from exc
        if status != "OK":
            raise OutlookMailboxReadError(f"OutlookToken IMAP 列出文件夹失败: {status}")
        if not data:
            return []
        boxes: list[tuple[str, str]] = []
        for line in data:
            parsed = _parse_imap_list_line(line)
            if parsed:
                boxes.append(parsed)
        return boxes

    def _imap_fetch_uids(self, imap, mailbox: dict[str, Any], uids: list[bytes]) -> tuple[list[dict[str, Any]], int]:
        messages: list[dict[str, Any]] = []
        failed = 0
        for uid in uids:
            status, fetched = imap.uid("fetch", uid, "(INTERNALDATE RFC822)")
            if status != "OK":
                failed += 1
                continue
            raw_payload = b""
            internal_received = None
            for part in fetched or []:
                if not (isinstance(part, tuple) and isinstance(part[1], bytes)):
                    continue
                meta = part[0].decode("utf-8", "replace") if isinstance(part[0], bytes) else str(part[0])
                match = re.search(r'INTERNALDATE "([^"]+)"', meta)
                if match:
                    try:
                        parsed = imaplib.Internaldate2tuple(b'INTERNALDATE "' + match.group(1).encode() + b'"')
                        if parsed:
                            internal_received = datetime.fromtimestamp(time.mktime(parsed), tz=timezone.utc)
                    except Exception:
                        internal_received = None
                raw_payload = part[1]
                break
            if not raw_payload:
                failed += 1
                continue
            messages.append(self._parse_imap_message(mailbox, raw_payload, internal_received))
        return messages, failed

    def _imap_fetch_selected(self, imap, mailbox: dict[str, Any]) -> list[dict[str, Any]]:
        status, data = imap.uid("search", None, "ALL")
        if status != "OK":
            self._last_folder_reached = False
            return []
        if not data or not data[0]:
            self._last_folder_reached = True
            return []
        uids = data[0].split()
        boundary = _effective_code_boundary(mailbox)
        if boundary is None:
            messages, failed = self._imap_fetch_uids(imap, mailbox, list(reversed(uids[-self.message_limit:])))
            self._last_folder_reached = failed == 0
            return messages
        collected: list[dict[str, Any]] = []
        index = len(uids)
        reached = False
        failed = 0
        while index > 0 and len(collected) < OUTLOOK_CODE_SEARCH_MAX_MESSAGES:
            start = max(0, index - self.message_limit)
            batch = uids[start:index]
            index = start
            batch_messages, batch_failed = self._imap_fetch_uids(imap, mailbox, list(reversed(batch)))
            failed += batch_failed
            collected.extend(batch_messages)
            oldest = _oldest_message_received_at(batch_messages)
            if oldest is not None and oldest < boundary:
                reached = failed == 0
                break
            if index == 0:
                reached = failed == 0
                break
        self._last_folder_reached = reached
        return collected[:OUTLOOK_CODE_SEARCH_MAX_MESSAGES]

    def _imap_fetch_folder(self, imap, mailbox: dict[str, Any], folder: str, required: bool) -> list[dict[str, Any]]:
        try:
            status, _ = imap.select(imap_command_mailbox(folder), readonly=True)
        except Exception:
            status = "NO"
        if status != "OK":
            if required:
                raise RuntimeError(f"OutlookToken IMAP select {folder} 失败")
            self._last_folder_reached = False
            logger.warning("OutlookToken IMAP 文件夹不可用，已跳过: %s", folder)
            return []
        return self._imap_fetch_selected(imap, mailbox)

    def _imap_messages(self, mailbox: dict[str, Any], access_token: str) -> list[dict[str, Any]]:
        """收件箱和垃圾箱翻到验证码边界，最新在前。"""
        auth_string = f"user={mailbox.get('login_email') or mailbox['address']}\x01auth=Bearer {access_token}\x01\x01"
        imap = self._open_imap_ssl(_mail_imap_proxy(self.conf))
        try:
            imap.authenticate("XOAUTH2", lambda _: auth_string.encode("utf-8"))
            self._last_folder_reached = True
            inbox = self._imap_fetch_folder(imap, mailbox, "INBOX", required=True)
            self._imap_inbox_reached = bool(self._last_folder_reached)
            boxes = self._imap_list_mailboxes(imap)
            junk_name = imap_junk_mailbox_name(boxes)
            junk: list[dict[str, Any]] = []
            if junk_name and junk_name.upper() != "INBOX":
                self._imap_junk_absent = False
                self._last_folder_reached = True
                junk = self._imap_fetch_folder(imap, mailbox, junk_name, required=False)
                self._imap_junk_reached = bool(self._last_folder_reached)
            else:
                self._imap_junk_absent = True
                self._imap_junk_reached = True
            return _merge_mail_messages(inbox, junk)
        finally:
            try:
                imap.logout()
            except Exception:
                pass

    def _parse_imap_message(self, mailbox: dict[str, Any], raw: bytes, internal_received: datetime | None = None) -> dict[str, Any]:
        message = message_from_bytes(raw, policy=policy.default)
        try:
            received = internal_received or _parse_received_at(parsedate_to_datetime(str(message.get("Date") or "")))
        except Exception:
            received = internal_received
        plain: list[str] = []
        html: list[str] = []
        for part in (message.walk() if message.is_multipart() else [message]):
            if part.get_content_maintype() == "multipart":
                continue
            try:
                payload = part.get_content()
            except Exception:
                continue
            if not payload:
                continue
            if part.get_content_type() == "text/html":
                html.append(str(payload))
            else:
                plain.append(str(payload))

        def _decode(value: str | None) -> str:
            if not value:
                return ""
            try:
                return str(make_header(decode_header(value)))
            except Exception:
                return value

        return {
            "provider": self.name,
            "mailbox": mailbox["address"],
            "message_id": _decode(str(message.get("Message-ID") or "")),
            "subject": _decode(str(message.get("Subject") or "")),
            "sender": _decode(str(message.get("From") or "")),
            "to": _decode(str(message.get("To") or "")),
            "cc": _decode(str(message.get("Cc") or "")),
            "delivered_to": _decode(str(message.get("Delivered-To") or "")),
            "x_forwarded_to": _decode(str(message.get("X-Forwarded-To") or "")),
            "x_original_to": _decode(str(message.get("X-Original-To") or "")),
            "text_content": "\n".join(plain).strip(),
            "html_content": "\n".join(html).strip(),
            "received_at": received,
            "raw": None,
        }

    def _mark_outlook_search(self, mailbox: dict[str, Any], incomplete: bool) -> None:
        if isinstance(mailbox, dict):
            mailbox["_outlook_search_incomplete"] = bool(incomplete)

    def _graph_search_is_complete(self) -> bool:
        inbox_ok = bool(getattr(self, "_graph_inbox_reached", False))
        junk_missing = bool(getattr(self, "_graph_junk_missing", False))
        junk_ok = bool(getattr(self, "_graph_junk_reached", False))
        if self.mode == "graph":
            return inbox_ok and (junk_ok or junk_missing)
        return inbox_ok and junk_ok and not junk_missing

    def _graph_search_incomplete(self, *, found_code: bool = False) -> bool:
        if found_code:
            return False
        return not self._graph_search_is_complete()

    def _combined_search_incomplete(self) -> bool:
        """IMAP 已经接上时，收件箱必须由 IMAP 查完。垃圾箱只有 IMAP 确认没有，或 Graph 已经覆盖/确认没有时才算查完。"""
        inbox_ok = bool(getattr(self, "_imap_inbox_reached", False))
        if getattr(self, "_imap_junk_absent", False):
            junk_ok = self.mode == "imap" or bool(getattr(self, "_graph_junk_reached", False)) or bool(getattr(self, "_graph_junk_missing", False))
        else:
            junk_ok = bool(getattr(self, "_imap_junk_reached", False))
        return not (inbox_ok and junk_ok)

    def fetch_recent_messages(self, mailbox: dict[str, Any]) -> list[dict[str, Any]]:
        """拉取覆盖验证码边界的邮件（最新在前），供 wait_for_code 逐封扫描验证码。"""
        client_id = str(mailbox.get("client_id") or "").strip()
        refresh_token = str(mailbox.get("refresh_token") or "").strip()
        if not client_id or not refresh_token:
            raise RuntimeError("OutlookToken mailbox 缺少 client_id 或 refresh_token")
        errors: list[str] = []
        graph_error: Exception | None = None
        graph_messages: list[dict[str, Any]] | None = None
        if isinstance(mailbox, dict):
            mailbox.pop("_outlook_search_incomplete", None)
        if self.mode in {"graph", "auto"}:
            try:
                access_token = self._access_token(mailbox, client_id, refresh_token, OUTLOOK_GRAPH_SCOPE)
                graph_messages = self._graph_messages(mailbox, access_token)
                if self.mode == "graph" or _outlook_messages_have_current_code(graph_messages, mailbox):
                    self._mark_outlook_search(mailbox, self._graph_search_incomplete(found_code=self.mode != "graph"))
                    return graph_messages
                errors.append("graph: no matching recipient")
            except Exception as error:
                graph_error = error
                if self.mode == "graph" and not _is_outlook_scope_denied(error):
                    if isinstance(error, _MailWaitDeadlineExceeded):
                        self._mark_outlook_search(mailbox, True)
                    raise
                errors.append(f"graph: {error}")
                self._mark_outlook_search(mailbox, True)
        should_try_imap = self.mode in {"imap", "auto"} or (
            self.mode == "graph" and graph_error is not None and _is_outlook_scope_denied(graph_error)
        )
        if should_try_imap:
            try:
                access_token = self._access_token(mailbox, client_id, refresh_token, OUTLOOK_IMAP_SCOPE)
                imap_messages = self._imap_messages(mailbox, access_token)
                self._mark_outlook_search(mailbox, self._combined_search_incomplete())
                if graph_messages:
                    return _merge_mail_messages(graph_messages, imap_messages)
                return imap_messages
            except Exception as error:
                if self.mode == "imap":
                    if isinstance(error, _MailWaitDeadlineExceeded):
                        self._mark_outlook_search(mailbox, True)
                    raise
                errors.append(f"imap: {error}")
                self._mark_outlook_search(mailbox, True)
                if self.mode == "graph":
                    raise RuntimeError("; ".join(errors)) from error
        if graph_messages is not None:
            # Graph 已经查完收件箱和垃圾箱时，IMAP 连不上不再把这次搜索算成不完整。
            self._mark_outlook_search(mailbox, not self._graph_search_is_complete())
            return graph_messages
        if errors:
            raise RuntimeError("; ".join(errors))
        return []

    def fetch_latest_message(self, mailbox: dict[str, Any]) -> dict[str, Any] | None:
        messages = self.fetch_recent_messages(mailbox)
        return messages[0] if messages else None

    def wait_for_code(self, mailbox: dict[str, Any]) -> str | None:
        """轮询时遍历最近 N 封邮件，逐封提取验证码，避免最新一封是广告/安全提醒时错过验证码。"""
        seen_value = mailbox.setdefault("_seen_code_message_refs", [])
        if not isinstance(seen_value, list):
            seen_value = []
            mailbox["_seen_code_message_refs"] = seen_value
        seen_refs = {str(item) for item in seen_value}

        previous_deadline = self._start_wait_window()
        try:
            target_address = str(mailbox.get("address") or "").strip()
            while True:
                remaining = self._remaining_wait_seconds()
                if remaining is not None and remaining <= 0:
                    return None
                try:
                    messages = self.fetch_recent_messages(mailbox)
                except _MailWaitDeadlineExceeded:
                    return None
                for message in messages:
                    if _message_before_code_boundary(mailbox, message):
                        continue
                    if target_address and not _message_matches_email(message, target_address):
                        continue
                    ref = _message_tracking_ref(message)
                    if ref in seen_refs:
                        continue
                    code = _extract_code(message)
                    if code:
                        seen_value.append(ref)
                        return code
                    seen_refs.add(ref)
                if not self._sleep_with_deadline(max(0.2, self.conf["wait_interval"])):
                    return None
        finally:
            self._restore_wait_window(previous_deadline)


def _entries(mail_config: dict) -> list[dict]:
    result: list[dict] = []
    counters: dict[str, int] = {}
    seen_provider_refs: dict[str, int] = {}
    for item in validate_provider_entries(mail_config.get("providers")):
        idx = len(result) + 1
        t = item.get("type", "")
        cnt = counters.get(t, 0) + 1
        counters[t] = cnt
        label = f"{t}#{idx}"
        stable_id = str(item.get("id") or item.get("provider_id") or "").strip()
        configured_ref = str(item.get("provider_ref") or "").strip()
        provider_ref = configured_ref or (
            f"{item['type']}:{stable_id}" if stable_id else f"{item['type']}#{idx}"
        )
        previous_index = seen_provider_refs.get(provider_ref)
        if previous_index is not None:
            raise RuntimeError(f"mail.providers duplicate provider id: {provider_ref}")
        seen_provider_refs[provider_ref] = idx
        result.append({**item, "provider_ref": provider_ref, "label": label})
    return result


def _enabled_entries(mail_config: dict) -> list[dict]:
    items = [item for item in _entries(mail_config) if _normalize_bool(item.get("enable"), True)]
    if not items:
        raise RuntimeError("mail.providers 没有启用的 provider")
    return items


def _next_entry(mail_config: dict) -> dict:
    global provider_index
    items = _enabled_entries(mail_config)
    if len(items) == 1:
        return dict(items[0])
    with provider_lock:
        value = dict(items[provider_index % len(items)])
        provider_index = (provider_index + 1) % len(items)
        return value


def _create_provider(mail_config: dict, provider: str = "", provider_ref: str = "") -> BaseMailProvider:
    entry = next((dict(item) for item in _entries(mail_config) if provider_ref and item["provider_ref"] == provider_ref), None)
    if provider_ref and entry is None:
        raise RuntimeError(f"mail provider not found: {provider_ref}")
    if provider == ReMailProvider.name and not provider_ref:
        remail_enabled = [dict(item) for item in _enabled_entries(mail_config) if item["type"] == ReMailProvider.name]
        if len(remail_enabled) > 1:
            raise RuntimeError("mail provider ambiguous: remail requires provider_ref when multiple remail sources are enabled")
    entry = entry or next((dict(item) for item in _enabled_entries(mail_config) if provider and item["type"] == provider), None) or _next_entry(mail_config)
    if entry["type"] not in ALLOWED_MAIL_PROVIDER_TYPES:
        raise RuntimeError(f"不支持的 mail.provider: {entry['type']}")
    conf = _config(mail_config)
    if entry["type"] == "yyds_mail":
        return YydsMailProvider(entry, conf)
    if entry["type"] == "icloud_api":
        return ICloudApiProvider(entry, conf)
    if entry["type"] == "remail":
        return ReMailProvider(entry, conf)
    if entry["type"] == "outlook_token":
        return OutlookTokenProvider(entry, conf)
    raise RuntimeError(f"不支持的 mail.provider: {entry['type']}")


def create_mailbox(mail_config: dict, username: str | None = None) -> dict:
    enabled = _enabled_entries(mail_config)
    errors: list[str] = []
    start_entry = _next_entry(mail_config)
    ordered_entries = [start_entry] + [
        dict(entry)
        for entry in enabled
        if str(entry.get("provider_ref") or "") != str(start_entry.get("provider_ref") or "")
    ]
    for entry in ordered_entries:
        provider = None
        try:
            provider = _create_provider(
                mail_config,
                provider=str(entry.get("type") or ""),
                provider_ref=str(entry.get("provider_ref") or ""),
            )
            mailbox = provider.create_mailbox(username)
            mailbox["_code_not_before"] = datetime.now(timezone.utc)
            return mailbox
        except Exception as error:
            provider_name = str(entry.get("type") or "unknown")
            errors.append(f"{provider_name}: {redact_register_log_text(error)}")
        finally:
            if provider is not None:
                provider.close()
    detail = "；".join(errors)
    raise RuntimeError(detail or "所有启用的邮箱提供商均无法创建邮箱")


def _create_provider_from_mailbox(mail_config: dict, mailbox: dict) -> BaseMailProvider | None:
    if str(mailbox.get("provider") or "") != ReMailProvider.name:
        return None
    snapshot = mailbox.get(REMAIL_PROVIDER_SNAPSHOT_KEY)
    if not isinstance(snapshot, dict):
        return None
    entry = dict(snapshot)
    provider_ref = str(mailbox.get("provider_ref") or entry.get("provider_ref") or "").strip()
    if provider_ref:
        entry["provider_ref"] = provider_ref
    entry["type"] = ReMailProvider.name
    if not str(entry.get("id") or "").strip() and provider_ref.startswith(f"{ReMailProvider.name}:"):
        entry["id"] = provider_ref.split(":", 1)[1]
    return ReMailProvider(entry, _config(mail_config))


def wait_for_code(mail_config: dict, mailbox: dict) -> str | None:
    provider = _create_provider_from_mailbox(mail_config, mailbox)
    if provider is None:
        provider = _create_provider(mail_config, str(mailbox.get("provider") or ""), str(mailbox.get("provider_ref") or ""))
    try:
        return provider.wait_for_code(mailbox)
    finally:
        provider.close()


def _outlook_mailbox_parent(mailbox: dict[str, Any]) -> str:
    return outlook_alias_parent_email(str(mailbox.get("login_email") or mailbox.get("alias_of") or mailbox.get("address") or ""))


def _outlook_refresh_credential_failure(error: Exception | str | None, reason: str) -> bool:
    """只认 Outlook 刷新凭据失败。ChatGPT 换票原文里的 access_token 不能算。"""
    if isinstance(error, OutlookTokenError):
        return True
    text = str(reason or "")
    return "OutlookToken 刷新失败" in text or "OutlookToken 刷新响应缺少 access_token" in text


def _outlook_failure_state(error: Exception | str | None, reason: str) -> tuple[str, bool]:
    if isinstance(error, OutlookTokenRateLimitError) or "AADSTS90055" in reason or "HTTP 429" in reason or "Microsoft 限流" in reason:
        return "failed", False
    if _outlook_refresh_credential_failure(error, reason):
        return "token_invalid", True
    # OpenAI 「邮箱登录流不支持无密码登录」不是 Outlook 需要重新登录。
    if "login_required" in reason:
        return "login_required", True
    return "failed", False


def _outlook_timeout_can_retire(mailbox: dict[str, Any]) -> bool:
    if not _normalize_bool(mailbox.get("alias_enabled"), False):
        return False
    if _normalize_bool(mailbox.get("_outlook_search_incomplete"), False):
        return False
    return True


def _record_outlook_no_code(store: dict[str, dict[str, Any]], mailbox: dict[str, Any], reason: str) -> None:
    address = str(mailbox.get("address") or "").strip().lower()
    parent = _outlook_mailbox_parent(mailbox)
    now = datetime.now(timezone.utc).isoformat()
    record = _outlook_record(store, address)
    record["state"] = "failed"
    record["reason"] = reason
    record["updated_at"] = now
    _store_outlook_record(store, address, record)
    parent_record = _outlook_record(store, parent)
    streak = _normalize_no_code_streak(parent_record.get("no_code_streak")) + 1
    parent_record["no_code_streak"] = streak
    parent_record["updated_at"] = now
    lease = _normalize_family_lease(parent_record.get("family_lease"))
    if lease and lease["address"] == address:
        parent_record.pop("family_lease", None)
    if streak >= OUTLOOK_ALIAS_NO_CODE_RETIRE_STREAK:
        parent_record["state"] = "retired"
        parent_record["reason"] = f"no_code_streak={streak}"
        logger.warning("OutlookToken 主号连续 %s 次未收到验证码，已停用: %s", streak, parent)
    _store_outlook_record(store, parent, parent_record)


def _mark_outlook_mailbox_result(mailbox: dict[str, Any], *, success: bool, error: Exception | str | None = None) -> bool:
    address = str(mailbox.get("address") or "").strip()
    if not address:
        return False
    parent = _outlook_mailbox_parent(mailbox)
    code = str(getattr(error, "code", "") or "")
    code_received = _normalize_bool(mailbox.get("_code_received"), False)
    reason = str(error or "").strip()
    now = datetime.now(timezone.utc).isoformat()
    with _outlook_state_transaction():
        store = _load_outlook_token_state()
        _remember_submitted_alias(store, mailbox)
        if success or code_received:
            parent_record = _outlook_record(store, parent)
            if parent_record.get("no_code_streak"):
                parent_record.pop("no_code_streak", None)
                parent_record["updated_at"] = now
                _store_outlook_record(store, parent, parent_record)
        if success:
            record = _outlook_record(store, address)
            record["state"] = "used"
            record["reason"] = ""
            record["updated_at"] = now
            _store_outlook_record(store, address, record)
            _clear_family_lease(store, parent, address)
            _save_outlook_token_state(store)
            return True
        if code in OUTLOOK_NO_CODE_TIMEOUT_CODES and not code_received and _outlook_timeout_can_retire(mailbox):
            _record_outlook_no_code(store, mailbox, reason or code)
            _save_outlook_token_state(store)
            return True
        state, cascade = _outlook_failure_state(error, reason)
        record = _outlook_record(store, address)
        record["state"] = state
        record["reason"] = reason
        record["updated_at"] = now
        _store_outlook_record(store, address, record)
        if cascade:
            login_email = str(mailbox.get("login_email") or mailbox.get("alias_of") or "").strip()
            if login_email and login_email.lower() != address.lower():
                parent_record = _outlook_record(store, login_email)
                parent_record["state"] = state
                parent_record["reason"] = reason
                parent_record["updated_at"] = now
                _store_outlook_record(store, login_email, parent_record)
        _clear_family_lease(store, parent, address)
        _save_outlook_token_state(store)
    return True


def mark_mailbox_result(mailbox: dict, *, success: bool, error: Exception | str | None = None) -> bool:
    """注册流程结束后更新邮箱池状态。

    Remail 失败时会按终态原因写入 dead mailbox；outlook_token 成功标记 used，失败时若是
    token 失效标记 token_invalid，登录态问题标记 login_required，其余失败标记 failed
    （可重试但不会自动再次领用）。iCloud 外部取码服务会在拿到验证码后回传 result，
    未拿到验证码则释放回池。
    """
    provider_name = str(mailbox.get("provider") or "")
    if provider_name == ReMailProvider.name:
        if not success:
            reason = _remail_dead_reason(error)
            if reason:
                _record_remail_dead_mailbox(mailbox, reason)
        return True
    if provider_name == ICloudApiProvider.name:
        if success or _normalize_bool(mailbox.get("_code_received"), False):
            ok = _icloud_mailbox_finalize(mailbox, success=success, error=error, note="注册流程结束")
        else:
            ok = _icloud_mailbox_finalize(mailbox, success=False, error=error, note="注册流程提前放弃", release_only=True)
        if not ok:
            detail = str(mailbox.get("_icloud_finalize_error") or "iCloud Privacy Mail 邮箱状态回写失败").strip()
            raise RuntimeError(detail)
        return True
    if provider_name != OutlookTokenProvider.name:
        return True
    return _mark_outlook_mailbox_result(mailbox, success=success, error=error)


def release_mailbox(mailbox: dict) -> bool:
    """把邮箱从占用态释放回可用（用于流程主动放弃且未消费验证码时）。"""
    try:
        provider_name = str(mailbox.get("provider") or "")
        if provider_name == OutlookTokenProvider.name:
            _release_outlook_token_state(str(mailbox.get("address") or ""))
            return True
        if provider_name == ICloudApiProvider.name:
            return _icloud_mailbox_finalize(mailbox, success=False, note="注册流程主动放弃", release_only=True)
        return True
    except Exception:
        return False


def get_existing_mailbox(mail_config: dict, email: str) -> dict:
    """通过管理员密码获取已有邮箱地址的 JWT，用于查询邮件。"""
    enabled = _enabled_entries(mail_config)
    errors: list[str] = []
    for entry in enabled:
        provider = None
        provider_name = str(entry.get("type") or "unknown")
        try:
            provider = _create_provider(
                mail_config,
                provider=provider_name,
                provider_ref=str(entry.get("provider_ref") or ""),
            )
            getter = getattr(provider, "get_existing_mailbox", None)
            if not callable(getter):
                raise RuntimeError(f"邮箱提供商 {provider_name} 不支持查询已有邮箱")
            return getter(email)
        except Exception as error:
            errors.append(f"{provider_name}: {redact_register_log_text(error)}")
        finally:
            if provider is not None:
                provider.close()
    detail = "；".join(errors)
    raise RuntimeError(detail or "所有启用的邮箱提供商均无法查询已有邮箱")
