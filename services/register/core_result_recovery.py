from __future__ import annotations

import inspect
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any, Callable

from services.account_service import account_service as default_account_service
from services.register import openai_register
from services.register.errors import RegisterError, format_register_error


MAX_RECOVERY_BATCH = 20
MAX_RETRY_DELAY_SECONDS = 60 * 60
MAX_RECOVERY_RETRY_COUNT = 5
TERMINAL_RECOVERY_STATUSES = {"failed_terminal"}
_reconcile_lock = RLock()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_text() -> str:
    return _now().isoformat()


def _parse_time(value: object) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _secret_values(row: dict[str, Any]) -> list[str]:
    return [
        str(row.get(key) or "").strip()
        for key in ("access_token", "refresh_token", "id_token", "password")
        if str(row.get(key) or "").strip()
    ]


def _safe_error(error: object, row: dict[str, Any]) -> str:
    del row
    return str(error or "")


def _read_rows() -> list[dict[str, Any]]:
    with openai_register.register_core_results_lock:
        return deepcopy(openai_register._pending_core_result_rows())


def _update_row(access_token: str, updates: dict[str, Any]) -> bool:
    with openai_register.register_core_results_lock:
        rows = openai_register._pending_core_result_rows()
        changed = False
        for row in rows:
            if str(row.get("access_token") or "").strip() != access_token:
                continue
            row.update(updates)
            changed = True
            break
        if changed:
            openai_register.write_pending_core_result_rows(rows)
        return changed


def _projection(row: dict[str, Any]) -> dict[str, Any]:
    projection = {
        key: row.get(key)
        for key in (
            "email",
            "password",
            "access_token",
            "refresh_token",
            "id_token",
            "register_proxy",
            "source_type",
            "created_at",
            "register_stage",
            "task_index",
            "updated_at",
            "status",
            "retry_count",
            "last_error",
            "next_retry_at",
            "terminal_at",
            "terminal_reason",
        )
        if row.get(key) not in (None, "")
    }
    if "last_error" in projection:
        projection["last_error"] = _safe_error(projection["last_error"], row)
    if isinstance(row.get("fp"), dict):
        projection["fp"] = dict(row["fp"])
    if isinstance(row.get("cookies"), dict):
        projection["cookies"] = dict(row["cookies"])
    return projection


def list_pending_core_results() -> list[dict[str, Any]]:
    """Return pending core-result rows for the admin UI, including tokens."""
    return [_projection(row) for row in _read_rows()]


def _reconcile_core_result_unlocked(
    result: dict[str, Any],
    *,
    register_proxy: str = "",
    verify_fn: Callable[..., dict[str, Any]] | None = None,
    account_service_obj: Any = default_account_service,
) -> dict[str, Any]:
    access_token = str(result.get("access_token") or "").strip()
    if not access_token:
        raise RegisterError("token_exchange_failed", "注册核心结果缺少 access_token。", stage="收口")

    if verify_fn is None:
        verify_fn = openai_register.verify_registered_account
    proxy = str(register_proxy or result.get("register_proxy") or result.get("proxy") or "").strip()
    warnings: list[str] = []
    remote_info: dict[str, Any] = {}
    verify_failed = False
    try:
        remote_info = _invoke_verify_fn(
            verify_fn,
            access_token,
            register_proxy=proxy,
            account=result,
        )
        if not isinstance(remote_info, dict):
            raise RegisterError("verify_blocked", "注册账号验活结果格式无效。", stage="收口验活")
    except Exception as verify_error:
        verify_failed = True
        warnings.append(format_register_error(verify_error, stage="收口验活", kind="warning"))
        remote_info = {}

    if str(remote_info.get("quota_warning") or "").strip():
        warnings.append(str(remote_info.get("quota_warning")))

    normalized = {
        **result,
        **{
            key: value
            for key, value in remote_info.items()
            if value not in (None, "")
        },
    }
    if proxy:
        normalized["proxy"] = proxy
        normalized["register_proxy"] = proxy
    if verify_failed:
        normalized["last_remote_check_result"] = "error"
        normalized["last_remote_check_event"] = "register_verify"
        normalized["last_remote_check_error"] = warnings[-1] if warnings else "收口验活失败"
        normalized["last_remote_check_error_at"] = _now_text()
        normalized["last_remote_checked_at"] = None
    try:
        persist_result = account_service_obj.add_account_items(
            [normalized],
            return_items=False,
        )
    except RegisterError:
        raise
    except Exception as persist_error:
        raise RegisterError(
            "persist_failed",
            "账号入库失败。",
            original=str(persist_error),
            stage="入库",
        ) from persist_error
    if isinstance(persist_result, dict) and persist_result.get("errors"):
        original = str(persist_result["errors"])
        if "号池已满" in original or "pool_full" in original.lower():
            raise RegisterError(
                "pool_full",
                "账号池已满。",
                original=original,
                stage="号池检查",
            )
        raise RegisterError(
            "persist_failed",
            "账号入库失败。",
            original=original,
            stage="入库",
        )

    try:
        refresh_result = account_service_obj.refresh_accounts([access_token])
        if not isinstance(refresh_result, dict):
            warnings.append(
                RegisterError("refresh_failed", "账号池刷新结果格式无效。", stage="刷新号池").format_log(kind="warning")
            )
        elif refresh_result.get("errors"):
            warnings.append(
                RegisterError(
                    "refresh_failed",
                    "账号池刷新失败。",
                    original=str(refresh_result["errors"]),
                    stage="刷新号池",
                ).format_log(kind="warning")
            )
    except Exception as refresh_error:
        warnings.append(format_register_error(refresh_error, stage="刷新号池", kind="warning"))

    remove_error = openai_register.remove_pending_core_result(access_token)
    if remove_error:
        warnings.append(
            RegisterError(
                "persist_failed",
                "注册核心暂存结果清理失败，账号已入库。",
                original=str(remove_error),
                stage="入库",
                label="核心结果暂存清理失败",
            ).format_log(kind="warning")
        )
    return {
        "result": normalized,
        "warnings": warnings,
    }


def _invoke_verify_fn(
    verify_fn: Callable[..., dict[str, Any]],
    access_token: str,
    *,
    register_proxy: str = "",
    account: dict[str, Any] | None = None,
) -> dict[str, Any]:
    kwargs: dict[str, Any] = {}
    try:
        parameters = inspect.signature(verify_fn).parameters
    except (TypeError, ValueError):
        parameters = {}
    accepts_keywords = any(
        item.kind is inspect.Parameter.VAR_KEYWORD for item in parameters.values()
    )
    if accepts_keywords or "register_proxy" in parameters:
        kwargs["register_proxy"] = register_proxy
    if accepts_keywords or "account" in parameters:
        kwargs["account"] = account
    return verify_fn(access_token, **kwargs)


def reconcile_core_result(
    result: dict[str, Any],
    *,
    register_proxy: str = "",
    verify_fn: Callable[..., dict[str, Any]] | None = None,
    account_service_obj: Any = default_account_service,
) -> dict[str, Any]:
    """Serialize direct and scheduled handoff of a registration core result."""
    with _reconcile_lock:
        return _reconcile_core_result_unlocked(
            result,
            register_proxy=register_proxy,
            verify_fn=verify_fn,
            account_service_obj=account_service_obj,
        )


def reconcile_pending_core_results(
    *,
    register_proxy: str = "",
    verify_fn: Callable[..., dict[str, Any]] | None = None,
    account_service_obj: Any = default_account_service,
    limit: int = MAX_RECOVERY_BATCH,
    force: bool = False,
    access_token: str = "",
    email: str = "",
) -> dict[str, Any]:
    try:
        batch_limit = max(1, min(MAX_RECOVERY_BATCH, int(limit or MAX_RECOVERY_BATCH)))
    except (TypeError, ValueError):
        batch_limit = MAX_RECOVERY_BATCH
    with _reconcile_lock:
        rows = _read_rows()
        now = _now()
        selected = 0
        succeeded = 0
        failed = 0
        skipped = 0
        errors: list[str] = []
        target_token = str(access_token or "").strip()
        target_email = str(email or "").strip().casefold()

        for row in rows:
            token = str(row.get("access_token") or "").strip()
            row_email = str(row.get("email") or "").strip().casefold()
            if (
                not token
                or (target_token and token != target_token)
                or (target_email and row_email != target_email)
            ):
                continue
            if str(row.get("status") or "").strip() in TERMINAL_RECOVERY_STATUSES and not force:
                skipped += 1
                continue
            next_retry_at = _parse_time(row.get("next_retry_at"))
            if not force and next_retry_at is not None and next_retry_at > now:
                skipped += 1
                continue
            if selected >= batch_limit:
                break
            selected += 1
            try:
                outcome = reconcile_core_result(
                    row,
                    register_proxy=register_proxy,
                    verify_fn=verify_fn,
                    account_service_obj=account_service_obj,
                )
                succeeded += 1
                warnings = outcome.get("warnings") or []
                errors.extend(str(item) for item in warnings)
            except Exception as exc:
                failed += 1
                try:
                    retry_count = max(0, int(row.get("retry_count") or 0)) + 1
                except (TypeError, ValueError):
                    retry_count = 1
                delay = min(MAX_RETRY_DELAY_SECONDS, 30 * (2 ** min(retry_count - 1, 7)))
                error_text = _safe_error(exc, row)
                terminal = retry_count >= MAX_RECOVERY_RETRY_COUNT
                try:
                    _update_row(
                        token,
                        {
                            "status": "failed_terminal" if terminal else "retrying",
                            "retry_count": retry_count,
                            "last_error": error_text,
                            "failure_reason": error_text,
                            "next_retry_at": "" if terminal else (now + timedelta(seconds=delay)).isoformat(),
                            "terminal_at": _now_text() if terminal else str(row.get("terminal_at") or ""),
                            "terminal_reason": error_text if terminal else str(row.get("terminal_reason") or ""),
                            "updated_at": _now_text(),
                        },
                    )
                except Exception as update_error:
                    error_text = RegisterError(
                        "unknown",
                        "核心结果收口状态更新失败。",
                        original=f"{error_text}；{_safe_error(update_error, row)}",
                        stage="入库",
                        label="收口状态更新失败",
                    ).format_log()
                errors.append(f"{row.get('email') or 'pending-result'}: {error_text}")

        return {
            "attempted": selected,
            "succeeded": succeeded,
            "failed": failed,
            "skipped": skipped,
            "errors": errors,
            "remaining": len(_read_rows()),
        }
