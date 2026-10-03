from __future__ import annotations

import asyncio
import json
import itertools
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

import anyio
from fastapi import HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, StreamingResponse


class _ClosingStreamingResponse(StreamingResponse):
    """Close the body when the client goes away.

    Current Starlette turns a failed body write into ClientDisconnect without
    closing the iterator, so image slots and call logs would wait for GC.
    A generator that never started does not run its own finally on aclose.
    """

    def __init__(self, content, *, on_close=None, **kwargs):
        super().__init__(content, **kwargs)
        self._on_close = on_close

    async def __call__(self, scope, receive, send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            with anyio.CancelScope(shield=True):
                await _aclose_stream(self.body_iterator)
                if self._on_close is not None:
                    await self._on_close()


async def _aclose_stream(iterator: object) -> None:
    aclose = getattr(iterator, "aclose", None)
    if callable(aclose):
        try:
            await aclose()
        except RuntimeError as exc:
            if "already running" not in str(exc):
                raise
        return
    close = getattr(iterator, "close", None)
    if callable(close):
        close()

from services import image_generation_gate as image_gate

from services.call_record_service import CallRecordService
from services.storage.call_record_repository import CallRecordCursorMismatch

from services.image_failure import (
    ImageFailure,
    ImageGenerationError,
    classify_image_exception,
    image_failure,
    is_text_review_failure_code,
    public_image_error_message,
)
from services.protocol.error_response import (
    anthropic_error_response,
    openai_error_payload,
    openai_error_response,
)
from services.protocol.image_json_result import ImageJsonResult
from services.realtime_monitor_service import realtime_monitor_service
from utils.diagnostics import (
    diagnostic_excerpt,
    exception_diagnostic_fields,
    scrub_diagnostic_value,
)
from utils.helper import anthropic_sse_stream, close_iterator, image_request_count, image_sse_stream, sse_json_stream
from utils.image_tokens import image_output_metadata
from utils.log import logger
from utils.timezone import beijing_from_timestamp, beijing_now_str

LOG_TYPE_CALL = "call"
LOG_TYPE_ACCOUNT = "account"
INTERNAL_RESPONSE_KEYS = {
    "_account_email",
    "_call_error",
    "_conversation_id",
    "_call_id",
    "_call_status",
    "_image_urls",
    "_image_attempts",
    "_image_metadata",
    "_slot_index",
}
LOG_IMAGE_URL_RE = re.compile(r"(?:!\[[^\]]*\]\()(?P<url>(?:https?://|/images/|/image-thumbnails/)[^\s)\"']+)\)")
PERF_WAIT_WARN_MS = 1000
IMAGE_STREAM_KEEPALIVE_SECS = 15
REQUEST_TEXT_EXCERPT_LIMIT = 1000
REQUEST_TEXT_FULL_LIMIT = 50000

LogService = CallRecordService
LogCursorMismatch = CallRecordCursorMismatch
log_service = LogService()


def cleanup_old_logs() -> dict[str, int | bool]:
    from services.config import config
    from services.retention_cleanup_service import retention_cleanup_coordinator

    return retention_cleanup_coordinator.run_logs(config.log_retention_hours)


def _auto_cleanup_worker(stop_event: threading.Event) -> None:
    from services.retention_cleanup_service import retention_cleanup_coordinator

    retention_cleanup_coordinator.scheduler_worker(stop_event)


def start_log_cleanup_scheduler(stop_event: threading.Event) -> threading.Thread:
    from services.retention_cleanup_service import start_retention_cleanup_scheduler

    return start_retention_cleanup_scheduler(stop_event)


def _collect_urls(value: object) -> list[str]:
    urls: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "url" and isinstance(item, str):
                urls.append(item)
            elif key in {"urls", "_image_urls"} and isinstance(item, list):
                urls.extend(str(url) for url in item if isinstance(url, str))
            else:
                urls.extend(_collect_urls(item))
    elif isinstance(value, list):
        for item in value:
            urls.extend(_collect_urls(item))
    elif isinstance(value, str):
        urls.extend(match.group("url").rstrip(".,;") for match in LOG_IMAGE_URL_RE.finditer(value))
    return urls


def _collect_account_emails(value: object) -> list[str]:
    emails: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"_account_email", "account_email"} and isinstance(item, str) and item.strip():
                emails.append(item.strip())
            else:
                emails.extend(_collect_account_emails(item))
    elif isinstance(value, list):
        for item in value:
            emails.extend(_collect_account_emails(item))
    return emails


def _collect_conversation_ids(value: object) -> list[str]:
    ids: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "_conversation_id" and isinstance(item, str) and item.strip():
                ids.append(item.strip())
            else:
                ids.extend(_collect_conversation_ids(item))
    elif isinstance(value, list):
        for item in value:
            ids.extend(_collect_conversation_ids(item))
    return ids


IMAGE_ATTEMPT_KEYS = {
    "slot",
    "attempt",
    "account_email",
    "status",
    "failure_code",
    "failure_scope",
    "failure_capability",
    "failure_retryable",
    "failure_account_failure",
    "failure_retry_after",
    "status_code",
    "error_type",
    "public_error",
    "raw_error",
    "upstream_error",
    "raw_upstream_message",
    "account_failure",
    "switched_account",
    "switched_node",
    "proxy_group_id",
    "proxy_node_id",
    "proxy_node_name",
    "conversation_id",
    "duration_ms",
    "monitor",
}
IMAGE_ATTEMPT_INTEGER_KEYS = {
    "slot", "attempt", "duration_ms", "status_code", "failure_retry_after",
}
IMAGE_ATTEMPT_BOOLEAN_KEYS = {
    "failure_retryable", "failure_account_failure", "account_failure", "switched_account",
    "switched_node",
}


def _normalize_image_attempt_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized == "true":
            return True
        if normalized == "false":
            return False
    return None


def _normalize_image_attempt_int(key: str, value: object) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return max(1 if key in {"slot", "attempt"} else 0, parsed)


def _normalize_image_attempt_monitor(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    monitor: dict[str, object] = {}
    raw_metrics = value.get("metrics")
    if isinstance(raw_metrics, dict):
        metrics: dict[str, int] = {}
        for key, item in raw_metrics.items():
            if not str(key).endswith("_ms"):
                continue
            try:
                parsed = max(0, int(item))
            except (TypeError, ValueError):
                continue
            if parsed > 0:
                metrics[str(key)] = parsed
        if metrics:
            monitor["metrics"] = metrics
    raw_events = value.get("events")
    if isinstance(raw_events, list):
        events: list[dict[str, object]] = []
        for raw_event in raw_events[-40:]:
            if not isinstance(raw_event, dict):
                continue
            event: dict[str, object] = {}
            for key, item in raw_event.items():
                if str(key).endswith("_ms"):
                    try:
                        parsed = max(0, int(item))
                    except (TypeError, ValueError):
                        continue
                    if parsed > 0:
                        event[str(key)] = parsed
                elif key in IMAGE_ATTEMPT_INTEGER_KEYS:
                    parsed = _normalize_image_attempt_int(key, item)
                    if parsed is not None:
                        event[key] = parsed
                elif key == "attempts":
                    try:
                        parsed_attempts = max(0, int(item))
                    except (TypeError, ValueError):
                        continue
                    event[key] = parsed_attempts
                elif key in IMAGE_ATTEMPT_BOOLEAN_KEYS:
                    parsed = _normalize_image_attempt_bool(item)
                    if parsed is not None:
                        event[key] = parsed
                elif key in {
                    "time", "event", "label", "status",
                    "failure_code", "failure_scope", "failure_capability",
                    "error_type", "public_error",
                    "proxy_group_id", "proxy_node_id", "proxy_node_name",
                }:
                    text = str(item or "").strip()
                    if text:
                        event[key] = text
            if event:
                events.append(event)
        if events:
            monitor["events"] = events
    return monitor or None


def _normalize_image_attempt(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    if not ({"slot", "attempt", "status"} <= value.keys()):
        return None
    attempt: dict[str, object] = {}
    for key in IMAGE_ATTEMPT_KEYS:
        item = value.get(key)
        if item in (None, ""):
            continue
        if key == "monitor":
            monitor = _normalize_image_attempt_monitor(item)
            if monitor:
                attempt[key] = monitor
        elif key in IMAGE_ATTEMPT_INTEGER_KEYS:
            parsed = _normalize_image_attempt_int(key, item)
            if parsed is not None:
                attempt[key] = parsed
        elif key in IMAGE_ATTEMPT_BOOLEAN_KEYS:
            parsed = _normalize_image_attempt_bool(item)
            if parsed is not None:
                attempt[key] = parsed
        else:
            text = str(item).strip()
            if text:
                attempt[key] = text
    if not ({"slot", "attempt", "status"} <= attempt.keys()):
        return None
    return attempt


def collect_image_attempts(value: object) -> list[dict[str, object]]:
    attempts: list[dict[str, object]] = []
    seen: set[str] = set()
    pending: list[object] = [value]
    visited: set[int] = set()
    while pending:
        item = pending.pop()
        if isinstance(item, BaseException):
            pending.append(getattr(item, "image_attempts", None))
            continue
        if isinstance(item, dict):
            identity = id(item)
            if identity in visited:
                continue
            visited.add(identity)
            normalized = _normalize_image_attempt(item)
            if normalized is not None:
                signature = json.dumps(normalized, ensure_ascii=False, sort_keys=True)
                if signature not in seen:
                    seen.add(signature)
                    attempts.append(normalized)
                continue
            for key, child in item.items():
                if key in {"_image_attempts", "image_attempts"} or isinstance(child, (dict, list, tuple)):
                    pending.append(child)
        elif isinstance(item, (list, tuple)):
            pending.extend(reversed(item))
    return attempts


IMAGE_TRACE_REQUEST_KEYS = {
    "n",
    "size",
    "quality",
    "response_format",
    "stream",
    "partial_images",
}


def image_request_metadata(body: dict[str, Any]) -> dict[str, object]:
    metadata: dict[str, object] = {}
    source = body
    for tool in body.get("tools") or []:
        if isinstance(tool, dict) and tool.get("type") == "image_generation":
            source = {**body, **tool}
            break
    for key in IMAGE_TRACE_REQUEST_KEYS:
        if key not in source:
            continue
        value = source.get(key)
        if value in (None, ""):
            continue
        if isinstance(value, (str, int, float, bool)):
            metadata[key] = value
    images = body.get("images")
    if isinstance(images, list) and images:
        metadata["input_image_count"] = len(images)
    return metadata


def image_result_metrics(value: object) -> dict[str, object]:
    metrics: dict[str, Any] = {
        "result_data_count": 0,
        "result_url_count": 0,
        "result_b64_count": 0,
        "result_b64_chars": 0,
    }
    images: list[dict[str, int]] = []

    def visit(item: object) -> None:
        if isinstance(item, dict):
            internal_images = item.get("_image_metadata")
            if isinstance(internal_images, list):
                images.extend(internal_images)
            else:
                images.extend(image_output_metadata(item.get("data")))
            if "data" in item and isinstance(item.get("data"), list):
                metrics["result_data_count"] = max(
                    int(metrics["result_data_count"]),
                    len(item.get("data") or []),
                )
            url = item.get("url")
            if isinstance(url, str) and url.strip():
                metrics["result_url_count"] = int(metrics["result_url_count"]) + 1
            b64_json = item.get("b64_json")
            if isinstance(b64_json, str) and b64_json.strip():
                metrics["result_b64_count"] = int(metrics["result_b64_count"]) + 1
                metrics["result_b64_chars"] = int(metrics["result_b64_chars"]) + len(b64_json)
            for key, nested in item.items():
                if key == "_image_metadata":
                    continue
                if isinstance(nested, (dict, list)):
                    visit(nested)
        elif isinstance(item, list):
            for nested in item:
                visit(nested)

    visit(value)
    if images:
        metrics["result_images"] = images
        metrics["result_data_count"] = max(metrics["result_data_count"], len(images))
    return {
        key: value
        for key, value in metrics.items()
        if value
    }


def _strip_internal_response_fields(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: _strip_internal_response_fields(item)
            for key, item in value.items()
            if key not in INTERNAL_RESPONSE_KEYS
        }
    if isinstance(value, list):
        return [_strip_internal_response_fields(item) for item in value]
    return value


def _request_excerpt(text: object, limit: int = REQUEST_TEXT_EXCERPT_LIMIT) -> str:
    value = str(text or "").strip()
    if not value:
        return ""
    normalized = " ".join(value.split())
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 1].rstrip() + "…"


def _request_full_text(text: object, limit: int = REQUEST_TEXT_FULL_LIMIT) -> tuple[str, bool]:
    value = str(text or "").strip()
    if not value:
        return "", False
    normalized = " ".join(value.split())
    if len(normalized) <= limit:
        return normalized, False
    return normalized[: limit - 1].rstrip() + "…", True


def _exception_log_fields(exc: Exception, *, image: bool = False) -> dict[str, object]:
    fields = exception_diagnostic_fields(exc, include_status_code=True)
    attempts = collect_image_attempts(exc)
    if attempts:
        fields["image_attempts"] = attempts
    failure = getattr(exc, "failure", None)
    if image or failure is not None:
        failure = _final_image_failure(exc)
        fields.update(failure.diagnostic_fields())
        fields["error_code"] = failure.code
        fields["public_error"] = _public_image_exception_message(exc, failure)
        if failure.code == "image_poll_timeout":
            fields.pop("raw_error", None)
        elif "raw_error" not in fields and not hasattr(exc, "raw_error"):
            fields["raw_error"] = diagnostic_excerpt(str(exc), 4000)
    return fields


def _final_image_failure(exc: Exception) -> ImageFailure:
    failure = getattr(exc, "failure", None)
    if isinstance(failure, ImageFailure):
        return failure
    return classify_image_exception(exc)


def _public_image_exception_message(
    exc: Exception,
    failure: ImageFailure | None = None,
) -> str:
    public_error = getattr(exc, "public_error", "")
    if isinstance(public_error, str) and public_error.strip():
        return public_error.strip()
    return public_image_error_message(failure or _final_image_failure(exc), exc)


def _image_error_payload(exc: Exception) -> dict[str, object]:
    failure = _final_image_failure(exc)
    return {
        "error": {
            "message": _public_image_exception_message(exc, failure),
            "type": failure.error_type,
            "param": getattr(exc, "param", None),
            "code": failure.code,
        }
    }


def _image_error_response(exc: Exception) -> JSONResponse:
    failure = _final_image_failure(exc)
    return openai_error_response(_image_error_payload(exc), failure.status_code)


def _image_keepalive_error(exc: Exception) -> dict[str, object]:
    """JSON error for a response whose HTTP status is already 200.

    ``error.status`` is the numeric status NewAPI restores. ``error.code`` stays
    the failure reason and is not used as the status.
    """
    if isinstance(exc, HTTPException):
        status = int(exc.status_code)
        payload = openai_error_payload(exc.detail, status)
        error = payload.get("error")
        if isinstance(error, dict):
            error["status"] = status
        return payload
    failure = _final_image_failure(exc)
    payload = _image_error_payload(exc)
    error = payload.get("error")
    if isinstance(error, dict):
        error["status"] = int(failure.status_code)
    return payload


def _protocol_error_response(exc: Exception, status_code: int, sse: str) -> JSONResponse:
    message = str(exc)
    if sse == "anthropic":
        return anthropic_error_response(message, status_code)
    return openai_error_response(message, status_code)


def _next_item(items):
    try:
        return True, next(items)
    except StopIteration:
        return False, None


def _next_item_timed(items):
    started = time.perf_counter()
    try:
        found, item = _next_item(items)
    finally:
        finished = time.perf_counter()
    return found, item, started, finished


def _is_sse_comment(item: object) -> bool:
    return isinstance(item, str) and item.lstrip().startswith(":")


def _frame_delivers_image(frame: object) -> bool:
    """True only after the client can use an image, not a preamble or progress text."""
    if isinstance(frame, (dict, list)):
        try:
            text = json.dumps(frame, ensure_ascii=False)
        except TypeError:
            return False
    elif isinstance(frame, str):
        text = frame
    else:
        return False
    if _is_sse_comment(text):
        return False
    # response.completed repeats the image already sent in output_item.done.
    # Counting it again turns a written image into an undelivered one when the
    # client leaves on the final event.
    if re.search(r'"type"\s*:\s*"response\.completed"', text):
        return False
    # Chat delivery is the markdown image itself. A progress delta that only
    # mentions data:image/ or ![image_ is not an image the client can use.
    if re.search(r"!\[image_\d+\]\([^)\s]+", text):
        return True
    fields = {
        key: value
        for key, value in re.findall(r'"([A-Za-z0-9_]+)"\s*:\s*"((?:\\.|[^"\\])*)"', text)
    }
    if fields.get("b64_json"):
        return True
    if fields.get("url") and (
        "image_generation.completed" in text or "image_edit.completed" in text
    ):
        return True
    return "image_generation_call" in text and bool(fields.get("result"))


def _frame_reports_slot_failure(item: object) -> bool:
    if isinstance(item, (dict, list)):
        try:
            text = json.dumps(item, ensure_ascii=False)
        except TypeError:
            text = ""
    elif isinstance(item, str):
        text = item
    else:
        text = ""
    if "image_generation.failed" in text or "image_edit.failed" in text:
        return True
    return _image_slots_missing_success(collect_image_attempts(item))


def _undelivered_image_failure_fields(
    attempts: list[dict[str, object]],
) -> tuple[str, dict[str, object]]:
    """The public failure from image attempts when no image was written."""

    code = ""
    message = ""
    for item in attempts:
        status = str(item.get("status") or "").strip().lower()
        if not status or status == "success":
            continue
        if not code:
            code = str(item.get("error_code") or item.get("failure_code") or "").strip()
        if not message:
            message = str(item.get("public_error") or item.get("error") or "").strip()
    extra: dict[str, object] = {}
    if code:
        extra["error_code"] = code
    return message or "image generation failed", extra


def _image_slots_missing_success(attempts: list[dict[str, object]]) -> bool:
    """A slot fails only when none of its attempts succeeded.

    Account retry keeps the failed attempt on the later success frame. That
    history is diagnostic and must not turn a delivered image into a partial
    success.
    """
    succeeded: set[int] = set()
    failed: set[int] = set()
    unslotted_failure = False
    for item in attempts:
        status = str(item.get("status") or "").strip().lower()
        try:
            slot = int(item.get("slot") or 0)
        except (TypeError, ValueError):
            slot = 0
        if status == "success" and slot > 0:
            succeeded.add(slot)
            continue
        if not status or status == "success":
            continue
        if slot > 0:
            failed.add(slot)
        else:
            unslotted_failure = True
    return unslotted_failure or bool(failed - succeeded)


def _image_stream_keepalive_secs() -> float:
    return max(0.001, float(IMAGE_STREAM_KEEPALIVE_SECS))


def _undelivered_image_log_fields(image_attempts: list[dict[str, object]]) -> dict[str, object]:
    """A generated image that never reached the client is not a delivered result."""
    rewritten: list[dict[str, object]] = []
    for item in image_attempts:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "").lower()
        if status == "success":
            rewritten.append(dict(item, status="generated_not_delivered"))
        else:
            rewritten.append(dict(item))
    if not rewritten:
        return {}
    return {"image_attempts": rewritten}


def _image_delivery_count_fields(
    result: dict,
    requested_n: object,
    status: str,
) -> dict[str, object]:
    """Count delivered images even when the body has no public URL."""
    data = result.get("data")
    items = data if isinstance(data, list) else []
    succeeded = sum(
        1
        for item in items
        if isinstance(item, dict)
        and (
            str(item.get("url") or "").strip()
            or str(item.get("b64_json") or "").strip()
        )
    )
    if succeeded <= 0:
        # Chat and Responses bodies fold images into text or output items.
        # Their measured metadata is the delivered count; a bare status must
        # not turn that into zero successes.
        metadata = result.get("_image_metadata")
        if isinstance(metadata, list):
            succeeded = sum(1 for item in metadata if isinstance(item, dict))
    errors = result.get("errors")
    error_count = len(errors) if isinstance(errors, list) else 0
    try:
        requested = int(requested_n) if requested_n not in (None, "") else 0
    except (TypeError, ValueError):
        requested = 0
    requested = max(requested, succeeded + error_count, succeeded)
    if requested <= 0 and succeeded <= 0:
        return {}
    if status == "partial_success" or (
        succeeded > 0 and (error_count > 0 or requested > succeeded)
    ):
        result_status = "partial_success"
        failed = max(error_count, requested - succeeded)
    elif status == "failed" or succeeded <= 0:
        result_status = "failed"
        failed = max(error_count, requested - succeeded)
    else:
        result_status = "success"
        failed = 0
    return {
        "image_requested_count": max(requested, succeeded + failed),
        "image_succeeded_count": succeeded,
        "image_failed_count": failed,
        "image_result_status": result_status,
    }


@dataclass
class LoggedCall:
    identity: dict[str, object]
    endpoint: str
    model: str
    summary: str
    started: float = field(default_factory=time.time)
    request_text: str = ""
    request_shape: dict[str, int] | None = None
    image_request: bool = False
    call_id: str = field(default_factory=lambda: uuid4().hex[:16])
    perf_timings: dict[str, int] = field(default_factory=dict)
    trace_metadata: dict[str, object] = field(default_factory=dict)

    async def run(self, handler, *args, sse: str = "openai"):
        if args and isinstance(args[0], dict):
            self.attach_trace_metadata(args[0])
        image_request = self._is_image_request()
        trace_perf = self._trace_image_perf()
        if trace_perf:
            realtime_monitor_service.start(
                self.call_id,
                endpoint=self.endpoint,
                model=self.model,
                summary=self.summary,
                role=str(self.identity.get("role") or ""),
                key_name=str(self.identity.get("name") or ""),
            )
        admission = None
        admission_token = None
        image_limiter = None
        cleanup_deferred = False
        try:
            if image_request:
                try:
                    admission = await self._reserve_image_admission(args)
                except ImageGenerationError as exc:
                    self.log(
                        "调用失败",
                        status="failed",
                        error=_public_image_exception_message(exc),
                        account_email=getattr(exc, "account_email", ""),
                        conversation_id=getattr(exc, "conversation_id", ""),
                        extra=_exception_log_fields(exc, image=image_request),
                    )
                    return _image_error_response(exc)
                except HTTPException as exc:
                    self.log("调用失败", status="failed", error=str(exc.detail))
                    raise
                admission_token = image_gate.image_generation_gate.bind(admission)
                image_limiter = image_gate.image_generation_gate.handler_limiter()
            handler_submitted = time.perf_counter()

            def _call_handler():
                handler_started = time.perf_counter()
                queue_ms = int((handler_started - handler_submitted) * 1000)
                if trace_perf:
                    self.perf_timings["handler_queue_ms"] = queue_ms
                    realtime_monitor_service.stage(
                        self.call_id,
                        "handler_started",
                        handler_queue_ms=queue_ms,
                        endpoint=self.endpoint,
                        model=self.model,
                    )
                if trace_perf and queue_ms >= PERF_WAIT_WARN_MS:
                    logger.warning({
                        "event": "api_handler_threadpool_wait_slow",
                        "call_id": self.call_id,
                        "endpoint": self.endpoint,
                        "model": self.model,
                        "queue_ms": queue_ms,
                    })
                try:
                    return handler(*args)
                finally:
                    if trace_perf:
                        self.perf_timings["handler_exec_ms"] = int((time.perf_counter() - handler_started) * 1000)

            try:
                result = await self._run_on_limiter(_call_handler, image_limiter)
            except ImageGenerationError as exc:
                self.log("调用失败", status="failed", error=_public_image_exception_message(exc), account_email=getattr(exc, "account_email", ""),
                         conversation_id=getattr(exc, "conversation_id", ""),
                         extra=_exception_log_fields(exc, image=image_request))
                return _image_error_response(exc)
            except HTTPException as exc:
                self.log("调用失败", status="failed", error=str(exc.detail))
                raise
            except Exception as exc:
                self.log("调用失败", status="failed", error=(
                    _public_image_exception_message(exc) if image_request else str(exc)
                ), account_email=getattr(exc, "account_email", ""),
                         extra=_exception_log_fields(exc, image=image_request))
                if image_request:
                    return _image_error_response(exc)
                return _protocol_error_response(exc, 502, sse)

            if isinstance(result, dict):
                self._log_projected_image_result(result)
                return _strip_internal_response_fields(result)

            if isinstance(result, ImageJsonResult):
                self._image_json_keepalive = True
                self._image_keepalive_admission = admission
                self._image_keepalive_token = admission_token
                self._image_keepalive_limiter = image_limiter
                body = self._iterate_image_json_keepalive(result.produce, image_limiter)
                response = _ClosingStreamingResponse(
                    body,
                    on_close=self._close_image_keepalive_response,
                    media_type="application/json",
                    headers={
                        "Cache-Control": "no-cache",
                        "X-Accel-Buffering": "no",
                    },
                )
                cleanup_deferred = True
                return response

            if self.endpoint.startswith("/v1/images"):
                sender = lambda items: image_sse_stream(items, error_builder=_image_error_payload)
            else:
                if sse == "anthropic":
                    sender = anthropic_sse_stream
                elif image_request:
                    sender = lambda items: sse_json_stream(items, error_builder=_image_error_payload)
                else:
                    sender = sse_json_stream
            if image_request:
                formatted = sender(self.stream(result))
                self._image_keepalive_items = formatted
                self._image_keepalive_generator = result
                self._image_keepalive_admission = admission
                self._image_keepalive_token = admission_token
                self._image_keepalive_limiter = image_limiter
                body = self._iterate_image_stream_keepalive(
                    formatted,
                    result,
                    admission,
                    admission_token,
                )
                response = _ClosingStreamingResponse(
                    body,
                    on_close=self._close_image_keepalive_response,
                    media_type="text/event-stream",
                    headers={
                        "Cache-Control": "no-cache",
                        "X-Accel-Buffering": "no",
                    },
                )
                cleanup_deferred = True
                return response
            first_item_submitted = time.perf_counter()

            def _next_item_with_timing():
                first_item_started = time.perf_counter()
                queue_ms = int((first_item_started - first_item_submitted) * 1000)
                if trace_perf:
                    self.perf_timings["stream_first_queue_ms"] = queue_ms
                    realtime_monitor_service.stage(
                        self.call_id,
                        "stream_first_item",
                        stream_first_queue_ms=queue_ms,
                        endpoint=self.endpoint,
                        model=self.model,
                    )
                if trace_perf and queue_ms >= PERF_WAIT_WARN_MS:
                    logger.warning({
                        "event": "api_stream_first_item_threadpool_wait_slow",
                        "call_id": self.call_id,
                        "endpoint": self.endpoint,
                        "model": self.model,
                        "queue_ms": queue_ms,
                    })
                try:
                    return _next_item(result)
                finally:
                    if trace_perf:
                        self.perf_timings["stream_first_exec_ms"] = int((time.perf_counter() - first_item_started) * 1000)

            try:
                has_first, first = await self._run_on_limiter(_next_item_with_timing, image_limiter)
            except ImageGenerationError as exc:
                self.log("调用失败", status="failed", error=_public_image_exception_message(exc), account_email=getattr(exc, "account_email", ""),
                         conversation_id=getattr(exc, "conversation_id", ""),
                         extra=_exception_log_fields(exc, image=image_request))
                return _image_error_response(exc)
            except HTTPException as exc:
                self.log("调用失败", status="failed", error=str(exc.detail))
                raise
            except Exception as exc:
                self.log("调用失败", status="failed", error=(
                    _public_image_exception_message(exc) if image_request else str(exc)
                ), account_email=getattr(exc, "account_email", ""),
                         extra=_exception_log_fields(exc, image=image_request))
                if image_request:
                    return _image_error_response(exc)
                return _protocol_error_response(exc, 502, sse)
            if not has_first:
                self.log("流式调用结束")
                body = sender(())
                return StreamingResponse(body, media_type="text/event-stream")
            body = sender(self.stream(itertools.chain([first], result)))
            return StreamingResponse(body, media_type="text/event-stream")
        finally:
            if not cleanup_deferred:
                if admission_token is not None:
                    image_gate.image_generation_gate.unbind(admission_token)
                if admission is not None and not admission.handed_off:
                    image_gate.image_generation_gate.release(admission)

    async def _reserve_image_admission(self, args):
        gate = image_gate.image_generation_gate
        from services.config import config

        deadline = time.monotonic() + max(0.001, float(config.image_request_timeout_secs))
        admission = None
        try:
            admission = gate.admit(
                self._image_slot_count(args),
                deadline_monotonic=deadline,
            )
            await gate.acquire_running_async(admission, deadline)
            return admission
        except image_gate.ImageGenerationQueueFullError as exc:
            if admission is not None:
                gate.release(admission)
            raise ImageGenerationError(
                "Image generation is busy. Please try again later.",
                failure=image_failure("image_generation_busy"),
            ) from exc
        except BaseException:
            if admission is not None:
                gate.release(admission)
            raise

    @staticmethod
    def _image_slot_count(args) -> int:
        if not args or not isinstance(args[0], dict):
            return 1
        return image_request_count(args[0])

    @staticmethod
    async def _run_on_limiter(func, limiter):
        if limiter is None:
            return await run_in_threadpool(func)
        return await anyio.to_thread.run_sync(func, limiter=limiter)

    def _abandon_open_image_request(self) -> None:
        admission = getattr(self, "_image_keepalive_admission", None)
        event = getattr(admission, "abandoned", None)
        if event is not None:
            event.set()

    def _log_image_json_failure(self, exc: Exception) -> None:
        if isinstance(exc, HTTPException):
            self.log("调用失败", status="failed", error=str(exc.detail))
            return
        self.log(
            "调用失败",
            status="failed",
            error=_public_image_exception_message(exc),
            account_email=getattr(exc, "account_email", ""),
            conversation_id=getattr(exc, "conversation_id", ""),
            extra=_exception_log_fields(exc, image=True),
        )

    def _log_projected_image_result(self, result: dict) -> None:
        projected_status = str(result.get("_call_status") or "success").strip().lower()
        if projected_status not in {"success", "failed", "text_review", "partial_success"}:
            projected_status = "success"
        projected_error = str(result.get("_call_error") or "").strip()
        projected_extra: dict[str, object] = {}
        if projected_status != "success" and result.get("error_code"):
            projected_extra["error_code"] = result["error_code"]
        has_images = isinstance(result.get("data"), list) and bool(result.get("data"))
        if self._is_image_request() and (
            projected_status == "partial_success" or has_images or result.get("errors")
        ):
            projected_extra.update(
                _image_delivery_count_fields(
                    result,
                    self.trace_metadata.get("n"),
                    projected_status,
                )
            )
        self.log(
            "调用失败" if projected_status == "failed" else "调用完成",
            result,
            status=projected_status,
            error=projected_error,
            account_email=str(result.get("_account_email") or ""),
            conversation_id=str(result.get("_conversation_id") or ""),
            extra=projected_extra or None,
        )

    def _log_image_json_undelivered(self) -> None:
        result = getattr(self, "_image_json_pending_result", None)
        attempts = collect_image_attempts(result) if isinstance(result, dict) else []
        extra = _undelivered_image_log_fields(attempts)
        email = ""
        conversation_id = ""
        if isinstance(result, dict):
            email = str(result.get("_account_email") or "")
            conversation_id = str(result.get("_conversation_id") or "")
        self._log_image_client_disconnected(
            account_email=email,
            conversation_id=conversation_id,
            extra=extra or None,
        )

    async def _iterate_image_json_keepalive(self, produce, limiter):
        """Keep a non-stream image response alive, then write one JSON document.

        Leading newlines are JSON whitespace. The HTTP status stays 200, so a
        failure document carries ``error.status`` for the relay to restore.
        """
        pending: asyncio.Task | None = asyncio.create_task(
            self._run_on_limiter(produce, limiter)
        )
        try:
            try:
                while True:
                    done, _waiting = await asyncio.wait(
                        {pending},
                        timeout=_image_stream_keepalive_secs(),
                    )
                    if pending not in done:
                        yield "\n"
                        continue
                    try:
                        result = pending.result()
                    except Exception as exc:
                        self._log_image_json_failure(exc)
                        self._image_json_result_logged = True
                        yield json.dumps(_image_keepalive_error(exc), ensure_ascii=False)
                        return
                    if not isinstance(result, dict):
                        raise TypeError("image json result must be an object")
                    body = json.dumps(
                        _strip_internal_response_fields(result),
                        ensure_ascii=False,
                    )
                    self._image_json_pending_result = result
                    yield body
                    self._log_projected_image_result(result)
                    self._image_json_result_logged = True
                    return
            except (GeneratorExit, asyncio.CancelledError):
                self._image_client_closed = True
                raise
        finally:
            with anyio.CancelScope(shield=True):
                try:
                    if (
                        getattr(self, "_image_client_closed", False)
                        and not getattr(self, "_image_json_result_logged", False)
                    ):
                        self._image_delivery_abandoned = True
                    if pending is not None and not pending.done():
                        self._abandon_open_image_request()
                        try:
                            await pending
                        except Exception:
                            pass
                    if (
                        pending is not None
                        and pending.done()
                        and not pending.cancelled()
                        and not getattr(self, "_image_json_result_logged", False)
                    ):
                        try:
                            finished = pending.result()
                        except Exception:
                            finished = None
                        if isinstance(finished, dict):
                            self._image_json_pending_result = finished
                finally:
                    await self._ensure_image_keepalive_closed()

    async def _iterate_image_stream_keepalive(self, items, image_generator, admission, admission_token):
        iterator = iter(items)
        limiter = image_gate.image_generation_gate.handler_limiter()
        self._image_keepalive_items = items
        self._image_keepalive_generator = image_generator
        self._image_keepalive_admission = admission
        self._image_keepalive_token = admission_token
        self._image_keepalive_limiter = limiter
        pending: asyncio.Task | None = None
        pending_frame = ""
        frame_timing: tuple[float, float, float] | None = None
        try:
            try:
                yield ": keep-alive\n\n"
                while True:
                    if pending is None:
                        submitted = time.perf_counter()
                        pending = asyncio.create_task(
                            anyio.to_thread.run_sync(_next_item_timed, iterator, limiter=limiter)
                        )
                    done, _waiting = await asyncio.wait(
                        {pending},
                        timeout=_image_stream_keepalive_secs(),
                    )
                    if pending not in done:
                        if not pending_frame:
                            yield ": keep-alive\n\n"
                        continue
                    found, item, started, finished = pending.result()
                    pending = None
                    if (
                        _frame_delivers_image(item)
                        and getattr(self, "_image_metric_origin", None) is None
                    ):
                        self._image_metric_origin = (submitted, started)
                    if not found:
                        if pending_frame:
                            yield pending_frame
                            self._note_image_frame_sent(pending_frame, frame_timing)
                        break
                    if not isinstance(item, str):
                        if pending_frame:
                            yield pending_frame
                            self._note_image_frame_sent(pending_frame, frame_timing)
                            pending_frame = ""
                            frame_timing = None
                        yield item
                        self._note_image_frame_sent(item, (submitted, started, finished))
                        continue
                    if frame_timing is None:
                        frame_timing = (submitted, started, finished)
                    pending_frame += item
                    if not pending_frame.endswith("\n\n"):
                        continue
                    frame = pending_frame
                    timing = frame_timing
                    pending_frame = ""
                    frame_timing = None
                    yield frame
                    self._note_image_frame_sent(frame, timing)
            except (GeneratorExit, asyncio.CancelledError):
                self._image_client_closed = True
                raise
        finally:
            with anyio.CancelScope(shield=True):
                try:
                    if (
                        getattr(self, "_image_client_closed", False)
                        and not getattr(self, "_image_business_frame_sent", False)
                    ):
                        self._image_delivery_abandoned = True
                    if pending is not None and not pending.done():
                        self._abandon_open_image_request()
                        try:
                            await pending
                        except Exception:
                            pass
                finally:
                    await self._ensure_image_keepalive_closed()

    def _queue_image_delivery(self, item: object) -> None:
        if not _frame_delivers_image(item):
            return
        pending = getattr(self, "_pending_image_deliveries", None)
        if pending is None:
            pending = []
            self._pending_image_deliveries = pending
        pending.append({
            "metrics": image_result_metrics(item),
            "urls": _collect_urls(item),
            "account_emails": _collect_account_emails(item),
            "conversation_ids": _collect_conversation_ids(item),
            "image_attempts": collect_image_attempts(item),
        })

    def _commit_sent_image_delivery(self) -> None:
        pending = getattr(self, "_pending_image_deliveries", None)
        if not pending:
            return
        sent = getattr(self, "_sent_image_deliveries", None)
        if sent is None:
            sent = []
            self._sent_image_deliveries = sent
        sent.append(pending.pop(0))

    def _log_delivered_image_stream(self) -> None:
        sent = list(getattr(self, "_sent_image_deliveries", []) or [])
        pending = list(getattr(self, "_pending_image_deliveries", []) or [])

        def merge(records: list[dict[str, object]]):
            metrics: dict[str, object] = {}
            urls: list[str] = []
            emails: list[str] = []
            conversation_ids: list[str] = []
            attempts: list[dict[str, object]] = []
            for record in records:
                item_metrics = record.get("metrics")
                if isinstance(item_metrics, dict):
                    for key, value in item_metrics.items():
                        if key == "result_images" and isinstance(value, list):
                            metrics.setdefault(key, []).extend(value)
                        elif isinstance(value, int):
                            metrics[key] = int(metrics.get(key, 0) or 0) + value
                urls.extend(url for url in record.get("urls") or [] if isinstance(url, str))
                emails.extend(email for email in record.get("account_emails") or [] if isinstance(email, str))
                conversation_ids.extend(
                    item for item in record.get("conversation_ids") or [] if isinstance(item, str)
                )
                attempts = collect_image_attempts([attempts, record.get("image_attempts")])
            return metrics, urls, emails, conversation_ids, attempts

        metrics, urls, emails, conversation_ids, attempts = merge(sent)
        _, _, _, _, undelivered = merge(pending)
        extra = dict(metrics)

        def attempt_identity(item: dict[str, object]) -> tuple[int, int] | None:
            try:
                slot = int(item.get("slot") or 0)
                attempt_no = int(item.get("attempt") or 0)
            except (TypeError, ValueError):
                return None
            if slot <= 0 or attempt_no <= 0:
                return None
            return slot, attempt_no

        delivered_keys = {
            key for item in attempts if (key := attempt_identity(item)) is not None
        }
        # One slot can emit several image frames with the same attempt. A later
        # frame that was not written must not replace the success of a frame
        # that was already written.
        undelivered_attempts = [
            dict(item, status="generated_not_delivered")
            for item in undelivered
            if (key := attempt_identity(item)) is None or key not in delivered_keys
        ]
        combined = [*attempts, *undelivered_attempts]
        seen_failures: list[dict[str, object]] = []
        for item in collect_image_attempts(getattr(self, "_observed_image_attempts", None)):
            status = str(item.get("status") or "").strip().lower()
            if not status or status == "success":
                continue
            key = attempt_identity(item)
            if key is not None and key in delivered_keys:
                continue
            seen_failures.append(dict(item))
        existing = {
            key for item in combined if (key := attempt_identity(item)) is not None
        }
        for item in seen_failures:
            key = attempt_identity(item)
            if key is not None and key in existing:
                continue
            combined.append(item)
            if key is not None:
                existing.add(key)
        if combined:
            extra["image_attempts"] = combined
            slot_failed = _image_slots_missing_success(combined)
        else:
            slot_failed = bool(getattr(self, "_image_slot_failure_seen", False))
        error = ""
        if not sent and slot_failed:
            status = "failed"
            error, failure_fields = _undelivered_image_failure_fields(combined)
            extra.update(failure_fields)
        elif sent and (pending or slot_failed):
            status = "partial_success"
        else:
            status = "success"
        self.log(
            "流式调用结束",
            status=status,
            error=error,
            urls=urls,
            account_email=emails[0] if emails else "",
            conversation_id=conversation_ids[0] if conversation_ids else "",
            extra=extra,
        )

    def _note_image_frame_sent(self, frame: object, timing: tuple[float, float, float] | None = None) -> None:
        if not _frame_delivers_image(frame):
            return
        self._commit_sent_image_delivery()
        self._image_business_frame_sent = True
        if getattr(self, "_image_first_metric_noted", False):
            return
        origin = getattr(self, "_image_metric_origin", None)
        if timing is not None:
            submitted, started, finished = timing
        elif origin is not None:
            submitted, started = origin
            finished = started
        else:
            return
        self._note_stream_first_item(submitted, started, finished)
        self._image_first_metric_noted = True

    async def _close_image_keepalive_response(self) -> None:
        if getattr(self, "_image_keepalive_closed", False):
            return
        if not getattr(self, "_image_business_frame_sent", False):
            self._image_delivery_abandoned = True
        await self._ensure_image_keepalive_closed()

    async def _ensure_image_keepalive_closed(self) -> None:
        if getattr(self, "_image_keepalive_closed", False):
            return
        self._image_keepalive_closed = True
        try:
            await self._close_image_iterators(
                getattr(self, "_image_keepalive_items", None),
                getattr(self, "_image_keepalive_generator", None),
                getattr(self, "_image_keepalive_limiter", None),
            )
        finally:
            self._finish_deferred_image_admission(
                getattr(self, "_image_keepalive_admission", None),
                getattr(self, "_image_keepalive_token", None),
            )
            if getattr(self, "_image_json_result_logged", False):
                return
            if not getattr(self, "_stream_started", False):
                if getattr(self, "_image_delivery_abandoned", False):
                    if getattr(self, "_image_json_keepalive", False):
                        self._log_image_json_undelivered()
                    else:
                        self._log_image_client_disconnected()
                else:
                    self.log("流式调用结束")

    def _log_image_client_disconnected(
        self,
        *,
        urls: list[str] | None = None,
        account_email: str = "",
        conversation_id: str = "",
        extra: dict[str, object] | None = None,
    ) -> None:
        fields: dict[str, object] = {"error_code": "client_disconnected"}
        if extra:
            fields.update(extra)
            fields["error_code"] = "client_disconnected"
        self.log(
            "流式调用失败",
            status="failed",
            error="client disconnected before the image was delivered",
            urls=urls,
            account_email=account_email,
            conversation_id=conversation_id,
            extra=fields,
        )

    def _note_stream_first_item(self, submitted: float, started: float, finished: float) -> None:
        if not self._trace_image_perf():
            return
        queue_ms = int((started - submitted) * 1000)
        self.perf_timings["stream_first_queue_ms"] = queue_ms
        realtime_monitor_service.stage(
            self.call_id,
            "stream_first_item",
            stream_first_queue_ms=queue_ms,
            endpoint=self.endpoint,
            model=self.model,
        )
        if queue_ms >= PERF_WAIT_WARN_MS:
            logger.warning({
                "event": "api_stream_first_item_threadpool_wait_slow",
                "call_id": self.call_id,
                "endpoint": self.endpoint,
                "model": self.model,
                "queue_ms": queue_ms,
            })
        self.perf_timings["stream_first_exec_ms"] = int((finished - started) * 1000)

    @staticmethod
    async def _close_image_iterators(iterator, image_generator, limiter) -> None:
        def _close_streams() -> None:
            first_error: Exception | None = None
            for candidate in (iterator, image_generator):
                close = getattr(candidate, "close", None)
                if close is None:
                    continue
                try:
                    close()
                except Exception as exc:
                    if first_error is None:
                        first_error = exc
            if first_error is not None:
                raise first_error

        await anyio.to_thread.run_sync(_close_streams, limiter=limiter)

    @staticmethod
    def _finish_deferred_image_admission(admission, admission_token) -> None:
        try:
            if admission_token is not None:
                image_gate.image_generation_gate.unbind(admission_token)
        finally:
            if admission is None or admission.handed_off or admission.state != "open":
                return
            image_gate.image_generation_gate.release(admission)

    def _is_image_request(self) -> bool:
        return bool(self.image_request) or self.endpoint.startswith("/v1/images")

    def _trace_image_perf(self) -> bool:
        return self._is_image_request()

    def attach_trace_metadata(self, body: dict[str, Any]) -> None:
        if not isinstance(body, dict):
            return
        if not self._trace_image_perf():
            return
        body["_call_id"] = self.call_id
        body["_trace_image_perf"] = True
        self.trace_metadata.update(image_request_metadata(body))

    def stream(self, items):
        self._stream_started = True
        urls: list[str] = []
        account_emails: list[str] = []
        conversation_ids: list[str] = []
        image_attempts: list[dict[str, object]] = []
        result_metrics: dict[str, Any] = {}
        failed = False
        image_request = self._is_image_request()
        if image_request:
            self._pending_image_deliveries = []
            self._sent_image_deliveries = []
        try:
            for item in items:
                if image_request:
                    self._queue_image_delivery(item)
                    if _frame_reports_slot_failure(item):
                        self._image_slot_failure_seen = True
                    for key, value in image_result_metrics(item).items():
                        if key == "result_images":
                            result_metrics.setdefault(key, []).extend(value)
                        else:
                            result_metrics[key] = result_metrics.get(key, 0) + value
                urls.extend(_collect_urls(item))
                account_emails.extend(_collect_account_emails(item))
                conversation_ids.extend(_collect_conversation_ids(item))
                image_attempts = collect_image_attempts([image_attempts, item])
                yield _strip_internal_response_fields(item)
        except Exception as exc:
            if image_request and getattr(self, "_image_delivery_abandoned", False):
                raise
            failed = True
            sent_images = list(getattr(self, "_sent_image_deliveries", []) or []) if image_request else []
            delivered = bool(sent_images)
            extra = _exception_log_fields(exc, image=image_request)
            extra.update(result_metrics)
            combined_attempts = collect_image_attempts([image_attempts, exc])
            if combined_attempts:
                extra["image_attempts"] = combined_attempts
            if delivered:
                extra["image_result_status"] = "partial_success"
            self.log(
                "流式调用结束" if delivered else "流式调用失败",
                status="partial_success" if delivered else "failed",
                error=(
                    _public_image_exception_message(exc)
                    if image_request else str(exc)
                ),
                urls=urls,
                account_email=(account_emails[0] if account_emails else getattr(exc, "account_email", "")),
                conversation_id=(conversation_ids[0] if conversation_ids else getattr(exc, "conversation_id", "")),
                extra=extra,
            )
            if image_request and not hasattr(exc, "to_openai_error"):
                from services.image_failure import ImageGenerationError, classify_image_exception

                raw_error = str(exc) or "image generation failed"
                raise ImageGenerationError(
                    raw_error,
                    failure=classify_image_exception(exc),
                    raw_error=raw_error,
                ) from exc
            raise
        finally:
            self._observed_image_attempts = image_attempts
            try:
                if not failed:
                    if getattr(self, "_image_delivery_abandoned", False):
                        self._log_image_client_disconnected(
                            account_email=account_emails[0] if account_emails else "",
                            conversation_id=conversation_ids[0] if conversation_ids else "",
                            extra=_undelivered_image_log_fields(image_attempts),
                        )
                    elif image_request and hasattr(self, "_sent_image_deliveries"):
                        pending = getattr(self, "_pending_image_deliveries", []) or []
                        sent = getattr(self, "_sent_image_deliveries", []) or []
                        if pending and not sent:
                            self._log_image_client_disconnected(
                                account_email=account_emails[0] if account_emails else "",
                                conversation_id=conversation_ids[0] if conversation_ids else "",
                                extra=_undelivered_image_log_fields(image_attempts),
                            )
                        else:
                            self._log_delivered_image_stream()
                    else:
                        extra = dict(result_metrics)
                        if image_attempts:
                            extra["image_attempts"] = image_attempts
                        self.log("流式调用结束", urls=urls, account_email=account_emails[0] if account_emails else "",
                                 conversation_id=conversation_ids[0] if conversation_ids else "", extra=extra)
            finally:
                close_iterator(items)

    def log(self, suffix: str, result: object = None, status: str = "success", error: str = "",
            urls: list[str] | None = None, account_email: str = "", conversation_id: str = "",
            extra: dict[str, object] | None = None) -> None:
        failure_code = (extra or {}).get("error_code") or (extra or {}).get("failure_code")
        if is_text_review_failure_code(failure_code):
            status = "text_review"
            suffix = "文本"
        detail = {
            "key_id": self.identity.get("id"),
            "key_name": self.identity.get("name"),
            "role": self.identity.get("role"),
            "endpoint": self.endpoint,
            "model": self.model,
            "call_id": self.call_id,
            "started_at": beijing_from_timestamp(self.started),
            "ended_at": beijing_now_str(),
            "duration_ms": int((time.time() - self.started) * 1000),
            "status": status,
            "image_request": self._is_image_request(),
        }
        if self.perf_timings:
            detail["perf"] = dict(self.perf_timings)
        request_excerpt = _request_excerpt(self.request_text)
        if request_excerpt:
            detail["request_text"] = request_excerpt
            request_full, request_full_truncated = _request_full_text(self.request_text)
            if request_full and request_full != request_excerpt:
                detail["request_text_full"] = request_full
                detail["request_text_truncated"] = request_full_truncated
        if self.request_shape:
            detail["request_shape"] = self.request_shape
        if self.trace_metadata:
            detail["request_meta"] = dict(self.trace_metadata)
        if error:
            detail["error"] = error
        if extra:
            for key, value in extra.items():
                if value in (None, ""):
                    continue
                detail[key] = value
        attempts = collect_image_attempts([result, extra])
        if attempts:
            detail["image_attempts"] = attempts
        email = str(account_email or "").strip()
        if not email:
            emails = _collect_account_emails(result)
            email = emails[0] if emails else ""
        if email:
            detail["account_email"] = email
        conv_id = str(conversation_id or "").strip()
        if not conv_id:
            conv_ids = _collect_conversation_ids(result)
            conv_id = conv_ids[0] if conv_ids else ""
        if conv_id:
            detail["conversation_id"] = conv_id
        collected_urls = [*(urls or []), *_collect_urls(result)]
        if collected_urls and not self.endpoint.startswith("/v1/search"):
            detail["urls"] = list(dict.fromkeys(collected_urls))
        if self._trace_image_perf():
            image_metrics = image_result_metrics(result)
            if image_metrics:
                detail.update(image_metrics)
        if self._trace_image_perf():
            realtime_monitor_service.finish(detail)
        log_service.add(LOG_TYPE_CALL, f"{self.summary}{suffix}", detail)
