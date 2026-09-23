from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Header, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.exc import SQLAlchemyError

from api.support import require_admin
from services.register_service import register_service
from utils.diagnostics import sanitize_diagnostic_text
from utils.log import logger


_REGISTER_STORAGE_ERRORS = (SQLAlchemyError, OSError)
_REGISTER_STORAGE_ERROR_DETAIL = {
    "error": "register_storage_unavailable",
    "message": "注册存储暂时不可用。",
}


def _register_storage_http_exception(exc: Exception) -> HTTPException:
    logger.error({
        "event": "register_storage_unavailable",
        "error_type": exc.__class__.__name__,
        "error": sanitize_diagnostic_text(exc),
    })
    return HTTPException(
        status_code=503,
        detail=dict(_REGISTER_STORAGE_ERROR_DETAIL),
    )


def _register_storage_stream_payload(exc: Exception) -> dict[str, object]:
    logger.error({
        "event": "register_storage_stream_unavailable",
        "error_type": exc.__class__.__name__,
        "error": sanitize_diagnostic_text(exc),
    })
    return {
        "error": {
            "message": _REGISTER_STORAGE_ERROR_DETAIL["message"],
            "type": "server_error",
            "code": _REGISTER_STORAGE_ERROR_DETAIL["error"],
        },
    }

class RegisterConfigRequest(BaseModel):
    mail: dict | None = None
    proxy: str | None = None
    proxy_required: bool | None = None
    total: int | None = None
    threads: int | None = None
    mode: str | None = None
    target_quota: int | None = None
    target_available: int | None = None
    auto_schedule_enabled: bool | None = None
    register_peak: dict | None = None
    register_offpeak: dict | None = None
    check_interval: int | None = None


class OutlookPoolResetRequest(BaseModel):
    scope: str | None = None


class CoreResultRetryRequest(BaseModel):
    email: str | None = None


def create_router() -> APIRouter:
    router = APIRouter()

    @router.get("/api/register")
    async def get_register_config(authorization: str | None = Header(default=None)):
        require_admin(authorization)
        try:
            return {"register": await run_in_threadpool(register_service.get)}
        except _REGISTER_STORAGE_ERRORS as exc:
            raise _register_storage_http_exception(exc) from exc

    @router.post("/api/register")
    async def update_register_config(body: RegisterConfigRequest, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        try:
            return {
                "register": await run_in_threadpool(
                    register_service.update,
                    body.model_dump(exclude_none=True),
                )
            }
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except _REGISTER_STORAGE_ERRORS as exc:
            raise _register_storage_http_exception(exc) from exc

    @router.post("/api/register/start")
    async def start_register(authorization: str | None = Header(default=None)):
        require_admin(authorization)
        try:
            return {"register": await run_in_threadpool(register_service.start)}
        except _REGISTER_STORAGE_ERRORS as exc:
            raise _register_storage_http_exception(exc) from exc

    @router.post("/api/register/stop")
    async def stop_register(authorization: str | None = Header(default=None)):
        require_admin(authorization)
        try:
            return {"register": await run_in_threadpool(register_service.stop)}
        except _REGISTER_STORAGE_ERRORS as exc:
            raise _register_storage_http_exception(exc) from exc

    @router.post("/api/register/reset")
    async def reset_register(authorization: str | None = Header(default=None)):
        require_admin(authorization)
        try:
            return {"register": await run_in_threadpool(register_service.reset)}
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except _REGISTER_STORAGE_ERRORS as exc:
            raise _register_storage_http_exception(exc) from exc

    @router.post("/api/register/outlook-pool/reset")
    async def reset_outlook_pool(body: OutlookPoolResetRequest, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        try:
            return {
                "register": await run_in_threadpool(
                    register_service.reset_outlook_pool,
                    body.scope or "all",
                )
            }
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except _REGISTER_STORAGE_ERRORS as exc:
            raise _register_storage_http_exception(exc) from exc

    @router.get("/api/register/core-results/pending")
    async def list_pending_core_results(authorization: str | None = Header(default=None)):
        require_admin(authorization)
        from services.register.core_result_recovery import list_pending_core_results as list_recovery_items

        try:
            return {"items": await run_in_threadpool(list_recovery_items)}
        except _REGISTER_STORAGE_ERRORS as exc:
            raise _register_storage_http_exception(exc) from exc

    @router.post("/api/register/core-results/retry")
    async def retry_pending_core_results(
        body: CoreResultRetryRequest,
        authorization: str | None = Header(default=None),
    ):
        require_admin(authorization)
        try:
            return {
                "recovery": await run_in_threadpool(
                    register_service.reconcile_pending_core_results,
                    force=True,
                    email=str(body.email or "").strip(),
                )
            }
        except _REGISTER_STORAGE_ERRORS as exc:
            raise _register_storage_http_exception(exc) from exc

    @router.post("/api/register/events")
    async def register_events(authorization: str | None = Header(default=None)):
        require_admin(authorization)

        async def stream():
            last = ""
            while True:
                try:
                    snapshot = await run_in_threadpool(register_service.get)
                except _REGISTER_STORAGE_ERRORS as exc:
                    error_payload = _register_storage_stream_payload(exc)
                    yield "event: error\n"
                    yield f"data: {json.dumps(error_payload, ensure_ascii=False)}\n\n"
                    yield "data: [DONE]\n\n"
                    return
                payload = json.dumps(snapshot, ensure_ascii=False)
                if payload != last:
                    last = payload
                    yield f"data: {payload}\n\n"
                await asyncio.sleep(0.5)

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    return router
