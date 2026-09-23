from __future__ import annotations

from enum import StrEnum
from typing import Any


class RegisterCoreStage(StrEnum):
    PREFLIGHT = "preflight"
    MAILBOX_PREP = "mailbox_prep"
    FINGERPRINT_SENTINEL = "fingerprint_sentinel"
    ACCOUNT_CREATE = "account_create"
    CODE_WAIT = "code_wait"
    TOKEN_EXCHANGE = "token_exchange"
    FINALIZE = "finalize"
    FAILED = "failed"


_ALLOWED_TRANSITIONS: dict[RegisterCoreStage, frozenset[RegisterCoreStage]] = {
    RegisterCoreStage.PREFLIGHT: frozenset(
        {RegisterCoreStage.PREFLIGHT, RegisterCoreStage.MAILBOX_PREP}
    ),
    RegisterCoreStage.MAILBOX_PREP: frozenset(
        {RegisterCoreStage.MAILBOX_PREP, RegisterCoreStage.FINGERPRINT_SENTINEL}
    ),
    RegisterCoreStage.FINGERPRINT_SENTINEL: frozenset(
        {
            RegisterCoreStage.FINGERPRINT_SENTINEL,
            RegisterCoreStage.CODE_WAIT,
            RegisterCoreStage.ACCOUNT_CREATE,
        }
    ),
    RegisterCoreStage.CODE_WAIT: frozenset(
        {
            RegisterCoreStage.CODE_WAIT,
            RegisterCoreStage.ACCOUNT_CREATE,
            RegisterCoreStage.TOKEN_EXCHANGE,
        }
    ),
    RegisterCoreStage.ACCOUNT_CREATE: frozenset(
        {RegisterCoreStage.ACCOUNT_CREATE, RegisterCoreStage.TOKEN_EXCHANGE}
    ),
    RegisterCoreStage.TOKEN_EXCHANGE: frozenset(
        {RegisterCoreStage.TOKEN_EXCHANGE, RegisterCoreStage.FINALIZE}
    ),
    RegisterCoreStage.FINALIZE: frozenset({RegisterCoreStage.FINALIZE}),
    RegisterCoreStage.FAILED: frozenset({RegisterCoreStage.FAILED}),
}


class RegisterCoreStateMachine:
    """注册核心状态机，负责限制跳步并保留最后一条失败/过程证据。"""

    def __init__(self, initial: RegisterCoreStage = RegisterCoreStage.PREFLIGHT) -> None:
        self._state = initial
        self._detail = ""
        self._failure_detail = ""
        self._failed_from: RegisterCoreStage | None = None
        self._history: list[dict[str, str]] = []

    @property
    def state(self) -> RegisterCoreStage:
        return self._state

    @property
    def detail(self) -> str:
        return self._detail

    def transition(self, stage: RegisterCoreStage | str, detail: str = "") -> RegisterCoreStage:
        target = stage if isinstance(stage, RegisterCoreStage) else RegisterCoreStage(str(stage))
        allowed = _ALLOWED_TRANSITIONS[self._state]
        if target not in allowed:
            raise ValueError(
                f"invalid register core transition: {self._state.value} -> {target.value}"
            )
        self._state = target
        self._detail = str(detail or "")
        self._history.append({"stage": target.value, "detail": self._detail})
        return self._state

    def fail(self, detail: str = "") -> RegisterCoreStage:
        message = str(detail or "")
        if self._state is not RegisterCoreStage.FAILED:
            self._failed_from = self._state
            self._state = RegisterCoreStage.FAILED
            self._history.append({"stage": self._state.value, "detail": message})
        self._detail = message
        self._failure_detail = message
        return self._state

    def snapshot(self) -> dict[str, Any]:
        return {
            "stage": self._state.value,
            "detail": self._detail,
            "failure_detail": self._failure_detail,
            "failed_from": self._failed_from.value if self._failed_from else "",
            "history": [dict(item) for item in self._history],
        }
