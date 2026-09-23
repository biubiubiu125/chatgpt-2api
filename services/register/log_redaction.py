from __future__ import annotations

import copy
from typing import Any


def redact_register_proxy(value: object) -> str:
    """Return the proxy URL unchanged. Admin logs keep credentials in plaintext."""
    return str(value or "").strip()


def redact_register_log_text(text: object) -> str:
    """Return log text unchanged. Admin registration logs are plaintext."""
    return str(text or "")


def redact_register_snapshot_inplace(snapshot: Any) -> Any:
    return snapshot


def redact_register_snapshot(snapshot: Any) -> Any:
    if isinstance(snapshot, dict):
        return copy.deepcopy(snapshot)
    return snapshot
