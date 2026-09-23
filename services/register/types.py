from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RegistrationWindow:
    name: str
    target_available: int
    time_range: str
    threads: int = 1
