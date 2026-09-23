from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence
SLOW_GENERATION_SECONDS = 60.0


@dataclass(frozen=True)
class AccountDispatchStats:
    inflight: int = 0
    generating_seconds: float = 0.0
    success: int = 0
    fail: int = 0

    @property
    def total_generations(self) -> int:
        return max(0, int(self.success) + int(self.fail) + int(self.inflight))

    def is_slow(self, threshold: float = SLOW_GENERATION_SECONDS) -> bool:
        return int(self.inflight) > 0 and float(self.generating_seconds) >= float(threshold)


def dispatch_group(
    stats: AccountDispatchStats,
    account_concurrency: int,
    slow_seconds: float = SLOW_GENERATION_SECONDS,
) -> int:
    inflight = max(0, int(stats.inflight))
    max_concurrency = max(1, int(account_concurrency or 1))
    if inflight <= 0:
        return 0
    if inflight >= max_concurrency:
        return 3
    if stats.is_slow(slow_seconds):
        return 2
    return 1


def rank_image_account_tokens(
    tokens: Sequence[str],
    stats_by_token: Mapping[str, AccountDispatchStats],
    *,
    account_concurrency: int,
    slow_seconds: float = SLOW_GENERATION_SECONDS,
    rotate: int = 0,
) -> list[str]:
    items = list(tokens)
    count = len(items)
    offset = int(rotate) % count if count else 0

    def sort_key(item: tuple[int, str]) -> tuple[int, int, int]:
        index, token = item
        stats = stats_by_token.get(token) or AccountDispatchStats()
        return (
            dispatch_group(stats, account_concurrency, slow_seconds),
            stats.total_generations,
            (index - offset) % count if count else 0,
        )

    return [token for _, token in sorted(enumerate(items), key=sort_key)]
