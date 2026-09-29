from __future__ import annotations

from collections.abc import Callable
from typing import Any


class ImageJsonResult:
    """Non-stream image work that must start only while the response is already open.

    The caller returns this immediately. The log layer writes leading whitespace,
    then runs ``produce`` and writes the final JSON. A plain dict is unchanged.
    """

    def __init__(self, produce: Callable[[], dict[str, Any]]) -> None:
        self.produce = produce
