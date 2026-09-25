from __future__ import annotations

import asyncio
import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Iterator

from services.runtime_configuration import env_int


class ImageGenerationQueueFullError(RuntimeError):
    code = "image_generation_busy"

    def __init__(self) -> None:
        super().__init__("Image generation queue is full. Please try again later.")


class _Admission:
    def __init__(self, slots: int, deadline_monotonic: float = 0.0) -> None:
        self.slots = slots
        self.remaining = slots
        self.running = 0
        self.prepaid = 0
        self.state = "open"
        self.handed_off = False
        self.deadline_monotonic = deadline_monotonic


class _AsyncWaiter:
    def __init__(self) -> None:
        self.loop = asyncio.get_running_loop()
        self.event = asyncio.Event()

    def wake(self) -> None:
        try:
            self.loop.call_soon_threadsafe(self.event.set)
        except RuntimeError:
            return


_CURRENT: ContextVar[_Admission | None] = ContextVar(
    "chatgpt2api_image_generation_admission",
    default=None,
)


class ImageGenerationGate:
    """Shared limit for every image generation, including sync API calls and panel tasks."""

    def __init__(self, workers: int, queue_size: int) -> None:
        self.workers = max(1, int(workers))
        self.queue_size = max(0, int(queue_size))
        self._capacity = self.workers + self.queue_size
        self._condition = threading.Condition()
        self._reserved = 0
        self._running = 0
        self._async_waiters: list[_AsyncWaiter] = []
        self._handler_limiter = None

    @property
    def reserved(self) -> int:
        with self._condition:
            return self._reserved

    @property
    def running(self) -> int:
        with self._condition:
            return self._running

    def wait_until_reserved(self, count: int, timeout: float) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        with self._condition:
            while self._reserved < count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            return True

    def handler_limiter(self):
        if self._handler_limiter is None:
            from anyio import CapacityLimiter

            self._handler_limiter = CapacityLimiter(self._capacity)
        return self._handler_limiter

    def current(self) -> _Admission | None:
        return _CURRENT.get()

    def bind(self, admission: _Admission) -> Token:
        return _CURRENT.set(admission)

    def unbind(self, token: Token) -> None:
        _CURRENT.reset(token)

    def admit(self, slots: int = 1, *, deadline_monotonic: float = 0.0) -> _Admission:
        count = max(1, int(slots))
        with self._condition:
            if self._reserved + count > self._capacity:
                raise ImageGenerationQueueFullError()
            self._reserved += count
            admission = _Admission(count, deadline_monotonic)
            self._notify_locked()
            return admission

    def acquire_running(
        self,
        admission: _Admission,
        deadline_monotonic: float | None = None,
    ) -> None:
        with self._condition:
            while True:
                self._ensure_open(admission)
                if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
                    raise ImageGenerationQueueFullError()
                if admission.prepaid > 0:
                    admission.prepaid -= 1
                    admission.running += 1
                    return
                if (
                    admission.remaining > admission.running
                    and self._running < self.workers
                ):
                    self._running += 1
                    admission.running += 1
                    self._notify_locked()
                    return
                timeout = None
                if deadline_monotonic is not None:
                    timeout = max(0.0, deadline_monotonic - time.monotonic())
                self._condition.wait(timeout)

    async def acquire_running_async(
        self,
        admission: _Admission,
        deadline_monotonic: float | None = None,
    ) -> None:
        while True:
            waiter: _AsyncWaiter | None = None
            with self._condition:
                self._ensure_open(admission)
                if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
                    raise ImageGenerationQueueFullError()
                if (
                    admission.remaining > admission.running + admission.prepaid
                    and self._running < self.workers
                ):
                    self._running += 1
                    admission.prepaid += 1
                    self._notify_locked()
                    return
                waiter = _AsyncWaiter()
                self._async_waiters.append(waiter)
                timeout = None
                if deadline_monotonic is not None:
                    timeout = max(0.0, deadline_monotonic - time.monotonic())
            try:
                if timeout == 0:
                    raise ImageGenerationQueueFullError()
                if timeout is None:
                    await waiter.event.wait()
                else:
                    await asyncio.wait_for(waiter.event.wait(), timeout)
            except TimeoutError:
                raise ImageGenerationQueueFullError() from None
            finally:
                with self._condition:
                    try:
                        self._async_waiters.remove(waiter)
                    except ValueError:
                        pass

    def release_running(self, admission: _Admission) -> None:
        with self._condition:
            if admission.running <= 0:
                return
            if self._running <= 0 or self._reserved <= 0 or admission.remaining <= 0:
                raise RuntimeError("image generation gate count underflow")
            admission.running -= 1
            admission.remaining -= 1
            self._running -= 1
            self._reserved -= 1
            self._notify_locked()

    def release_worker_keep_reservation(self, admission: _Admission) -> None:
        """Free a running worker without dropping this request's queue reservation."""

        with self._condition:
            if admission.running <= 0:
                return
            if self._running <= 0:
                raise RuntimeError("image generation gate count underflow")
            admission.running -= 1
            self._running -= 1
            self._notify_locked()

    def release(self, admission: _Admission) -> None:
        with self._condition:
            if admission.state != "open":
                return
            idle = admission.remaining - admission.running
            if (
                admission.prepaid > idle
                or admission.prepaid > self._running
                or admission.running > self._running
                or idle > self._reserved
            ):
                raise RuntimeError("image generation gate count underflow")
            self._running -= admission.prepaid
            self._reserved -= idle
            admission.remaining = admission.running
            admission.prepaid = 0
            admission.state = "closed"
            self._notify_locked()

    @contextmanager
    def slot(
        self,
        *,
        deadline_monotonic: float | None = None,
        admission: _Admission | None = None,
    ) -> Iterator[None]:
        current = _CURRENT.get()
        if current is not None and current.state == "open":
            yield
            return
        if admission is None:
            admission = self.admit(1)
        token = _CURRENT.set(admission)
        try:
            self.acquire_running(admission, deadline_monotonic)
            try:
                yield
            finally:
                self.release_running(admission)
        finally:
            _CURRENT.reset(token)
            self.release(admission)

    def _ensure_open(self, admission: _Admission) -> None:
        if admission.state != "open":
            raise ImageGenerationQueueFullError()

    def _notify_locked(self) -> None:
        self._condition.notify_all()
        for waiter in list(self._async_waiters):
            waiter.wake()


image_generation_gate = ImageGenerationGate(
    env_int("CHATGPT2API_IMAGE_TASK_WORKERS", 16),
    env_int("CHATGPT2API_IMAGE_TASK_QUEUE_SIZE", 256),
)
