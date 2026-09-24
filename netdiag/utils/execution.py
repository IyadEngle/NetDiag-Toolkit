# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""Per-step execution scope shared by the scan runner and the diagnostics.

The runner activates an `ExecutionScope` (via a ContextVar) around each step.
Diagnostic code never receives it as a parameter; instead a few helpers consult
it and fall back to plain behavior when no scope is active:

- `process.run` (netdiag.utils.process) honours cancellation and the step deadline
- `connect_host(host)` returns the IP already resolved for `host`, else `host`
- `cached(key, fn)` computes `fn()` once per scan, else on every call

Direct calls to diagnostic functions outside a scan therefore use none of
these: no cancellation, no deadline, no reuse.
"""

from __future__ import annotations

import contextvars
import logging
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any, TypeVar

logger = logging.getLogger("netdiag.execution")

T = TypeVar("T")


class ScanCancelled(BaseException):
    """Raised inside a step when its scan has been cancelled.

    Deliberately a BaseException (like asyncio.CancelledError): diagnostic
    functions wrap their work in `except Exception` and would otherwise turn a
    cancellation into a misleading ERROR result.
    """


class CancelToken:
    """Thread-safe, one-way cancellation flag with optional callbacks."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._callbacks: list[Callable[[], None]] = []

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def cancel(self) -> None:
        """Request cancellation. Idempotent; callbacks run once, in the calling thread."""
        with self._lock:
            if self._event.is_set():
                return
            self._event.set()
            callbacks, self._callbacks = self._callbacks, []
        for callback in callbacks:
            try:
                callback()
            except Exception:
                logger.exception("cancel callback failed")

    def add_callback(self, callback: Callable[[], None]) -> Callable[[], None]:
        """Run `callback` on cancellation (immediately if already cancelled).

        Returns a function that unregisters the callback.
        """
        with self._lock:
            if not self._event.is_set():
                self._callbacks.append(callback)

                def remove() -> None:
                    with self._lock:
                        if callback in self._callbacks:
                            self._callbacks.remove(callback)

                return remove
        callback()
        return lambda: None

    def wait(self, timeout: float | None = None) -> bool:
        return self._event.wait(timeout)

    def raise_if_cancelled(self) -> None:
        if self._event.is_set():
            raise ScanCancelled()


class ScanCache:
    """Per-scan cache with per-key single-flight computation.

    Concurrent callers asking for the same key wait for one computation; other
    keys are never blocked. Failed computations are not cached.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._key_locks: dict[Any, threading.Lock] = {}
        self._values: dict[Any, Any] = {}

    def get(self, key: Any, default: Any = None) -> Any:
        with self._lock:
            return self._values.get(key, default)

    def set(self, key: Any, value: Any) -> None:
        with self._lock:
            self._values[key] = value

    def __contains__(self, key: Any) -> bool:
        with self._lock:
            return key in self._values

    def get_or_compute(
        self, key: Any, compute: Callable[[], T], cache_if: Callable[[T], bool] | None = None,
    ) -> T:
        """Return the cached value for `key`, computing it once if absent.

        When `cache_if` is given, a computed value is stored only if
        `cache_if(value)` is true (e.g. cache successful handshakes only);
        otherwise the next caller computes again.
        """
        with self._lock:
            if key in self._values:
                return self._values[key]  # type: ignore[no-any-return]
            key_lock = self._key_locks.setdefault(key, threading.Lock())
        with key_lock:
            with self._lock:
                if key in self._values:
                    return self._values[key]  # type: ignore[no-any-return]
            value = compute()
            if cache_if is None or cache_if(value):
                with self._lock:
                    self._values[key] = value
            return value


class ExecutionScope:
    """Cancellation token, time budget and cache for one running step."""

    def __init__(
        self,
        cancel_token: CancelToken | None = None,
        deadline: float | None = None,
        cache: ScanCache | None = None,
        hide_console_windows: bool = False,
    ) -> None:
        self.cancel_token = cancel_token if cancel_token is not None else CancelToken()
        self.deadline = deadline                  # time.monotonic() value, or None
        self.cache = cache
        self.hide_console_windows = hide_console_windows  # Windows: CREATE_NO_WINDOW
        self._expired = threading.Event()

    @classmethod
    def with_budget(cls, budget_s: float | None, **kwargs: Any) -> ExecutionScope:
        deadline = None if budget_s is None else time.monotonic() + budget_s
        return cls(deadline=deadline, **kwargs)

    @property
    def cancelled(self) -> bool:
        return self.cancel_token.cancelled

    def remaining(self) -> float | None:
        """Seconds left in the budget (never negative), or None if unbounded."""
        if self._expired.is_set():
            return 0.0
        if self.deadline is None:
            return None
        return max(0.0, self.deadline - time.monotonic())

    @property
    def expired(self) -> bool:
        return self.remaining() == 0.0

    def expire(self) -> None:
        """Mark the budget as exhausted now (used by the runner's backstop)."""
        self._expired.set()

    def check_cancelled(self) -> None:
        self.cancel_token.raise_if_cancelled()


_current_scope: contextvars.ContextVar[ExecutionScope | None] = contextvars.ContextVar(
    "netdiag_execution_scope", default=None,
)


def current_scope() -> ExecutionScope | None:
    return _current_scope.get()


@contextmanager
def activate(scope: ExecutionScope) -> Iterator[ExecutionScope]:
    """Make `scope` the current scope for this thread/context."""
    token = _current_scope.set(scope)
    try:
        yield scope
    finally:
        _current_scope.reset(token)


def check_cancelled() -> None:
    """Raise ScanCancelled if the current scope has been cancelled (no-op outside a scan)."""
    scope = current_scope()
    if scope is not None:
        scope.check_cancelled()


def cached(key: Any, compute: Callable[[], T], cache_if: Callable[[T], bool] | None = None) -> T:
    """Compute once per scan when a cache is active; otherwise compute every call.

    `cache_if` restricts which values are kept (see ScanCache.get_or_compute).
    """
    scope = current_scope()
    if scope is None or scope.cache is None:
        return compute()
    return scope.cache.get_or_compute(key, compute, cache_if)


def cached_value(key: Any, default: Any = None) -> Any:
    """Look up a value cached earlier in this scan without computing anything."""
    scope = current_scope()
    if scope is None or scope.cache is None:
        return default
    return scope.cache.get(key, default)


_RESOLUTION_KEY = "resolved_ipv4"


def remember_resolution(host: str, address: str) -> None:
    """Record the address `host` resolved to, for reuse by later steps of this scan."""
    scope = current_scope()
    if scope is not None and scope.cache is not None:
        scope.cache.set((_RESOLUTION_KEY, host.lower()), address)


def connect_host(host: str) -> str:
    """Address to use for a network connection to `host`.

    Returns the address resolved earlier in this scan, or `host` unchanged when
    none is known (including outside a scan). Callers must keep using `host`
    itself for user-facing labels, TLS SNI and certificate verification.
    """
    scope = current_scope()
    if scope is None or scope.cache is None:
        return host
    address = scope.cache.get((_RESOLUTION_KEY, host.lower()))
    return address if isinstance(address, str) else host
