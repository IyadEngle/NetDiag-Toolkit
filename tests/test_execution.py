# Copyright (c) 2026 Iyad Engle. All rights reserved.

"""Execution scope primitives: cancellation, deadlines, context propagation, caches."""

import contextvars
import threading
import time

import pytest

from netdiag.utils.execution import (
    CancelToken,
    ExecutionScope,
    ScanCache,
    ScanCancelled,
    activate,
    cached,
    check_cancelled,
    connect_host,
    current_scope,
    remember_resolution,
)


class TestScanCancelled:
    def test_not_swallowed_by_except_exception(self):
        """Diagnostics wrap work in `except Exception`; cancellation must pass through."""
        def diagnostic_like():
            try:
                raise ScanCancelled()
            except Exception:
                return "swallowed"

        with pytest.raises(ScanCancelled):
            diagnostic_like()

    def test_is_base_exception_not_exception(self):
        assert issubclass(ScanCancelled, BaseException)
        assert not issubclass(ScanCancelled, Exception)


class TestCancelToken:
    def test_cancel_is_idempotent_and_callbacks_run_once(self):
        token = CancelToken()
        calls = []
        token.add_callback(lambda: calls.append(1))
        token.cancel()
        token.cancel()
        assert token.cancelled
        assert calls == [1]

    def test_callback_added_after_cancel_runs_immediately(self):
        token = CancelToken()
        token.cancel()
        calls = []
        token.add_callback(lambda: calls.append(1))
        assert calls == [1]

    def test_removed_callback_does_not_run(self):
        token = CancelToken()
        calls = []
        remove = token.add_callback(lambda: calls.append(1))
        remove()
        token.cancel()
        assert calls == []

    def test_failing_callback_does_not_stop_others(self):
        token = CancelToken()
        calls = []

        def boom():
            raise RuntimeError("boom")

        token.add_callback(boom)
        token.add_callback(lambda: calls.append(1))
        token.cancel()
        assert calls == [1]

    def test_wait_and_raise(self):
        token = CancelToken()
        assert token.wait(0.01) is False
        token.raise_if_cancelled()
        threading.Timer(0.05, token.cancel).start()
        assert token.wait(2) is True
        with pytest.raises(ScanCancelled):
            token.raise_if_cancelled()


class TestExecutionScope:
    def test_unbounded_scope(self):
        scope = ExecutionScope()
        assert scope.remaining() is None
        assert not scope.expired

    def test_budget_counts_down_and_expires(self):
        scope = ExecutionScope.with_budget(0.05)
        remaining = scope.remaining()
        assert remaining is not None and 0 < remaining <= 0.05
        time.sleep(0.07)
        assert scope.remaining() == 0.0
        assert scope.expired

    def test_expire_forces_zero_remaining(self):
        scope = ExecutionScope.with_budget(60)
        scope.expire()
        assert scope.expired and scope.remaining() == 0.0
        unbounded = ExecutionScope()
        unbounded.expire()
        assert unbounded.expired

    def test_cancel_via_shared_token(self):
        token = CancelToken()
        scope_a = ExecutionScope(cancel_token=token)
        scope_b = ExecutionScope(cancel_token=token)
        token.cancel()
        assert scope_a.cancelled and scope_b.cancelled
        with pytest.raises(ScanCancelled):
            scope_a.check_cancelled()


class TestActivation:
    def test_no_scope_by_default(self):
        assert current_scope() is None
        check_cancelled()  # no-op outside a scan

    def test_activate_sets_and_restores(self):
        outer, inner = ExecutionScope(), ExecutionScope()
        with activate(outer):
            assert current_scope() is outer
            with activate(inner):
                assert current_scope() is inner
            assert current_scope() is outer
        assert current_scope() is None

    def test_restored_after_exception(self):
        with pytest.raises(RuntimeError):
            with activate(ExecutionScope()):
                raise RuntimeError
        assert current_scope() is None

    def test_scope_is_per_thread(self):
        seen = []
        with activate(ExecutionScope()):
            thread = threading.Thread(target=lambda: seen.append(current_scope()))
            thread.start()
            thread.join()
        assert seen == [None]

    def test_copy_context_propagates_scope_to_threads(self):
        scope = ExecutionScope()
        seen = []
        with activate(scope):
            ctx = contextvars.copy_context()
        thread = threading.Thread(target=ctx.run, args=(lambda: seen.append(current_scope()),))
        thread.start()
        thread.join()
        assert seen == [scope]

    def test_check_cancelled_inside_scope(self):
        token = CancelToken()
        with activate(ExecutionScope(cancel_token=token)):
            check_cancelled()
            token.cancel()
            with pytest.raises(ScanCancelled):
                check_cancelled()


class TestScanCache:
    def test_computes_once(self):
        cache = ScanCache()
        calls = []
        for _ in range(3):
            assert cache.get_or_compute("k", lambda: calls.append(1) or "v") == "v"
        assert calls == [1]
        assert "k" in cache and cache.get("k") == "v"

    def test_single_flight_under_concurrency(self):
        cache = ScanCache()
        calls = []
        start = threading.Barrier(8)
        results = []

        def compute():
            calls.append(1)
            time.sleep(0.1)
            return "cert"

        def worker():
            start.wait()
            results.append(cache.get_or_compute(("tls", "h", 443), compute))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert calls == [1]
        assert results == ["cert"] * 8

    def test_different_keys_do_not_block_each_other(self):
        cache = ScanCache()
        slow_started = threading.Event()
        release = threading.Event()

        def slow():
            slow_started.set()
            release.wait(5)
            return "slow"

        thread = threading.Thread(target=lambda: cache.get_or_compute("a", slow))
        thread.start()
        assert slow_started.wait(2)
        began = time.monotonic()
        assert cache.get_or_compute("b", lambda: "fast") == "fast"
        assert time.monotonic() - began < 1
        release.set()
        thread.join()

    def test_failures_are_not_cached(self):
        cache = ScanCache()
        attempts = []

        def flaky():
            attempts.append(1)
            if len(attempts) == 1:
                raise OSError("first attempt fails")
            return "ok"

        with pytest.raises(OSError):
            cache.get_or_compute("k", flaky)
        assert cache.get_or_compute("k", flaky) == "ok"
        assert len(attempts) == 2

    def test_cancellation_is_not_cached(self):
        cache = ScanCache()

        def cancelled():
            raise ScanCancelled()

        with pytest.raises(ScanCancelled):
            cache.get_or_compute("k", cancelled)
        assert "k" not in cache


class TestCachedHelper:
    def test_outside_scan_computes_every_time(self):
        calls = []
        cached("k", lambda: calls.append(1))
        cached("k", lambda: calls.append(1))
        assert len(calls) == 2

    def test_scope_without_cache_computes_every_time(self):
        calls = []
        with activate(ExecutionScope()):
            cached("k", lambda: calls.append(1))
            cached("k", lambda: calls.append(1))
        assert len(calls) == 2

    def test_shared_cache_across_step_scopes(self):
        cache = ScanCache()
        calls = []
        with activate(ExecutionScope(cache=cache)):
            assert cached("k", lambda: calls.append(1) or 42) == 42
        with activate(ExecutionScope(cache=cache)):
            assert cached("k", lambda: calls.append(1) or 99) == 42
        assert calls == [1]


class TestResolutionReuse:
    def test_outside_scan_returns_host(self):
        remember_resolution("example.com", "93.184.216.34")  # no-op without a scope
        assert connect_host("example.com") == "example.com"

    def test_unknown_host_returns_host(self):
        with activate(ExecutionScope(cache=ScanCache())):
            assert connect_host("example.com") == "example.com"

    def test_remembered_address_is_reused_case_insensitively(self):
        cache = ScanCache()
        with activate(ExecutionScope(cache=cache)):
            remember_resolution("Example.COM", "93.184.216.34")
        with activate(ExecutionScope(cache=cache)):
            assert connect_host("example.com") == "93.184.216.34"
            assert connect_host("other.example") == "other.example"

    def test_scope_without_cache_returns_host(self):
        with activate(ExecutionScope()):
            remember_resolution("example.com", "93.184.216.34")
            assert connect_host("example.com") == "example.com"
