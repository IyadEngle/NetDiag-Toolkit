# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later

"""Cancellable drop-in replacement for `subprocess.run`.

Outside a scan (no active ExecutionScope) `run` simply delegates to
`subprocess.run`, so direct calls to diagnostic functions are unchanged.

Inside a scan step it:
- refuses to start a command once the scan is cancelled (ScanCancelled)
- caps the command timeout at the step's remaining time budget
- polls while the command runs; on cancellation or budget expiry it terminates
  the command (its whole process group on POSIX), escalating to kill
- raises subprocess.TimeoutExpired on timeout, exactly like subprocess.run,
  so the diagnostics' existing timeout handling keeps working
- hides console windows on Windows when the scope asks for it (GUI)
"""

from __future__ import annotations

import os
import signal
import subprocess
import time
from typing import Any

from netdiag.utils.execution import ExecutionScope, ScanCancelled, current_scope

_IS_WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

POLL_INTERVAL_S = 0.1   # how quickly cancellation / budget expiry is noticed
KILL_GRACE_S = 2.0      # time between terminate and kill


def run(
    args: Any,
    *,
    input: Any = None,
    capture_output: bool = False,
    timeout: float | None = None,
    check: bool = False,
    **kwargs: Any,
) -> subprocess.CompletedProcess:
    """Same contract as `subprocess.run`, plus scan cancellation and time budgets."""
    scope = current_scope()
    if scope is None:
        return subprocess.run(
            args, input=input, capture_output=capture_output, timeout=timeout, check=check, **kwargs,
        )
    return _run_in_scope(scope, args, input, capture_output, timeout, check, kwargs)


def _run_in_scope(
    scope: ExecutionScope,
    args: Any,
    input: Any,
    capture_output: bool,
    timeout: float | None,
    check: bool,
    kwargs: dict[str, Any],
) -> subprocess.CompletedProcess:
    scope.check_cancelled()

    remaining = scope.remaining()
    effective_timeout = timeout
    if remaining is not None:
        effective_timeout = remaining if timeout is None else min(timeout, remaining)
    if effective_timeout is not None and effective_timeout <= 0:
        raise subprocess.TimeoutExpired(args, timeout if timeout is not None else 0)

    if input is not None:
        if kwargs.get("stdin") is not None:
            raise ValueError("stdin and input arguments may not both be used.")
        kwargs["stdin"] = subprocess.PIPE
    if capture_output:
        if kwargs.get("stdout") is not None or kwargs.get("stderr") is not None:
            raise ValueError("stdout and stderr arguments may not be used with capture_output.")
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    if _IS_WINDOWS:
        if scope.hide_console_windows:
            kwargs["creationflags"] = kwargs.get("creationflags", 0) | CREATE_NO_WINDOW
    else:
        # Own process group, so cancellation can stop any children as well.
        kwargs.setdefault("start_new_session", True)
    own_group = not _IS_WINDOWS and bool(kwargs.get("start_new_session"))

    started = time.monotonic()
    proc = subprocess.Popen(args, **kwargs)
    stop_reason: str | None = None   # "cancelled" | "timeout"
    stop_requested_at = 0.0
    killed = False
    pending_input = input
    try:
        while True:
            try:
                stdout, stderr = proc.communicate(pending_input, timeout=POLL_INTERVAL_S)
                break
            except subprocess.TimeoutExpired:
                pending_input = None   # input is sent on the first communicate() only

            if stop_reason is None:
                if scope.cancelled:
                    stop_reason = "cancelled"
                elif scope.expired or (
                    effective_timeout is not None and time.monotonic() - started >= effective_timeout
                ):
                    stop_reason = "timeout"
                if stop_reason is not None:
                    stop_requested_at = time.monotonic()
                    _terminate(proc, own_group)
            elif not killed and time.monotonic() - stop_requested_at >= KILL_GRACE_S:
                _kill(proc, own_group)
                killed = True
    except BaseException:
        # Includes KeyboardInterrupt: never leave the child running.
        _kill(proc, own_group)
        proc.wait()
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream:
                stream.close()
        raise

    if stop_reason == "cancelled":
        raise ScanCancelled()
    if stop_reason == "timeout":
        reported = effective_timeout if effective_timeout is not None else time.monotonic() - started
        raise subprocess.TimeoutExpired(args, reported, output=stdout, stderr=stderr)

    retcode = proc.poll()
    assert retcode is not None
    if check and retcode:
        raise subprocess.CalledProcessError(retcode, args, output=stdout, stderr=stderr)
    return subprocess.CompletedProcess(args, retcode, stdout, stderr)


def _terminate(proc: subprocess.Popen, own_group: bool) -> None:
    _signal(proc, signal.SIGTERM, own_group)


def _kill(proc: subprocess.Popen, own_group: bool) -> None:
    _signal(proc, getattr(signal, "SIGKILL", signal.SIGTERM), own_group)


def _signal(proc: subprocess.Popen, sig: int, own_group: bool) -> None:
    if proc.poll() is not None:
        return
    try:
        if _IS_WINDOWS:
            proc.kill()   # TerminateProcess; Windows has no graceful equivalent
        elif own_group:
            os.killpg(proc.pid, sig)   # the child leads its own process group
        else:
            proc.send_signal(sig)
    except (ProcessLookupError, PermissionError):
        pass
