# Copyright (c) 2026 Iyad Engle. All rights reserved.

"""process.run: subprocess.run parity, time budgets and real cancellation.

Uses real child processes (the running Python interpreter) so the behavior is
checked end to end on every platform CI runs on.
"""

import os
import subprocess
import sys
import threading
import time
from unittest.mock import MagicMock, patch

import psutil
import pytest

from netdiag.utils import process
from netdiag.utils.execution import CancelToken, ExecutionScope, ScanCancelled, activate

PY = sys.executable
SLEEP_30 = [PY, "-c", "import time; time.sleep(30)"]


def _sleeper_writing_pid(pid_file) -> list[str]:
    code = f"import os, time; open({str(pid_file)!r}, 'w').write(str(os.getpid())); time.sleep(30)"
    return [PY, "-c", code]


def _wait_for_file(path, timeout=10.0) -> int:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if path.exists() and path.read_text().strip():
            return int(path.read_text())
        time.sleep(0.02)
    raise AssertionError(f"{path} was not written")


def _gone(pid: int, timeout=5.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            if psutil.Process(pid).status() == psutil.STATUS_ZOMBIE:
                return True
        except psutil.NoSuchProcess:
            return True
        time.sleep(0.05)
    return False


class TestOutsideScan:
    def test_delegates_to_subprocess_run(self):
        with patch("netdiag.utils.process.subprocess.run", return_value="sentinel") as mock_run:
            result = process.run(["ping", "-c", "1", "x"], capture_output=True, text=True, timeout=5)
        assert result == "sentinel"
        mock_run.assert_called_once_with(
            ["ping", "-c", "1", "x"], input=None, capture_output=True, timeout=5, check=False, text=True,
        )

    def test_real_command(self):
        result = process.run([PY, "-c", "print('hi')"], capture_output=True, text=True)
        assert result.returncode == 0 and result.stdout.strip() == "hi"


class TestParityInsideScan:
    def run_both(self, *args, **kwargs):
        expected = subprocess.run(*args, **kwargs)
        with activate(ExecutionScope()):
            actual = process.run(*args, **kwargs)
        return expected, actual

    def test_stdout_stderr_returncode(self):
        cmd = [PY, "-c", "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"]
        expected, actual = self.run_both(cmd, capture_output=True, text=True)
        assert (actual.args, actual.returncode, actual.stdout, actual.stderr) == \
               (expected.args, expected.returncode, expected.stdout, expected.stderr)

    def test_bytes_output(self):
        expected, actual = self.run_both([PY, "-c", "print('x')"], capture_output=True)
        assert actual.stdout == expected.stdout and isinstance(actual.stdout, bytes)

    def test_encoding_and_errors(self):
        cmd = [PY, "-c", "import sys; sys.stdout.buffer.write(b'caf\\xc3\\xa9 \\xff')"]
        expected, actual = self.run_both(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        assert actual.stdout == expected.stdout

    def test_input(self):
        cmd = [PY, "-c", "import sys; print(sys.stdin.read().upper())"]
        expected, actual = self.run_both(cmd, input="abc", capture_output=True, text=True)
        assert actual.stdout == expected.stdout == "ABC\n"

    def test_no_capture(self):
        expected, actual = self.run_both([PY, "-c", "pass"])
        assert actual.stdout is None and actual.returncode == expected.returncode == 0

    def test_check_raises_called_process_error(self):
        with activate(ExecutionScope()):
            with pytest.raises(subprocess.CalledProcessError) as info:
                process.run([PY, "-c", "import sys; sys.exit(2)"], check=True, capture_output=True)
        assert info.value.returncode == 2

    def test_missing_executable_raises_file_not_found(self):
        # Diagnostics rely on this to report "command not found".
        with activate(ExecutionScope()):
            with pytest.raises(FileNotFoundError):
                process.run(["netdiag-no-such-command-xyz"], capture_output=True)

    def test_conflicting_arguments_rejected(self):
        with activate(ExecutionScope()):
            with pytest.raises(ValueError):
                process.run([PY, "-c", "pass"], capture_output=True, stdout=subprocess.PIPE)
            with pytest.raises(ValueError):
                process.run([PY, "-c", "pass"], input="x", stdin=subprocess.PIPE)


class TestTimeouts:
    def test_command_timeout_raises_timeout_expired_and_kills(self, tmp_path):
        pid_file = tmp_path / "pid"
        began = time.monotonic()
        with activate(ExecutionScope()):
            with pytest.raises(subprocess.TimeoutExpired) as info:
                process.run(_sleeper_writing_pid(pid_file), capture_output=True, timeout=1.0)
        assert time.monotonic() - began < 8
        assert info.value.timeout == 1.0
        assert _gone(_wait_for_file(pid_file))

    def test_step_budget_caps_a_longer_command_timeout(self):
        began = time.monotonic()
        with activate(ExecutionScope.with_budget(0.5)):
            with pytest.raises(subprocess.TimeoutExpired) as info:
                process.run(SLEEP_30, capture_output=True, timeout=30)
        assert time.monotonic() - began < 8
        assert info.value.timeout <= 0.5

    def test_step_budget_applies_without_command_timeout(self):
        began = time.monotonic()
        with activate(ExecutionScope.with_budget(0.5)):
            with pytest.raises(subprocess.TimeoutExpired):
                process.run(SLEEP_30, capture_output=True)
        assert time.monotonic() - began < 8

    def test_exhausted_budget_does_not_start_the_command(self):
        scope = ExecutionScope.with_budget(10)
        scope.expire()
        with activate(scope), patch("netdiag.utils.process.subprocess.Popen") as mock_popen:
            with pytest.raises(subprocess.TimeoutExpired):
                process.run(SLEEP_30, timeout=5)
        mock_popen.assert_not_called()

    def test_expire_from_another_thread_stops_the_command(self, tmp_path):
        pid_file = tmp_path / "pid"
        scope = ExecutionScope()
        errors = []

        def step():
            with activate(scope):
                try:
                    process.run(_sleeper_writing_pid(pid_file), capture_output=True)
                except subprocess.TimeoutExpired as exc:
                    errors.append(exc)

        thread = threading.Thread(target=step)
        thread.start()
        pid = _wait_for_file(pid_file)
        scope.expire()   # the runner's budget backstop
        thread.join(8)
        assert not thread.is_alive()
        assert len(errors) == 1
        assert _gone(pid)

    def test_fast_command_within_budget_is_unaffected(self):
        with activate(ExecutionScope.with_budget(30)):
            result = process.run([PY, "-c", "print('ok')"], capture_output=True, text=True, timeout=20)
        assert result.stdout.strip() == "ok"


class TestCancellation:
    def test_cancelled_scope_does_not_start_the_command(self):
        token = CancelToken()
        token.cancel()
        with activate(ExecutionScope(cancel_token=token)), \
             patch("netdiag.utils.process.subprocess.Popen") as mock_popen:
            with pytest.raises(ScanCancelled):
                process.run(SLEEP_30)
        mock_popen.assert_not_called()

    def test_cancel_kills_running_command_promptly(self, tmp_path):
        pid_file = tmp_path / "pid"
        token = CancelToken()
        outcome = []

        def step():
            with activate(ExecutionScope(cancel_token=token)):
                try:
                    process.run(_sleeper_writing_pid(pid_file), capture_output=True, timeout=60)
                    outcome.append("finished")
                except ScanCancelled:
                    outcome.append("cancelled")
                except Exception as exc:   # must NOT catch ScanCancelled
                    outcome.append(f"swallowed {type(exc).__name__}")

        thread = threading.Thread(target=step)
        thread.start()
        pid = _wait_for_file(pid_file)
        began = time.monotonic()
        token.cancel()
        thread.join(8)
        assert not thread.is_alive()
        assert time.monotonic() - began < 3
        assert outcome == ["cancelled"]
        assert _gone(pid)

    def test_cancel_reaches_commands_started_from_worker_threads(self, tmp_path):
        """Diagnostics with internal thread pools propagate the scope via copy_context."""
        import concurrent.futures
        import contextvars

        token = CancelToken()
        pid_files = [tmp_path / f"pid{i}" for i in range(3)]
        cancelled = []

        def probe(pid_file):
            try:
                process.run(_sleeper_writing_pid(pid_file), capture_output=True)
            except ScanCancelled:
                cancelled.append(pid_file)

        def step():
            with activate(ExecutionScope(cancel_token=token)):
                with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                    futures = [pool.submit(contextvars.copy_context().run, probe, f) for f in pid_files]
                    concurrent.futures.wait(futures)

        thread = threading.Thread(target=step)
        thread.start()
        pids = [_wait_for_file(f) for f in pid_files]
        token.cancel()
        thread.join(10)
        assert not thread.is_alive()
        assert len(cancelled) == 3
        assert all(_gone(pid) for pid in pids)

    @pytest.mark.skipif(os.name == "nt", reason="process groups are POSIX-only")
    def test_cancel_kills_the_whole_process_group(self, tmp_path):
        grandchild_pid = tmp_path / "grandchild"
        inner = _sleeper_writing_pid(grandchild_pid)
        parent_code = f"import subprocess, time; subprocess.Popen({inner!r}); time.sleep(30)"
        token = CancelToken()

        def step():
            with activate(ExecutionScope(cancel_token=token)):
                with pytest.raises(ScanCancelled):
                    process.run([PY, "-c", parent_code], capture_output=True)

        thread = threading.Thread(target=step)
        thread.start()
        pid = _wait_for_file(grandchild_pid)
        token.cancel()
        thread.join(10)
        assert not thread.is_alive()
        assert _gone(pid)

    @pytest.mark.skipif(os.name == "nt", reason="SIGTERM handling is POSIX-only")
    def test_escalates_to_kill_when_terminate_is_ignored(self, tmp_path, monkeypatch):
        monkeypatch.setattr(process, "KILL_GRACE_S", 0.3)
        pid_file = tmp_path / "pid"
        code = ("import os, signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                f"open({str(pid_file)!r}, 'w').write(str(os.getpid())); time.sleep(30)")
        token = CancelToken()

        def step():
            with activate(ExecutionScope(cancel_token=token)):
                with pytest.raises(ScanCancelled):
                    process.run([PY, "-c", code], capture_output=True)

        thread = threading.Thread(target=step)
        thread.start()
        pid = _wait_for_file(pid_file)
        token.cancel()
        thread.join(8)
        assert not thread.is_alive()
        assert _gone(pid)

    def test_keyboard_interrupt_while_waiting_kills_the_child(self):
        fake = MagicMock()
        fake.poll.return_value = None
        fake.pid = 424242
        fake.communicate.side_effect = KeyboardInterrupt
        with activate(ExecutionScope()), \
             patch("netdiag.utils.process.subprocess.Popen", return_value=fake), \
             patch("netdiag.utils.process._kill") as mock_kill:
            with pytest.raises(KeyboardInterrupt):
                process.run(SLEEP_30)
        mock_kill.assert_called_once()
        fake.wait.assert_called_once()
        fake.stdout.close.assert_called_once()   # pipes are not leaked


class TestPlatformFlags:
    def _popen_kwargs(self, monkeypatch, windows: bool, hide: bool) -> dict:
        monkeypatch.setattr(process, "_IS_WINDOWS", windows)
        fake = MagicMock()
        fake.communicate.return_value = ("", "")
        fake.poll.return_value = 0
        with activate(ExecutionScope(hide_console_windows=hide)), \
             patch("netdiag.utils.process.subprocess.Popen", return_value=fake) as mock_popen:
            process.run(["ping"], capture_output=True, text=True)
        return mock_popen.call_args.kwargs

    def test_windows_gui_hides_console_windows(self, monkeypatch):
        kwargs = self._popen_kwargs(monkeypatch, windows=True, hide=True)
        assert kwargs["creationflags"] & process.CREATE_NO_WINDOW
        assert "start_new_session" not in kwargs

    def test_windows_cli_keeps_default_flags(self, monkeypatch):
        kwargs = self._popen_kwargs(monkeypatch, windows=True, hide=False)
        assert "creationflags" not in kwargs

    def test_posix_starts_a_new_process_group(self, monkeypatch):
        kwargs = self._popen_kwargs(monkeypatch, windows=False, hide=True)
        assert kwargs["start_new_session"] is True
        assert "creationflags" not in kwargs
