"""Tests for utility modules: retry, rate_limiter, subprocess_runner."""

import time
from unittest.mock import MagicMock, patch

import pytest

from secaudit.utils.rate_limiter import RateLimiter
from secaudit.utils.retry import retry
from secaudit.utils.subprocess_runner import run_command


class TestRetry:
    def test_succeeds_first_try(self):
        call_count = 0

        @retry(max_attempts=3, base_delay=0.01)
        def succeed():
            nonlocal call_count
            call_count += 1
            return "ok"

        assert succeed() == "ok"
        assert call_count == 1

    def test_retries_on_failure_then_succeeds(self):
        call_count = 0

        @retry(max_attempts=3, base_delay=0.01)
        def fail_twice():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("not yet")
            return "ok"

        assert fail_twice() == "ok"
        assert call_count == 3

    def test_raises_after_max_attempts(self):
        @retry(max_attempts=2, base_delay=0.01)
        def always_fail():
            raise ValueError("always fails")

        with pytest.raises(ValueError, match="always fails"):
            always_fail()

    def test_only_catches_specified_exceptions(self):
        @retry(max_attempts=3, base_delay=0.01, exceptions=(TypeError,))
        def raise_value_error():
            raise ValueError("wrong type")

        with pytest.raises(ValueError):
            raise_value_error()

    def test_exponential_backoff_timing(self):
        call_times = []

        @retry(max_attempts=3, base_delay=0.05, max_delay=1.0)
        def track_timing():
            call_times.append(time.monotonic())
            if len(call_times) < 3:
                raise ValueError("retry")
            return "ok"

        track_timing()
        assert len(call_times) == 3
        # Second delay should be roughly 2x the first
        delay1 = call_times[1] - call_times[0]
        delay2 = call_times[2] - call_times[1]
        assert delay2 > delay1 * 1.5  # Allow some slack


class TestRateLimiter:
    def test_rate_limiting(self):
        limiter = RateLimiter(max_per_second=100.0)  # Fast for testing
        start = time.monotonic()
        for _ in range(5):
            limiter.wait()
        elapsed = time.monotonic() - start
        # 5 calls at 100/s = at least 0.04s (4 intervals)
        assert elapsed >= 0.03

    def test_no_delay_on_first_call(self):
        limiter = RateLimiter(max_per_second=1.0)
        start = time.monotonic()
        limiter.wait()
        elapsed = time.monotonic() - start
        assert elapsed < 0.1  # First call should be near-instant


class TestSubprocessRunner:
    def test_successful_command(self):
        rc, stdout, stderr = run_command(["echo", "hello"])
        assert rc == 0
        assert "hello" in stdout

    def test_command_failure(self):
        rc, stdout, stderr = run_command(["ls", "/nonexistent_path_xyz"])
        assert rc != 0

    def test_command_not_found(self):
        rc, stdout, stderr = run_command(["nonexistent_binary_xyz"])
        assert rc == -1
        assert "not found" in stderr.lower()

    def test_timeout(self):
        rc, stdout, stderr = run_command(["sleep", "10"], timeout=1)
        assert rc == -1
        assert "timed out" in stderr.lower()

    def test_cwd(self, tmp_path):
        rc, stdout, stderr = run_command(["pwd"], cwd=tmp_path)
        assert rc == 0
        assert str(tmp_path) in stdout
