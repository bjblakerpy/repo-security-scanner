"""Token bucket rate limiter for API calls."""

from __future__ import annotations

import threading
import time


class RateLimiter:
    """Simple token bucket rate limiter.

    Usage:
        limiter = RateLimiter(max_per_second=3.0)
        for item in items:
            limiter.wait()
            api_call(item)
    """

    def __init__(self, max_per_second: float = 3.0):
        self._interval = 1.0 / max_per_second
        self._last_call = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        """Block until a request slot is available."""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_call
            if elapsed < self._interval:
                time.sleep(self._interval - elapsed)
            self._last_call = time.monotonic()
