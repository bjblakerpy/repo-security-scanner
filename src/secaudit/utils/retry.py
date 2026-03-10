"""Exponential backoff retry decorator for API calls."""

from __future__ import annotations

import functools
import logging
import time
from typing import Any, Callable

log = logging.getLogger(__name__)


def retry(
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    exceptions: tuple[type[Exception], ...] = (Exception,),
) -> Callable:
    """Retry a function with exponential backoff.

    Args:
        max_attempts: Maximum number of attempts.
        base_delay: Initial delay in seconds.
        max_delay: Maximum delay between retries.
        exceptions: Tuple of exception types to catch.
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exception = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt == max_attempts:
                        log.error("All %d attempts failed for %s: %s", max_attempts, func.__name__, e)
                        raise
                    delay = min(base_delay * (2 ** (attempt - 1)), max_delay)
                    log.warning(
                        "Attempt %d/%d failed for %s: %s. Retrying in %.1fs",
                        attempt,
                        max_attempts,
                        func.__name__,
                        e,
                        delay,
                    )
                    time.sleep(delay)
            raise last_exception  # Should not reach here

        return wrapper

    return decorator
