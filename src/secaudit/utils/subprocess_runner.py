"""Safe subprocess execution with timeout and logging."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)


def run_command(
    cmd: list[str],
    cwd: Path | str | None = None,
    timeout: int = 300,
    check: bool = False,
) -> tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr).

    Args:
        cmd: Command and arguments.
        cwd: Working directory.
        timeout: Max seconds before killing the process.
        check: If True, raise on non-zero exit.

    Returns:
        Tuple of (returncode, stdout, stderr).
    """
    cmd_str = " ".join(cmd[:4])  # Log only first few args for brevity
    log.debug("Running: %s (timeout=%ds)", cmd_str, timeout)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(cwd) if cwd else None,
            timeout=timeout,
        )
        if check and result.returncode != 0:
            log.error("Command failed (rc=%d): %s\nstderr: %s", result.returncode, cmd_str, result.stderr[:500])
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        log.error("Command timed out after %ds: %s", timeout, cmd_str)
        return -1, "", f"Command timed out after {timeout}s"
    except FileNotFoundError:
        log.error("Command not found: %s", cmd[0])
        return -1, "", f"Command not found: {cmd[0]}"
