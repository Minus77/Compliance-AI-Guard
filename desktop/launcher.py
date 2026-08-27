"""Desktop launcher: start the local server, then open the UI in a browser.

Packaged builds have no console, so this entry point:

- picks a free port (the fixed 8000 is often already taken),
- defaults to ``LLM_MODE=mock`` so a packaged copy is offline unless the operator
  explicitly opts into live model calls,
- writes a log file into the per-user data directory for troubleshooting,
- opens the default browser once the server answers,
- shuts down cleanly on SIGINT/SIGTERM.

There is deliberately no bundled Chromium/webview: the demo runs offline by
default, and the system browser keeps the download small.

**On the offline claim.** ``setdefault`` is a default, not a lock: an operator who
exports ``LLM_MODE=live`` before launching gets real model calls, which is
intentional so a packaged build can be pointed at a real provider. The UI never
lies about it -- the header badge and ``/health`` report which mode is active. If a
build must be incapable of network calls, pin the value instead of defaulting it.
"""

from __future__ import annotations

import logging
import os
import signal
import socket
import sys
import threading
import time
import urllib.request
import webbrowser

HOST = "127.0.0.1"


class StartupError(RuntimeError):
    """A startup problem the operator can act on.

    Its own type so the launcher can print the message plainly instead of
    re-raising. A traceback tells a developer where the code was; it tells an
    operator nothing about what to do next, and first-run failures are exactly
    when the reader is least equipped to translate one.
    """


def describe_port_failure(preferred: int) -> str:
    """Explain that no local port could be bound, and what to try.

    "no free local port available" states the fact and withholds the remedy, which
    is the difference between a diagnosis and an error string.
    """
    return (
        f"无法绑定本机端口（已尝试 {preferred} 和系统随机端口）。\n"
        f"Could not bind a local port (tried {preferred} and an OS-assigned one).\n"
        "  · 可能有其他程序占用了端口，或本机防火墙阻止了监听。\n"
        "    Another process may hold the port, or a local firewall is blocking it.\n"
        "  · 可指定其他端口后重试：COMPLIANCE_GUARD_PORT=8123 python3 run.py\n"
        "    Retry with a specific port: COMPLIANCE_GUARD_PORT=8123 python3 run.py"
    )


def check_writable_data_dir(path) -> str | None:
    """Return a problem description when ``path`` cannot hold runtime state.

    The app needs somewhere to keep the audit ledger and the account store. On a
    locked-down machine this is the first thing that fails, and a bare
    ``PermissionError`` on a path the operator has never seen is the least
    actionable form the news could take -- so the directory, its purpose, and the
    override are all named.
    """
    from pathlib import Path

    target = Path(path)
    probe = target / ".write-probe"
    try:
        target.mkdir(parents=True, exist_ok=True)
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as error:
        return (
            f"无法写入运行数据目录：{target}\n"
            f"Cannot write to the runtime data directory: {target}\n"
            f"  · 原因 / reason: {error.strerror or error}\n"
            "  · 该目录用于保存审计账本与本地账号，必须可写。\n"
            "    It holds the audit ledger and local accounts, so it must be writable.\n"
            "  · 可改用其他目录：COMPLIANCE_GUARD_DATA_DIR=/path/to/dir python3 run.py\n"
            "    Use another location: COMPLIANCE_GUARD_DATA_DIR=/path/to/dir python3 run.py"
        )
    return None


def _free_port(preferred: int = 8000) -> int:
    """Return ``preferred`` when free, otherwise an OS-assigned free port."""
    for candidate in (preferred, 0):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind((HOST, candidate))
            except OSError:
                continue
            return probe.getsockname()[1]
    raise StartupError(describe_port_failure(preferred))


def _configure_logging() -> "os.PathLike[str] | str":
    from compliance_guard.runtime_paths import writable_data_dir

    log_path = writable_data_dir() / "launcher.log"
    logging.basicConfig(
        filename=str(log_path),
        filemode="a",
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    return log_path


def _wait_until_ready(url: str, timeout: float = 45.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:  # noqa: S310
                if response.status == 200:
                    return True
        except Exception:  # noqa: BLE001 - server not up yet is expected
            time.sleep(0.3)
    return False


# Re-exported: the implementation lives with the code that generates the password,
# so every entry point announces it rather than just this one.
from compliance_guard.security.sessions import (  # noqa: E402
    announce_bootstrap_credential,
)


def main() -> int:
    # Offline by default: set the mode before importing the application so the
    # gateway cannot pick a live adapter by accident. An explicit LLM_MODE=live
    # from the environment is honoured on purpose (see the module docstring).
    os.environ.setdefault("LLM_MODE", "mock")

    log_path = _configure_logging()
    logging.info("launcher starting (frozen=%s)", getattr(sys, "frozen", False))

    try:
        import uvicorn

        from apps.api.main import app
    except Exception:
        logging.exception("failed to import the application")
        raise

    # Read the credential off the composed service graph rather than provisioning
    # a second store: two stores would mean two different user files.
    try:
        sessions = app.state.services.sessions
        announce_bootstrap_credential(
            "admin", sessions.bootstrap_password
        )
    except AttributeError:
        # A service graph without sessions is not a reason to refuse to start.
        logging.warning("session store unavailable; no bootstrap credential announced")

    # Check writability before binding: an unwritable data directory fails later
    # and more confusingly, in the middle of the first request.
    from compliance_guard.runtime_paths import user_data_dir

    problem = check_writable_data_dir(user_data_dir())
    if problem is not None:
        raise StartupError(problem)

    # An explicit port wins, so the remedy the error message suggests actually works.
    preferred = 8000
    override = os.environ.get("COMPLIANCE_GUARD_PORT")
    if override and override.strip().isdigit():
        preferred = int(override.strip())
    port = _free_port(preferred)
    base_url = f"http://{HOST}:{port}"
    logging.info("serving on %s (log: %s)", base_url, log_path)

    config = uvicorn.Config(app, host=HOST, port=port, log_level="warning")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, name="uvicorn", daemon=True)
    thread.start()

    # SIGTERM must also unwind cleanly. Without an explicit handler the default
    # disposition kills the process outright, so the shutdown path below never
    # runs and the log ends mid-session with no "stopped" record -- which is
    # exactly how this gap was caught during verification.
    stopping = threading.Event()

    def _request_stop(signum, _frame):
        logging.info("signal %s received; shutting down", signum)
        stopping.set()
        server.should_exit = True

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _request_stop)
        except (ValueError, OSError):
            # Not the main thread, or the platform lacks the signal: the
            # KeyboardInterrupt path below still covers Ctrl+C.
            pass

    if _wait_until_ready(f"{base_url}/health"):
        logging.info("server ready; opening browser")
        webbrowser.open(base_url)
    else:
        logging.error("server did not become ready in time")

    try:
        while thread.is_alive() and not stopping.is_set():
            thread.join(timeout=0.5)
    except KeyboardInterrupt:
        logging.info("interrupt received; shutting down")
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        logging.info("launcher stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
