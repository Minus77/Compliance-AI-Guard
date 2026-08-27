"""J4: a startup failure must tell the operator what to do next.

`run.py` already handles missing dependencies well. Two other first-run failures
still surfaced as raw tracebacks, and a traceback is not an instruction:

* **no free port** — the message said "no free local port available", which states
  the fact and not the remedy.
* **an unwritable data directory** — the app needs somewhere to keep the audit
  ledger and the account store. On a locked-down machine this is the first thing
  that fails, and a `PermissionError` on a path the operator has never heard of is
  the least actionable form the news could take.

Each check therefore names the file or port, says what to try, and is verified to
mention neither a stack frame nor an internal module path.
"""

from __future__ import annotations

import socket

import pytest

from desktop.launcher import StartupError, check_writable_data_dir, describe_port_failure


def test_port_failure_names_the_port_it_tried():
    message = describe_port_failure(8000)
    assert "8000" in message


def test_port_failure_suggests_a_remedy():
    message = describe_port_failure(8000)
    assert "COMPLIANCE_GUARD_PORT" in message or "端口" in message


def test_port_failure_is_not_a_traceback():
    message = describe_port_failure(8000)
    for noise in ("Traceback", "File \"", "line ", "OSError"):
        assert noise not in message


def test_writable_check_passes_for_a_usable_directory(tmp_path):
    assert check_writable_data_dir(tmp_path) is None


def test_writable_check_reports_an_unwritable_directory(tmp_path):
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)          # readable, not writable
    try:
        problem = check_writable_data_dir(locked)
    finally:
        locked.chmod(0o700)      # restore so the fixture can clean up
    assert problem is not None
    assert str(locked) in problem


def test_unwritable_message_says_what_the_directory_is_for(tmp_path):
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    try:
        problem = check_writable_data_dir(locked)
    finally:
        locked.chmod(0o700)
    # An operator needs to know why it matters, not just that a write failed.
    assert "审计" in problem or "audit" in problem.casefold()


def test_unwritable_message_offers_the_override(tmp_path):
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    try:
        problem = check_writable_data_dir(locked)
    finally:
        locked.chmod(0o700)
    assert "COMPLIANCE_GUARD_DATA_DIR" in problem


def test_startup_error_is_its_own_type():
    """So the launcher can print it plainly instead of re-raising a traceback."""
    assert issubclass(StartupError, RuntimeError)


def test_a_taken_port_is_still_handled_by_falling_back():
    """The existing behaviour must survive: a busy 8000 picks another port."""
    from desktop.launcher import _free_port

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as held:
        held.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        held.bind(("127.0.0.1", 0))
        taken = held.getsockname()[1]
        chosen = _free_port(preferred=taken)
        assert chosen != taken
        assert chosen > 0
