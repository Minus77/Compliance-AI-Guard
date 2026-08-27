"""The bootstrap credential must reach the operator, and only the operator.

A generated password that is never shown makes a first run unusable: the account
exists, the password is unknowable, and the app asks for a credential nobody has.

The constraint that shapes the implementation is where it may appear. Not the log
file: ``launcher.log`` lives in the per-user data directory, is written on every
run, and gets attached to bug reports. Putting a working password there would place
a plaintext credential on disk beside its own hash, which is exactly what hashing
the password was meant to avoid.

So it goes to stdout, once, on the run that generates it.
"""

from __future__ import annotations

import logging

from desktop.launcher import announce_bootstrap_credential


class _Recorder(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def test_password_is_printed_for_the_operator(capsys):
    announce_bootstrap_credential("admin", "generated-secret-value")
    out = capsys.readouterr().out
    assert "generated-secret-value" in out
    assert "admin" in out


def test_password_never_reaches_the_log_file(capsys):
    """launcher.log is on disk and ends up in bug reports."""
    recorder = _Recorder()
    root = logging.getLogger()
    previous = root.level
    # The launcher configures INFO via basicConfig; the root logger defaults to
    # WARNING, so without this the record is filtered and the test would pass for
    # the wrong reason -- proving only that nothing was logged at all.
    root.setLevel(logging.INFO)
    root.addHandler(recorder)
    try:
        announce_bootstrap_credential("admin", "generated-secret-value")
    finally:
        root.removeHandler(recorder)
        root.setLevel(previous)

    assert not any("generated-secret-value" in message for message in recorder.messages)
    # The event is still recorded, just not the value.
    assert any("bootstrap" in message.casefold() for message in recorder.messages)


def test_nothing_is_announced_when_there_is_no_new_password(capsys):
    """A later start reuses an established account; silence is correct there."""
    announce_bootstrap_credential("admin", None)
    assert capsys.readouterr().out == ""


def test_announcement_says_the_password_must_be_changed(capsys):
    announce_bootstrap_credential("admin", "generated-secret-value")
    out = capsys.readouterr().out
    assert "修改" in out or "change" in out.casefold()


def test_announcement_says_it_will_not_be_shown_again(capsys):
    """Otherwise an operator assumes they can find it later, and they cannot."""
    announce_bootstrap_credential("admin", "generated-secret-value")
    out = capsys.readouterr().out
    assert "仅显示一次" in out or "only once" in out.casefold()
