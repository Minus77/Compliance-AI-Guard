"""J3: the main flow must be completable without a mouse.

Submit (Cmd/Ctrl+Enter) and Esc were already wired; moving between workspaces was
not, so a keyboard user could work inside a workspace but had to reach for the mouse
to leave it.

The digits are bound with a guard: they must not fire while someone is typing.
A rep writing "1 片每日两次" in the narrative would otherwise be thrown into
another workspace mid-sentence, which is a worse failure than having no shortcut.
"""

from __future__ import annotations


def _js(client) -> str:
    return client.get("/assets/app.js").text


def _shortcut_handler(client) -> str:
    """The keydown branch that acts on a digit.

    ``WORKSPACE_KEYS`` is declared with the other workspace constants, ~1000 lines
    above the handler that uses it, so scanning forward from the first occurrence
    reads the declaration and none of the guards.
    """
    js = _js(client)
    start = js.index("hasOwnProperty.call(WORKSPACE_KEYS")
    return js[start : start + 1200]


def test_number_keys_switch_workspaces(client):
    js = _js(client)
    assert "WORKSPACE_KEYS" in js


def test_shortcut_is_ignored_while_typing(client):
    """Otherwise typing a dose would navigate away mid-sentence."""
    body = _shortcut_handler(client)
    assert "TEXTAREA" in body
    assert "INPUT" in body


def test_shortcut_is_ignored_with_a_modifier(client):
    """Cmd+1 belongs to the browser (switch tab), not to this app."""
    body = _shortcut_handler(client)
    assert "metaKey" in body or "ctrlKey" in body


def test_shortcut_respects_capability_gating(client):
    """A shortcut must not reach a workspace the role cannot open."""
    body = _shortcut_handler(client)
    assert "allowed(" in body


def test_shortcuts_are_discoverable(client):
    """An undocumented shortcut is one nobody uses."""
    html = client.get("/").text
    assert "data-i18n-title=\"nav.shortcutHint\"" in html or "nav.shortcutHint" in html
    i18n = client.get("/assets/i18n.js").text
    assert "nav.shortcutHint" in i18n
