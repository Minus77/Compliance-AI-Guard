"""The way forward must reach the screen, and the copy must not over-promise.

Two gaps found by running the real server:

1. The response carried `guidance.rewrite` and the interface never rendered it.
   A way forward computed but not displayed is the same, from the author's seat,
   as no way forward at all.

2. The blocked copy said "请按改写建议修改" — follow the rewrite suggestion —
   unconditionally. After inducement was narrowed to guidance-only there often is
   no suggestion, so the instruction pointed at something absent. Copy that
   promises a control the reader cannot find is worse than plainer copy.
"""

from __future__ import annotations

import json

from compliance_guard.runtime_paths import config_dir


def test_rewrite_block_exists_in_the_markup(client):
    html = client.get("/").text
    assert 'id="rewrite-block"' in html
    assert 'id="rewrite-suggestion"' in html
    assert 'id="rewrite-guidance"' in html


def test_rewrite_is_rendered_from_the_response(client):
    js = client.get("/assets/app.js").text
    assert "function renderRewrite" in js
    assert "renderRewrite(" in js


def test_suggestion_is_only_shown_when_verified(client):
    """Displaying an unverified suggestion would mean proposing the violation."""
    js = client.get("/assets/app.js").text
    start = js.index("function renderRewrite")
    body = js[start : start + 1600]
    assert "verified" in body
    assert "available" in body


def test_guidance_is_shown_even_when_no_suggestion_exists(client):
    js = client.get("/assets/app.js").text
    start = js.index("function renderRewrite")
    body = js[start : start + 1600]
    assert "guidance" in body


def test_copy_does_not_promise_a_suggestion_that_may_be_absent():
    payload = json.loads((config_dir() / "glossary.json").read_text(encoding="utf-8"))
    blocked = payload["decisions"]["blocked"]
    assert "改写建议" not in blocked["zh-CN"]["next_step"]
    assert "rewrite suggestion" not in blocked["en"]["next_step"].casefold()


def test_blocked_copy_still_offers_a_route(client):
    """Removing the over-promise must not remove the next step."""
    payload = json.loads((config_dir() / "glossary.json").read_text(encoding="utf-8"))
    blocked = payload["decisions"]["blocked"]
    assert blocked["zh-CN"]["next_step"]
    assert "申诉" in blocked["zh-CN"]["next_step"]
    assert "appeal" in blocked["en"]["next_step"].casefold()


def test_rewrite_styles_exist(client):
    css = client.get("/assets/styles.css").text
    assert "rewrite-block" in css
