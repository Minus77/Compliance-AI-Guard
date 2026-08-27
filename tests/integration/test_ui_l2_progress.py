"""E3: a wait longer than a second must be visible, and degradation must be named.

Two gaps the plan audit found in the submit path.

**Progress.** Offline the model answers in milliseconds; against a real provider the
same path measured 5.1-19.7s p95 on this host. A spinner that says only "checking"
for nineteen seconds reads as a hang, and the rep's next move is to press submit
again or reload -- which is how a narrative gets lost. Past one second the interface
says what it is waiting for.

**Degradation.** When the model is unavailable the server returns ``MANUAL_DEGRADED``
rather than an approval. That is the right behaviour and it is invisible: the rep
sees a result they cannot interpret. The interface has to say, in plain words, that
the AI check did not complete, the content was kept, and a person now has it. Without
that sentence a fail-safe outcome feels like a failure.
"""

from __future__ import annotations

import re


def _js(client) -> str:
    return client.get("/assets/app.js").text


def _html(client) -> str:
    return client.get("/").text


def _i18n(client) -> str:
    return client.get("/assets/i18n.js").text


# -- progress state ---------------------------------------------------------


def test_progress_threshold_is_one_second(client):
    js = _js(client)
    assert "L2_PROGRESS_MS" in js
    assert re.search(r"L2_PROGRESS_MS\s*=\s*1000", js)


def test_progress_escalation_is_scheduled_on_submit(client):
    js = _js(client)
    start = js.index("function submitCase")
    body = js[start : start + 1800]
    assert "L2_PROGRESS_MS" in body


def test_progress_timer_is_always_cleared(client):
    """A timer left running would flip a finished result back to 'still working'."""
    js = _js(client)
    start = js.index("function submitCase")
    body = js[start : start + 2400]
    assert body.count("clearTimeout(progressTimer)") >= 2


def test_progress_message_says_what_is_being_waited_for(client):
    i18n = _i18n(client)
    assert "rep.checkingSlow" in i18n


def test_progress_region_is_announced(client):
    html = _html(client)
    loading = html.split('id="check-loading"', 1)[1][:200]
    assert "aria-live" in html.split('id="check-loading"', 1)[0][-200:] or "aria-live" in loading


# -- degraded outcome -------------------------------------------------------


def test_degraded_notice_exists_in_the_markup(client):
    html = _html(client)
    assert 'id="degraded-notice"' in html


def test_degraded_state_is_detected_from_the_response(client):
    js = _js(client)
    assert "MANUAL_DEGRADED" in js
    assert "function renderDegraded" in js


def test_degraded_message_explains_the_three_things_that_matter(client):
    """AI did not finish, content was kept, a person has it."""
    i18n = _i18n(client)
    for key in ("degraded.title", "degraded.body", "degraded.next"):
        assert key in i18n


def test_degraded_message_never_reads_as_an_approval(client):
    i18n = _i18n(client)
    block = i18n.split('"degraded.body"', 1)[1][:400]
    assert "通过" not in block.split("\n")[0]


def test_degraded_notice_has_styles(client):
    css = client.get("/assets/styles.css").text
    assert "degraded-notice" in css
