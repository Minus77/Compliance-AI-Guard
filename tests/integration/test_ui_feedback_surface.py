"""C3 in the browser: a reviewer must be able to report a misclassification.

The feedback loop was built end to end -- store, confirmation by a second person,
export into the golden set -- and reachable only by calling the API directly. A
reviewer noticing a false positive had nowhere to say so, which means the loop that
turns production failures into regression cases never actually closes.

The buttons live on the review task, next to the decision form, because that is the
moment the judgement is being made. A separate admin screen would be visited by
nobody at the point where the observation is fresh.
"""

from __future__ import annotations


def _js(client) -> str:
    return client.get("/assets/app.js").text


def test_feedback_buttons_are_rendered_on_a_review_task(client):
    js = _js(client)
    assert "function feedbackFormHtml" in js
    assert "feedbackFormHtml(" in js


def test_both_directions_can_be_reported(client):
    """A false positive and a missed risk are different failures."""
    js = _js(client)
    start = js.index("function feedbackFormHtml")
    body = js[start : start + 1400]
    assert "false_positive" in body
    assert "false_negative" in body


def test_reporting_calls_the_case_feedback_endpoint(client):
    js = _js(client)
    assert "/feedback" in js
    assert "function submitFeedback" in js


def test_a_reason_is_required_before_sending(client):
    """The reason is what makes a candidate reviewable later."""
    js = _js(client)
    start = js.index("function submitFeedback")
    body = js[start : start + 1200]
    assert "feedback-reason" in body


def test_the_second_confirmation_is_surfaced(client):
    """A candidate needs a different person to confirm it; that must be visible."""
    js = _js(client)
    assert "/api/feedback" in js
    assert "confirm" in js


def test_feedback_wording_exists_in_both_locales(client):
    i18n = client.get("/assets/i18n.js").text
    for key in (
        "feedback.title",
        "feedback.falsePositive",
        "feedback.falseNegative",
        "feedback.reason",
        "feedback.submit",
        "feedback.sent",
    ):
        assert i18n.count(f'"{key}"') >= 2, f"{key} is missing from a locale"


def test_feedback_styles_exist(client):
    css = client.get("/assets/styles.css").text
    assert "feedback-form" in css
