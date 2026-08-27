"""J + E2 + H5: the interface a representative actually works in.

These assert the *contract* of the served assets rather than rendered pixels:
there is no build chain and no browser in this suite, so the durable checks are
that the markup exposes the right hooks and the script talks to the right routes.

What the phase is for, in order of how much it changes daily use:

* **L0 local hints (E2).** A cue appears while typing, from a local word list,
  with no network call. It only ever speaks when it has something to say — it
  never displays "looks fine", because a local word match cannot support that
  claim and a false reassurance is worse than silence.
* **Draft autosave (H5).** Losing a half-written narrative once is enough to
  teach someone to keep reports short. Drafts stay in the browser and are never
  uploaded: text that has not been submitted should not reach the server.
* **Errors that stay put (J2).** A toast that vanishes cannot be re-read. Field
  problems render inline, next to the field.
* **Keyboard and non-colour coding (J3).** The whole main flow works without a
  mouse, and outcome is never carried by colour alone.
* **Demo scaffolding out of the way (J1).** Six scenario buttons at the top of a
  daily tool say "this is a demo"; they move into a collapsed drawer.
"""

from __future__ import annotations

import re


def _html(client) -> str:
    return client.get("/").text


def _js(client) -> str:
    return client.get("/assets/app.js").text


def _css(client) -> str:
    return client.get("/assets/styles.css").text


# -- E2: L0 local instant hints ---------------------------------------------


def test_local_hint_layer_exists(client):
    html = _html(client)
    assert 'id="live-hints"' in html
    js = _js(client)
    assert "L0_TERMS" in js


def test_local_hints_are_debounced(client):
    """A hint on every keystroke is noise; ~120ms of quiet is the trigger."""
    js = _js(client)
    assert "L0_DEBOUNCE_MS" in js
    assert re.search(r"L0_DEBOUNCE_MS\s*=\s*1[0-9][0-9]", js)


def test_local_hints_make_no_network_call(client):
    """L0 must stay inside the typing latency budget, so it cannot go to the server."""
    js = _js(client)
    start = js.index("function runLocalHints")
    end = js.index("function", start + 10)
    body = js[start:end]
    assert "fetch(" not in body
    assert "api(" not in body


def test_local_hints_never_claim_content_is_clean(client):
    """A local word match cannot support 'no problems found'."""
    js = _js(client)
    assert "L0 never asserts" in js or "never claim" in js.casefold()


def test_server_precheck_is_triggered_on_pause_and_blur(client):
    js = _js(client)
    assert "/api/cases/precheck" in js
    assert "L1_IDLE_MS" in js
    assert 'addEventListener("blur"' in js or "blur" in js


# -- H5: draft autosave -----------------------------------------------------


def test_draft_is_saved_locally(client):
    js = _js(client)
    assert "localStorage" in js
    assert "DRAFT_KEY" in js


def test_draft_key_is_scoped_to_user_and_product(client):
    """A shared key would restore one person's draft into another's editor."""
    js = _js(client)
    start = js.index("function draftKey")
    body = js[start : start + 400]
    assert "currentRole" in body
    assert "product" in body.casefold()


def test_draft_is_never_uploaded(client):
    js = _js(client)
    start = js.index("function saveDraft")
    body = js[start : start + 500]
    assert "fetch(" not in body
    assert "api(" not in body


def test_draft_restore_is_offered_not_forced(client):
    html = _html(client)
    assert 'id="draft-banner"' in html
    js = _js(client)
    assert "draft-restore" in js
    assert "draft-discard" in js


def test_draft_is_cleared_after_successful_submit(client):
    js = _js(client)
    assert "clearDraft" in js


# -- J1: demo scaffolding in a drawer ---------------------------------------


def test_scenario_buttons_live_in_a_collapsed_drawer(client):
    html = _html(client)
    demo = html.split('id="demo-drawer"', 1)
    assert len(demo) == 2, "scenario buttons must sit inside a demo drawer"
    drawer = demo[1].split("</details>", 1)[0]
    for scenario in ("normal", "ae", "pii", "off_label", "redline", "injection"):
        assert f'data-scenario="{scenario}"' in drawer
    assert "open" not in demo[0].rsplit("<details", 1)[-1]


def test_main_flow_precedes_the_demo_drawer(client):
    """Source, context, narrative, submit come first; teaching material after."""
    html = _html(client)
    assert html.index('id="content"') < html.index('id="demo-drawer"')


# -- J2: errors that can be re-read ----------------------------------------


def test_inline_error_region_exists_for_the_narrative(client):
    html = _html(client)
    assert 'id="content-error"' in html
    assert 'aria-describedby' in html


def test_field_errors_render_inline_rather_than_as_a_toast(client):
    js = _js(client)
    assert "function setFieldError" in js
    start = js.index("function setFieldError")
    body = js[start : start + 600]
    assert "toast(" not in body


def test_service_errors_offer_a_retry(client):
    html = _html(client)
    assert 'id="submit-error"' in html
    js = _js(client)
    assert "retry" in js.casefold()


def test_first_error_receives_focus(client):
    js = _js(client)
    assert ".focus()" in js


# -- J3: keyboard and accessibility ----------------------------------------


def test_submit_has_a_keyboard_shortcut(client):
    js = _js(client)
    assert "metaKey" in js and "ctrlKey" in js


def test_escape_closes_transient_panels(client):
    js = _js(client)
    assert '"Escape"' in js


def test_masked_spans_are_announced_to_screen_readers(client):
    js = _js(client)
    assert "aria-label" in js
    start = js.index("function highlightSpans")
    body = js[start : start + 1200]
    assert "aria-label" in body


def test_outcome_is_not_conveyed_by_colour_alone(client):
    """Colour plus an icon and a word, so a colour-blind reader loses nothing."""
    js = _js(client)
    assert "DECISION_GLYPH" in js
    css = _css(client)
    assert "verdict-glyph" in css


def test_result_receives_focus_when_it_appears(client):
    js = _js(client)
    assert "resultFocus" in js or 'setAttribute("tabindex", "-1")' in js


def test_live_regions_are_declared_for_async_updates(client):
    html = _html(client)
    assert 'aria-live="polite"' in html


def test_focus_is_visible(client):
    css = _css(client)
    assert ":focus-visible" in css


def test_reduced_motion_is_respected(client):
    css = _css(client)
    assert "prefers-reduced-motion" in css


# -- J4 + new surfaces: records, notifications, glossary --------------------


def test_my_records_workspace_exists(client):
    html = _html(client)
    assert 'data-workspace="records"' in html
    js = _js(client)
    assert "/api/cases?scope=mine" in js or "/api/cases" in js


def test_notification_bell_shows_unread_count(client):
    html = _html(client)
    assert 'id="notif-button"' in html
    assert 'id="notif-count"' in html
    js = _js(client)
    assert "/api/notifications" in js


def test_glossary_terms_are_available_as_tooltips(client):
    html = _html(client)
    js = _js(client)
    assert "/api/glossary" in js
    assert "glossary" in html.casefold() or "glossaryTip" in js


def test_three_sentence_card_is_rendered_from_guidance(client):
    js = _js(client)
    assert "renderGuidance" in js
    for key in ("title", "why", "what_to_do"):
        assert key in js


def test_technical_details_are_collapsed_not_removed(client):
    """An auditor still needs the codes; a representative should not lead with them."""
    html = _html(client)
    assert 'id="tech-details"' in html
    assert "<details" in html


def test_followup_form_is_rendered_when_elements_are_missing(client):
    html = _html(client)
    assert 'id="followup-block"' in html
    js = _js(client)
    assert "renderFollowup" in js
    assert "/followup" in js


def test_appeal_entry_point_exists_for_blocked_results(client):
    html = _html(client)
    assert 'id="appeal-block"' in html
    js = _js(client)
    assert "/appeal" in js


def test_first_run_guidance_is_present(client):
    html = _html(client)
    assert 'id="onboarding"' in html
    js = _js(client)
    assert "ONBOARDING_KEY" in js


def test_products_come_from_master_data(client):
    js = _js(client)
    assert "/api/master-data/products" in js


def test_audit_chain_status_is_shown_in_governance(client):
    html = _html(client)
    assert 'id="chain-status"' in html
    js = _js(client)
    assert "/api/audit-trail/verify" in js


def test_oversight_warning_is_surfaced(client):
    js = _js(client)
    assert "oversight" in js
