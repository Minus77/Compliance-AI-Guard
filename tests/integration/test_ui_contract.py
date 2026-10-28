"""Embedded UI contract: served pages, assets, and workspace entry points."""

import re
from pathlib import Path


def test_ui_serves_seven_workspaces(client):
    response = client.get("/")
    assert response.status_code == 200
    html = response.text
    for marker in (
        "workspace-overview",
        "workspace-content_check",
        "workspace-conversation_guard",
        "workspace-reviews",
        "workspace-rules",
        "workspace-quality_audit",
        "workspace-settings",
    ):
        assert marker in html


def test_ui_exposes_both_check_entries_and_seven_workspaces():
    html = Path("src/compliance_guard/web/index.html").read_text(encoding="utf-8")
    for workspace in (
        "overview",
        "content_check",
        "conversation_guard",
        "reviews",
        "rules",
        "quality_audit",
        "settings",
    ):
        assert f'data-workspace="{workspace}"' in html
    assert 'id="content-check"' in html
    assert 'id="conversation-guard"' in html


def test_ui_assets_served(client):
    assert client.get("/assets/styles.css").status_code == 200
    assert client.get("/assets/app.js").status_code == 200
    assert client.get("/assets/i18n.js").status_code == 200


def test_ui_contract_exposes_workspace_entry_points(client):
    html = client.get("/").text
    # Anchor on the stable markup contract, not on rendered label text: the nav
    # labels are localized (zh-CN by default) and carry data-i18n keys, so
    # asserting English strings would only be testing the default locale.
    for workspace in (
        "overview",
        "content_check",
        "conversation_guard",
        "reviews",
        "rules",
        "quality_audit",
        "settings",
    ):
        assert f'data-workspace="{workspace}"' in html
    for key in (
        "nav.overview",
        "nav.content_check",
        "nav.conversation_guard",
        "nav.reviews",
        "nav.rules",
        "nav.quality_audit",
        "nav.settings",
    ):
        assert f'data-i18n="{key}"' in html
    assert "x-demo-role" in html


def test_ui_contract_references_api_endpoints(client):
    js = client.get("/assets/app.js").text
    for endpoint in (
        "/api/checks",
        "/api/checks/precheck",
        "/api/cases/check",
        "/api/reviews",
        "/api/config/models",
        "/api/config/publish",
        "/api/config/rollback",
        "/api/conversations/guard-input",
        "/api/metrics",
    ):
        assert endpoint in js


def test_ui_renders_structured_spans_only_for_the_current_content_version(client):
    js = client.get("/assets/app.js").text
    assert "content_version" in js
    assert "spans_stale" in js
    assert "currentContentVersion" in js
    assert "renderStructuredSpans" in js
    assert 'if (result.spans_stale || result.content_version !== currentContentVersion)' in js
    assert 'id="content-recheck"' in client.get("/").text


def test_ui_never_renders_a_blocked_or_withdrawn_ai_body(client):
    js = client.get("/assets/app.js").text
    assert 'state === "input_blocked"' in js
    assert 'state === "generating"' in js
    assert 'state === "output_withdrawn"' in js
    assert 'state === "safe_replacement"' in js
    assert 'state === "failed_safe"' in js
    assert "published_text" in js
    assert "conversation-body" in client.get("/").text


def test_language_switch_preserves_editor_and_check_identity(client):
    js = client.get("/assets/app.js").text
    assert "persistEditorState" in js
    assert "draftKey()" in js
    assert "currentCheckId" in js
    i18n = client.get("/assets/i18n.js").text
    assert '"conv.state.input_blocked"' in i18n
    assert '"conv.state.generating"' in i18n
    assert '"conv.state.output_withdrawn"' in i18n
    assert '"conv.state.safe_replacement"' in i18n
    assert '"nav.shortcutHint": "按 1–7' in i18n
    assert '"nav.shortcutHint": "Press 1-7' in i18n


def test_mobile_layout_keeps_review_actions_reachable(client):
    css = client.get("/assets/styles.css").text
    mobile = css.split("@media (max-width: 900px)", 1)[1]
    assert ".review-layout" in mobile
    assert ".review-detail-pane" in mobile
    assert ".review-decision" in mobile or ".review-actions" in mobile


def test_ui_contract_has_semantic_form_elements(client):
    html = client.get("/").text
    assert 'type="button"' in html
    assert 'type="submit"' in html
    assert 'id="content"' in html
    assert 'aria-label' in html or 'aria-labelledby' in html


def test_ui_reviewer_allow_option_disabled_for_s0_s1(client):
    js = client.get("/assets/app.js").text
    assert 'severity === "S0" || severity === "S1"' in js
    assert "value='accepted' disabled" in js


def test_ui_offers_both_interface_locales(client):
    html = client.get("/").text
    assert 'id="ui-locale"' in html
    assert 'value="zh-CN"' in html
    assert 'value="en"' in html
    assert "简体中文" in html
    assert "English" in html


def test_ui_locale_tables_cover_both_languages(client):
    js = client.get("/assets/i18n.js").text
    assert '"zh-CN": {' in js
    assert '"en": {' in js


def test_scenario_payload_text_stays_chinese_in_every_locale(client):
    """Risk detection is keyed on Chinese terms, so payload text must not be localized.

    ``agents/pv_signal.py`` and ``security/injection_scan.py`` match Chinese
    keywords and the evidence fixtures are zh-CN only. Translating the scenario
    narratives would silently disable AE, redline, and injection detection.
    """
    js = client.get("/assets/app.js").text
    for term in ("皮疹", "昏迷", "忽略所有规则"):
        assert term in js


def test_request_language_field_is_not_driven_by_interface_locale(client):
    js = client.get("/assets/app.js").text
    # The payload language comes from the business context select, never the UI locale.
    assert 'language: el("ctx-language").value' in js
    assert 'language: i18n.locale()' not in js


def test_ui_exposes_upload_entry_points_for_image_and_audio(client):
    html = client.get("/").text
    assert 'id="attach-image-input"' in html
    assert 'id="attach-audio-input"' in html
    assert 'accept="image/*"' in html
    assert 'accept="audio/*"' in html


def test_ui_gates_workspaces_from_server_permission_matrix(client):
    js = client.get("/assets/app.js").text
    assert "/api/permissions" in js
    # Workspace visibility must be keyed on capabilities, not a hard-coded role list.
    assert "WORKSPACE_CAPABILITY" in js
    for capability in ("view_case_summary", "review_case", "architecture_review"):
        assert capability in js


def test_ui_renders_rag_retrieval_stages(client):
    js = client.get("/assets/app.js").text
    assert "renderRag" in js
    i18n = client.get("/assets/i18n.js").text
    for stage in ("query_build", "metadata_filter", "lexical_score", "stance_split"):
        assert f"rag.stage.{stage}" in i18n


def test_ui_uses_pluggable_source_connectors(client):
    js = client.get("/assets/app.js").text
    assert "/api/sources" in js
    html = client.get("/").text
    assert 'id="src-connector"' in html
    assert 'id="src-record"' in html


def test_ui_shows_phrase_and_raw_code_together(client):
    """Audit values must stay visible next to their natural-language phrasing."""
    js = client.get("/assets/app.js").text
    assert "function labelled(" in js
    assert "code-tag" in js


def test_locale_tables_cover_severity_explanations(client):
    i18n = client.get("/assets/i18n.js").text
    for level in ("S0", "S1", "S2", "S3"):
        assert f"sev.{level}.name" in i18n
        assert f"sev.{level}.desc" in i18n


# ---------------------------------------------------------------------------
# Pharma-professional UI surfaces
# ---------------------------------------------------------------------------


def test_ui_exposes_pv_icsr_panel(client):
    html = client.get("/").text
    for marker in ('id="pv-block"', 'id="pv-clock"', 'id="pv-criteria"', 'id="pv-meta"'):
        assert marker in html
    js = client.get("/assets/app.js").text
    assert "renderIcsr" in js


def test_locale_tables_cover_icsr_and_signature_terms(client):
    i18n = client.get("/assets/i18n.js").text
    for criterion in (
        "identifiable_patient",
        "identifiable_reporter",
        "suspect_product",
        "suspect_reaction",
    ):
        assert f"pv.criterion.{criterion}" in i18n
    for key in ("pv.clockTitle", "pv.dayZero", "pv.due", "pv.aggregate"):
        assert key in i18n
    for key in ("sig.title", "sig.meaning", "sig.digest", "sig.kind"):
        assert key in i18n


def test_ui_exposes_governance_workspace(client):
    html = client.get("/").text
    assert 'data-workspace="quality_audit"' in html
    for marker in ('id="gov-integrity"', 'id="connector-table"', 'id="audit-table"'):
        assert marker in html
    js = client.get("/assets/app.js").text
    assert "/api/audit-trail" in js
    assert "/api/connectors" in js


def test_governance_workspace_is_gated_on_audit_export(client):
    js = client.get("/assets/app.js").text
    assert "quality_audit: \"audit_export\"" in js


def test_ui_offers_exactly_the_four_demo_roles(client):
    """The picker is deliberately four roles, one per workspace.

    The full pharma matrix still exists server-side in
    ``security/authorization.py`` (MSL, QPPV, MLR, QA, regulatory affairs); the
    selector only exposes the four needed to demo every workspace, so the demo
    stays legible instead of presenting twelve near-identical options.
    """
    html = client.get("/").text
    select = html.split('id="role"', 1)[1].split("</select>", 1)[0]
    offered = re.findall(r'value="([a-z_]+)"', select)
    assert offered == ["author", "reviewer", "auditor", "architect"]


def test_server_still_recognizes_the_wider_pharma_role_matrix(client):
    """Narrowing the picker must not narrow the permission matrix."""
    for role in ("msl", "qppv", "mlr_reviewer", "qa", "regulatory_affairs"):
        response = client.get("/api/permissions", headers={"x-demo-role": role})
        assert response.status_code == 200
        assert response.json()["role"] == role


def test_hidden_attribute_is_enforced_in_css(client):
    """Role gating and conditional panels toggle `hidden`; a class-level
    `display` would silently defeat it without this guard."""
    css = client.get("/assets/styles.css").text
    assert "[hidden]" in css
    assert "display: none !important" in css


def test_signature_block_is_rendered_from_the_decision_record(client):
    html = client.get("/").text
    assert 'id="signature-block"' in html
    js = client.get("/assets/app.js").text
    assert "renderSignature" in js
    # The strength marker must be surfaced, not hidden.
    assert "signature_kind" in js


def test_audit_workspace_descriptions_are_localized(client):
    """The ALCOA+ descriptions must come from the locale tables, not the API.

    The server returns English prose for the integrity model; the UI has its own
    localized copy so the 内部审计 workspace reads in the active language.
    """
    i18n = client.get("/assets/i18n.js").text
    for key in (
        "attributable",
        "legible",
        "contemporaneous",
        "original",
        "accurate",
        "complete_consistent_enduring_available",
    ):
        assert f"gov.integrityDesc.{key}" in i18n
    js = client.get("/assets/app.js").text
    # The server string is only a fallback for an unknown key.
    assert "gov.integrityDesc." in js


def test_connector_interface_descriptor_is_localized(client):
    i18n = client.get("/assets/i18n.js").text
    assert "interfaceKind" in i18n
    js = client.get("/assets/app.js").text
    assert 'term("interfaceKind"' in js


def test_review_queue_is_scoped_to_business_findings(client):
    js = client.get("/assets/app.js").text
    # The queue calls the default (business) scope, not scope=all.
    assert "/api/reviews" in js
    assert "scope=all" not in js
