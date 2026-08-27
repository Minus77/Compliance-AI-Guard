"""Embedded UI contract: served pages, assets, and workspace entry points."""

import re


def test_ui_serves_three_workspaces(client):
    response = client.get("/")
    assert response.status_code == 200
    html = response.text
    for marker in ("workspace-representative", "workspace-reviewer", "workspace-policy"):
        assert marker in html


def test_ui_assets_served(client):
    assert client.get("/assets/styles.css").status_code == 200
    assert client.get("/assets/app.js").status_code == 200
    assert client.get("/assets/i18n.js").status_code == 200


def test_ui_contract_exposes_workspace_entry_points(client):
    html = client.get("/").text
    # Anchor on the stable markup contract, not on rendered label text: the nav
    # labels are localized (zh-CN by default) and carry data-i18n keys, so
    # asserting English strings would only be testing the default locale.
    for workspace in ("representative", "reviewer", "policy"):
        assert f'data-workspace="{workspace}"' in html
    for key in ("nav.representative", "nav.reviewer", "nav.policy"):
        assert f'data-i18n="{key}"' in html
    assert "x-demo-role" in html


def test_ui_contract_references_api_endpoints(client):
    js = client.get("/assets/app.js").text
    for endpoint in (
        "/api/cases/check",
        "/api/reviews",
        "/api/config/models",
        "/api/config/publish",
        "/api/config/rollback",
        "/api/metrics",
    ):
        assert endpoint in js


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
    assert 'data-workspace="governance"' in html
    for marker in ('id="gov-integrity"', 'id="connector-table"', 'id="audit-table"'):
        assert marker in html
    js = client.get("/assets/app.js").text
    assert "/api/audit-trail" in js
    assert "/api/connectors" in js


def test_governance_workspace_is_gated_on_audit_export(client):
    js = client.get("/assets/app.js").text
    assert "governance: \"audit_export\"" in js


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
    assert offered == ["field_rep", "reviewer", "auditor", "architect"]


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
