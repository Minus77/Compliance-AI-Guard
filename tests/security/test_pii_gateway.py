"""PII/PHI gateway tests: masking, stable tokens, spans, audit, and DLP rejection."""

import pytest

from compliance_guard.domain.enums import SecurityAction, Severity
from compliance_guard.security.dlp import DlpScanner
from compliance_guard.security.pii_gateway import KnownIdentifier, SanitizeContext, sanitize


def demo_context(audit_callback=None, tenant_id="TENANT-CN"):
    return SanitizeContext(
        tenant_id=tenant_id,
        audit_callback=audit_callback,
        known_identifiers=[
            KnownIdentifier(
                entity_type="patient",
                canonical_id="PATIENT-0001",
                values=["张三", "13812345678", "zhangsan@example.com", "PATIENT-0001"],
            ),
            KnownIdentifier(
                entity_type="hcp",
                canonical_id="HCP-0007",
                values=["李医生", "HCP-0007"],
            ),
            KnownIdentifier(
                entity_type="patient",
                canonical_id="PATIENT-0002",
                values=["章三"],
            ),
        ],
    )


def test_sanitize_removes_patient_phone_and_keeps_safe_span():
    result = sanitize("患者张三电话 13812345678，出现皮疹", demo_context())
    assert "13812345678" not in result.model_text
    assert "[PATIENT_" in result.model_text
    assert any(f.type == "pii" for f in result.findings)


def test_sanitize_preserves_safe_context():
    result = sanitize("患者张三电话 13812345678，出现皮疹", demo_context())
    assert "出现皮疹" in result.model_text


def test_sanitize_masks_known_name_without_title():
    result = sanitize("章三在门诊复诊", demo_context())
    assert "章三" not in result.model_text
    assert "[PATIENT_" in result.model_text


def test_sanitize_masks_name_with_title_context():
    result = sanitize("章医生正在查看影像", demo_context())
    assert "章医生" not in result.model_text
    assert "[HCP_" in result.model_text
    assert "查看影像" in result.model_text


def test_sanitize_masks_unregistered_name_after_title():
    result = sanitize("患者王五前来复诊", demo_context())
    assert "王五" not in result.model_text
    assert "[PATIENT_" in result.model_text
    assert "复诊" in result.model_text


def test_sanitize_masks_email():
    result = sanitize("联系 zhangsan@example.com 获取报告", demo_context())
    assert "zhangsan@example.com" not in result.model_text
    assert "[PATIENT_" in result.model_text


def test_sanitize_masks_patient_identifier():
    result = sanitize("患者编号 PATIENT-0001 出现皮疹", demo_context())
    assert "PATIENT-0001" not in result.model_text
    assert "[PATIENT_" in result.model_text


def test_sanitize_does_not_mangle_administrative_words():
    result = sanitize("患者编号登记完成", demo_context())
    assert "编号" in result.model_text


def test_span_map_offsets_refer_to_sanitized_text():
    result = sanitize("患者张三电话 13812345678，出现皮疹", demo_context())
    for token, spans in result.spans.items():
        assert spans
        for span in spans:
            assert span.startswith("char:")
            start_text, end_text = span[5:].split("-", 1)
            start, end = int(start_text), int(end_text)
            assert result.model_text[start:end] == token


def test_tokens_are_stable_across_calls_in_tenant():
    first = sanitize("患者张三电话 13812345678，出现皮疹", demo_context())
    second = sanitize("患者张三电话 13812345678，出现皮疹", demo_context())
    assert first.model_text == second.model_text
    assert first.spans == second.spans


def test_tokens_differ_across_tenants():
    cn = sanitize("患者张三电话 13812345678", demo_context(tenant_id="TENANT-CN"))
    eu = sanitize("患者张三电话 13812345678", demo_context(tenant_id="TENANT-EU"))
    assert cn.model_text != eu.model_text


def test_sanitize_records_audit_event():
    events = []
    sanitize("患者张三电话 13812345678", demo_context(audit_callback=lambda e, p: events.append((e, p))))
    assert any(event == "sanitize" for event, _ in events)


def test_findings_are_redaction_not_block():
    result = sanitize("患者张三电话 13812345678，出现皮疹", demo_context())
    for finding in result.findings:
        assert finding.type == "pii"
        assert finding.action == SecurityAction.REDACT
        assert finding.severity == Severity.S2


def test_entities_carry_token_and_span():
    result = sanitize("患者张三电话 13812345678", demo_context())
    assert result.entities
    for entity in result.entities:
        assert entity.token in result.model_text
        assert entity.span in result.spans[entity.token]


def test_dlp_rejects_raw_phone_in_model_output():
    scanner = DlpScanner()
    findings = scanner.scan("患者报告电话 13900001111，情况稳定")
    assert findings
    assert findings[0].action == SecurityAction.BLOCK
    assert findings[0].blocked
    assert scanner.is_clean("患者报告电话 13900001111") is False


def test_dlp_rejects_raw_email_in_config_payload():
    scanner = DlpScanner()
    findings = scanner.scan({"notify": "nurse@example.com", "channel": "email"})
    assert any(f.type == "dlp" for f in findings)


def test_dlp_rejects_raw_name_with_title():
    scanner = DlpScanner()
    findings = scanner.scan("值班医生李医生已确认")
    assert findings


def test_dlp_accepts_clean_payload():
    scanner = DlpScanner()
    assert scanner.is_clean("皮疹持续两天，建议复查") is True
    assert scanner.scan({"channel": "email", "region": "CN"}) == []


def test_repeated_entity_spans_cover_every_occurrence():
    text = "患者张三电话 13812345678，邮件 zhangsan@example.com，张三复诊"
    result = sanitize(text, demo_context())
    tokens = {entity.token for entity in result.entities}
    assert len(tokens) == 1
    token = next(iter(tokens))
    spans = result.spans[token]
    assert len(spans) == 4
    seen = set()
    for span in spans:
        start_text, end_text = span[5:].split("-", 1)
        start, end = int(start_text), int(end_text)
        assert result.model_text[start:end] == token
        seen.add((start, end))
    assert len(seen) == 4
    assert [entity.span for entity in result.entities] == spans


def test_dlp_clean_for_clinical_request_to_doctor():
    scanner = DlpScanner()
    assert scanner.is_clean("患者请医生查看影像") is True


def test_sanitize_does_not_mask_function_word_before_title():
    result = sanitize("患者请医生查看影像", demo_context())
    assert "医生" in result.model_text
    assert result.findings == []


def test_sanitize_masks_real_title_context_name():
    result = sanitize("章医生正在查看影像", demo_context())
    assert "章医生" not in result.model_text
    assert "[HCP_" in result.model_text


def test_sanitize_masks_cjk_adjacent_patient_identifier():
    result = sanitize("患者PATIENT-12345出现皮疹", demo_context())
    assert "PATIENT-12345" not in result.model_text
    assert "[PATIENT_" in result.model_text


def test_sanitize_masks_cjk_adjacent_hcp_identifier():
    result = sanitize("患者HCP-12345复诊", demo_context())
    assert "HCP-12345" not in result.model_text
    assert "[HCP_" in result.model_text
