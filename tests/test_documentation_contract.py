"""Documentation-contract tests: required documents exist and stay truthful.

The golden-set evaluator and the full suite keep the system honest; these tests
keep the documentation honest. Every document the README points at must exist,
and the run instructions must not drift from the implemented behavior:
``LLM_MODE=mock`` is the default and makes no network calls, the uvicorn command
works with either ``pip install -e .`` or ``PYTHONPATH=src``, and the walkthrough
still covers all six scenarios.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "relative_path",
    [
        "README.md",
        "docs/architecture.md",
        "docs/operations.md",
        "docs/security-and-risk.md",
        "docs/validation.md",
        "docs/integration-contracts.md",
        "docs/decisions/0001-workflow-first-controlled-agent.md",
    ],
)
def test_required_document_exists(relative_path):
    assert (_PROJECT_ROOT / relative_path).exists()


def test_readme_links_resolve():
    """A broken link in the entry point is how a reader loses trust immediately."""
    import re

    readme = (_PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    for target in re.findall(r"\]\((docs/[^)#]+)\)", readme):
        assert (_PROJECT_ROOT / target).exists(), f"README links to missing {target}"


def test_operations_guide_documents_safe_degradation():
    text = (_PROJECT_ROOT / "docs/operations.md").read_text(encoding="utf-8")
    assert "MANUAL_DEGRADED" in text
    assert "FAILED_SAFE" in text


def test_architecture_records_the_never_fail_open_invariant():
    text = (_PROJECT_ROOT / "docs/architecture.md").read_text(encoding="utf-8")
    assert "FAILED_SAFE" in text
    assert "ALLOWED" in text


def test_readme_contains_run_command():
    text = (_PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    assert "uvicorn" in text
    assert "apps.api.main:app" in text


def test_operations_guide_contains_mock_mode_default():
    text = (_PROJECT_ROOT / "docs/operations.md").read_text(encoding="utf-8")
    assert "LLM_MODE=mock" in text


def test_operations_guide_documents_install_variant():
    text = (_PROJECT_ROOT / "docs/operations.md").read_text(encoding="utf-8")
    assert "pip install -e ." in text or "PYTHONPATH=src" in text


def test_operations_guide_references_all_six_scenarios():
    text = (_PROJECT_ROOT / "docs/operations.md").read_text(encoding="utf-8")
    for scenario in ["normal", "ae", "pii", "off_label", "redline", "injection"]:
        assert scenario in text


def test_validation_doc_records_the_release_gates():
    text = (_PROJECT_ROOT / "docs/validation.md").read_text(encoding="utf-8")
    assert "release_gate" in text
    assert "Masking recall" in text


def test_scope_limits_are_stated_in_the_readme():
    """The demo/production boundary is a claim about honesty, so it is tested."""
    text = (_PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    assert "no claim" in text.casefold()
    assert "synthetic" in text.casefold()
