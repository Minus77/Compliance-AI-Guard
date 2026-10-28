"""Documentation-contract tests: required documents exist and stay truthful.

The golden-set evaluator and the full suite keep the system honest; these tests
keep the documentation honest. Every document the README points at must exist,
and the run instructions must not drift from the implemented behavior:
``LLM_MODE=mock`` is the default and makes no network calls, the uvicorn command
works with either ``pip install -e .`` or ``PYTHONPATH=src``, and the walkthrough
still covers all six scenarios.

The docs ship in English and Simplified Chinese. Two documents maintained by hand
drift apart silently, so the pairing is tested: every English document has a
Chinese counterpart, both carry a link to the other, and the facts that a reader
would act on -- rule ids, gate thresholds, decision names -- appear in both.
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
        "README.zh.md",
        "docs/zh/architecture.md",
        "docs/zh/operations.md",
        "docs/zh/security-and-risk.md",
        "docs/zh/validation.md",
        "docs/zh/integration-contracts.md",
        "docs/zh/decisions/0001-workflow-first-controlled-agent.md",
    ],
)
def test_required_document_exists(relative_path):
    assert (_PROJECT_ROOT / relative_path).exists()


def _markdown_files() -> list[Path]:
    return [
        path
        for path in _PROJECT_ROOT.glob("**/*.md")
        if ".venv" not in path.parts and "node_modules" not in path.parts
    ]


def test_every_markdown_link_resolves():
    """A broken link is how a reader loses trust immediately.

    Checked across both language trees rather than only the README, because the
    relative depth differs between ``docs/`` and ``docs/zh/`` and that is exactly
    where a hand-written cross-link goes wrong.
    """
    import re

    broken = []
    for path in _markdown_files():
        text = path.read_text(encoding="utf-8")
        for target in re.findall(r"\]\(([^)\s]+\.md)\)", text):
            if not (path.parent / target).resolve().exists():
                broken.append(f"{path.relative_to(_PROJECT_ROOT)} -> {target}")
    assert not broken, f"broken markdown links: {broken}"


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


# -- bilingual contract ------------------------------------------------------

_LANGUAGE_PAIRS = [
    ("README.md", "README.zh.md"),
    ("docs/architecture.md", "docs/zh/architecture.md"),
    ("docs/operations.md", "docs/zh/operations.md"),
    ("docs/security-and-risk.md", "docs/zh/security-and-risk.md"),
    ("docs/validation.md", "docs/zh/validation.md"),
    ("docs/integration-contracts.md", "docs/zh/integration-contracts.md"),
    (
        "docs/decisions/0001-workflow-first-controlled-agent.md",
        "docs/zh/decisions/0001-workflow-first-controlled-agent.md",
    ),
]


@pytest.mark.parametrize("english,chinese", _LANGUAGE_PAIRS)
def test_both_language_versions_link_to_each_other(english, chinese):
    """A translation nobody can find from the other side is a dead end."""
    english_text = (_PROJECT_ROOT / english).read_text(encoding="utf-8")
    chinese_text = (_PROJECT_ROOT / chinese).read_text(encoding="utf-8")

    assert "简体中文" in english_text, f"{english} has no link to the Chinese version"
    assert "English" in chinese_text, f"{chinese} has no link to the English version"


@pytest.mark.parametrize("english,chinese", _LANGUAGE_PAIRS)
def test_chinese_version_is_actually_chinese(english, chinese):
    """Guards against a copy of the English file landing at the Chinese path.

    A CJK ratio is a crude measure, but it catches the failure that matters: a
    placeholder or an accidental duplicate would read as English prose.
    """
    text = (_PROJECT_ROOT / chinese).read_text(encoding="utf-8")
    cjk = sum(1 for ch in text if "\u4e00" <= ch <= "\u9fff")
    assert cjk > 200, f"{chinese} does not look like a Chinese translation"


def test_policy_rule_ids_match_across_languages():
    """Rule ids are what a reviewer cites, so they must not drift.

    The policy table is the densest factual content in the docs; if a rule is
    added on one side only, the two documents describe different systems.
    """
    import re

    english = (_PROJECT_ROOT / "docs/architecture.md").read_text(encoding="utf-8")
    chinese = (_PROJECT_ROOT / "docs/zh/architecture.md").read_text(encoding="utf-8")

    english_rules = set(re.findall(r"CN-\d{3}", english))
    chinese_rules = set(re.findall(r"CN-\d{3}", chinese))

    assert english_rules == chinese_rules, (
        f"policy rules differ: only in English {english_rules - chinese_rules}, "
        f"only in Chinese {chinese_rules - english_rules}"
    )


def test_policy_rule_ids_match_the_shipped_bundle():
    """And both documents must match the bundle that actually decides cases."""
    import json
    import re

    bundle = json.loads(
        (_PROJECT_ROOT / "config/policies/general-medical-demo.json").read_text(
            encoding="utf-8"
        )
    )
    documented = set(
        re.findall(
            r"CN-\d{3}",
            (_PROJECT_ROOT / "docs/architecture.md").read_text(encoding="utf-8"),
        )
    )

    assert documented == set(bundle["rules"]), (
        "architecture.md policy table has drifted from config/policies/general-medical-demo.json"
    )


@pytest.mark.parametrize("english,chinese", _LANGUAGE_PAIRS)
def test_server_codes_survive_translation(english, chinese):
    """Server codes stay verbatim in both languages.

    The UI renders a readable phrase *plus* the raw code for the same reason: a
    translated-only code makes a trace unverifiable. The docs follow that rule.

    Only *backticked* codes are compared. The bare English words "blocked" and
    "allow" also occur as ordinary prose ("injection blocked at S0"), which a
    Chinese document correctly renders as 拦截 -- comparing those would demand a
    literal word-for-word translation rather than a faithful one.
    """
    import re

    def codes(path: str) -> set[str]:
        text = (_PROJECT_ROOT / path).read_text(encoding="utf-8")
        return set(
            re.findall(
                r"`(allow|needs_info|human_review|blocked|refused|"
                r"FAILED_SAFE|FAILED_RETRYABLE|MANUAL_DEGRADED|ALLOWED)`",
                text,
            )
        )

    missing = codes(english) - codes(chinese)
    assert not missing, f"{chinese} dropped server codes {sorted(missing)}"


@pytest.mark.parametrize("english,chinese", _LANGUAGE_PAIRS)
def test_severity_levels_survive_translation(english, chinese):
    english_text = (_PROJECT_ROOT / english).read_text(encoding="utf-8")
    chinese_text = (_PROJECT_ROOT / chinese).read_text(encoding="utf-8")

    for code in ("S0", "S1", "S2", "S3"):
        if code in english_text:
            assert code in chinese_text, f"{chinese} dropped severity code {code}"


def test_release_gate_count_agrees_across_languages():
    """Fifteen gates in one language and fourteen in the other is a real defect."""
    import re

    english = (_PROJECT_ROOT / "docs/validation.md").read_text(encoding="utf-8")
    chinese = (_PROJECT_ROOT / "docs/zh/validation.md").read_text(encoding="utf-8")

    # The gate table numbers rows 1..15 in a leading "| n |" cell.
    def gate_rows(text: str) -> set[str]:
        return set(re.findall(r"^\| (\d{1,2}) \|", text, re.MULTILINE))

    assert gate_rows(english) == gate_rows(chinese) != set()


def test_scope_limits_are_stated_in_both_readmes():
    """The honesty disclaimer must not exist only in the language nobody reads."""
    english = (_PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    chinese = (_PROJECT_ROOT / "README.zh.md").read_text(encoding="utf-8")

    assert "no claim" in english.casefold()
    assert "synthetic" in english.casefold()
    assert "不作任何声称" in chinese
    assert "合成" in chinese
