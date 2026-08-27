"""Turn a missing ICSR criterion into a question the author can answer.

The assessment already knew what was missing and said so — then offered nowhere to
supply it (defect P-9). Naming a gap without a field to fill it is worse than
saying nothing: it reads as the tool refusing on purpose, and the representative's
only remaining move is to give up on the report.

Two design choices worth stating:

**Only ask for what is missing.** A form that re-asks for facts the narrative
already established teaches people to skim past it, and the one field that
actually mattered gets skimmed too.

**Establish identifiability without collecting an identity.** ICH E2D asks whether
a patient is *identifiable to the reporter*, not that the company hold their name.
So the patient question asks for a non-identifying description — sex, age band —
and never for a name, a phone number, or a record number. Answering it moves the
case toward a valid report without creating a new place for personal data to sit.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field

from compliance_guard.domain.models import DomainModel

# One question per ICSR criterion. `why` is shown next to the field: a rep asked
# for information they do not understand supplies it badly or not at all.
_QUESTIONS: dict[str, dict[str, Any]] = {
    "identifiable_patient": {
        "label": "这次涉及的患者，可以怎么描述？",
        "placeholder": "例如：成年男性，60-65岁",
        "why": "有效的安全报告需要能对应到一位具体患者。请不要填写真实姓名或联系方式，写性别和年龄段就够了。",
        "input": "text",
        "collects_identifier": False,
    },
    "identifiable_reporter": {
        "label": "这条信息是谁提供的？",
        "placeholder": "例如：患者本人 / 家属 / 门诊医生",
        "why": "需要知道信息来源，才能在后续随访时找到能补充情况的人。填写身份即可，不需要联系方式。",
        "input": "text",
        "collects_identifier": False,
    },
    "suspect_product": {
        "label": "涉及的是哪个产品？",
        "placeholder": "请选择产品",
        "why": "需要明确是哪个产品，才能把这条安全信息归到正确的产品档案。",
        "input": "product",
        "collects_identifier": False,
    },
    "suspect_reaction": {
        "label": "患者出现了什么不适？",
        "placeholder": "例如：服药两天后出现皮疹",
        "why": "需要具体描述反应本身，这是构成一份安全报告的核心内容。",
        "input": "textarea",
        "collects_identifier": False,
    },
}

# Asked whenever follow-up is needed at all: both feed the reporting clock and
# the outcome assessment, and neither identifies anyone.
_ALWAYS_ASKED: dict[str, dict[str, Any]] = {
    "onset_date": {
        "label": "大约什么时候开始的？",
        "placeholder": "例如：2026-08-18，或「上周三左右」",
        "why": "上报时限从公司知悉当天开始计算，发生时间会影响后续评估。不确定的话写大概时间也可以。",
        "input": "text",
        "collects_identifier": False,
    },
    "current_outcome": {
        "label": "目前情况怎么样了？",
        "placeholder": "例如：已好转 / 仍在持续 / 已停药观察",
        "why": "转归情况决定这条信息的严重程度分级，也是药物警戒同事最先问的问题。",
        "input": "text",
        "collects_identifier": False,
    },
}


class FollowupField(DomainModel):
    """One question, with the reason it is being asked."""

    # Deliberately not called "name": the payload must never read as though it
    # were asking for a person's name.
    field: str
    label: str
    placeholder: str = ""
    why: str = ""
    input: str = "text"
    criterion: str | None = None
    collects_identifier: bool = False


class FollowupForm(DomainModel):
    """The set of questions still outstanding for one case."""

    required: bool = False
    reason: str = ""
    missing_criteria: list[str] = Field(default_factory=list)
    fields: list[FollowupField] = Field(default_factory=list)

    @property
    def field_names(self) -> list[str]:
        return [item.field for item in self.fields]


def build_followup_form(icsr: dict[str, Any] | None) -> FollowupForm:
    """Derive the outstanding questions from an ICSR assessment.

    Returns an empty form when the narrative is not safety relevant or the report
    is already valid: an unnecessary form is a reason to distrust the next one.
    """
    assessment = icsr or {}
    if not assessment.get("is_safety_relevant"):
        return FollowupForm(required=False, reason="")

    missing = [str(item) for item in (assessment.get("missing_criteria") or [])]
    if not missing:
        return FollowupForm(
            required=False,
            reason="这条安全信息的四要素已齐全，无需补充。",
        )

    fields: list[FollowupField] = []
    for criterion in missing:
        question = _QUESTIONS.get(criterion)
        if question is None:
            continue
        fields.append(FollowupField(field=criterion, criterion=criterion, **question))
    for name, question in _ALWAYS_ASKED.items():
        fields.append(FollowupField(field=name, **question))

    return FollowupForm(
        required=True,
        reason=(
            "一份可上报的安全报告需要「患者、报告人、可疑药品、不良反应」四项齐全。"
            "下面几项还差，补齐后就能提交，内容不会丢。"
        ),
        missing_criteria=missing,
        fields=fields,
    )


def followup_narrative(answers: dict[str, Any]) -> str:
    """Fold answers into a sentence the deterministic assessment can re-read.

    The assessment works on text, so answers become text rather than a parallel
    structured path. One code path means the criteria cannot be satisfied one way
    on submission and another way on follow-up.
    """
    parts: list[str] = []
    patient = str(answers.get("identifiable_patient") or "").strip()
    if patient:
        parts.append(f"患者情况：{patient}")
    reporter = str(answers.get("identifiable_reporter") or "").strip()
    if reporter:
        parts.append(f"报告人：{reporter}")
    reaction = str(answers.get("suspect_reaction") or "").strip()
    if reaction:
        parts.append(f"不良反应：{reaction}")
    onset = str(answers.get("onset_date") or "").strip()
    if onset:
        parts.append(f"发生时间：{onset}")
    outcome = str(answers.get("current_outcome") or "").strip()
    if outcome:
        parts.append(f"目前转归：{outcome}")
    return "。".join(parts)


__all__ = ["FollowupField", "FollowupForm", "build_followup_form", "followup_narrative"]
