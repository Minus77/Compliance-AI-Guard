/* Compliance AI Guard - interface locale + code-to-natural-language vocabulary.
 *
 * Two distinct jobs:
 *   1. UI chrome strings (labels, buttons, headings, hints, toasts).
 *   2. Vocabulary maps that turn server codes into readable sentences:
 *      decisions, case states, severities, finding types, audit events,
 *      retrieval stages, roles. The raw code is always kept visible next to
 *      the phrasing so an audit trail stays verifiable.
 *
 * Deliberately NOT translated:
 *   - Scenario sample text and the submitted narrative. Server-side risk
 *     detection matches Chinese keywords (agents/pv_signal.py,
 *     security/injection_scan.py) and data/fixtures/evidence.json is zh-CN /
 *     zh-HK only. Translating the payload would silently disable AE, redline
 *     and injection detection and return an empty evidence set.
 *   - Version identifiers (policy / route / prompt / snapshot / profile ids).
 *     These are audit values and must read identically in every locale.
 */
(function (global) {
  "use strict";

  var STORAGE_KEY = "cg.ui.locale";
  var DEFAULT_LOCALE = "zh-CN";
  var FALLBACK_LOCALE = "en";
  var LOCALES = ["zh-CN", "en"];

  var STRINGS = {
    "zh-CN": {
      "app.title": "Compliance AI Guard",
      "app.subtitle": "医药合规预检 · 发布前决策网关",
      "header.uiLanguage": "界面语言",
      "header.role": "演示角色",
      "header.demoOnly": "仅演示模式",

      "auth.title": "请先登录",
      "auth.lead": "合规记录需要可追溯到具体的人，因此不支持匿名提交。",
      "auth.username": "用户名",
      "auth.password": "密码",
      "auth.signIn": "登录",
      "auth.signOut": "退出登录",
      "auth.failed": "登录失败，请检查用户名和密码。",
      "auth.scopeNote": "本地最小可用会话，非企业级单点登录：无身份提供方、无二次验证。",
      "auth.changeTitle": "请先修改初始密码",
      "auth.changeLead": "初始密码由系统生成且必须修改后才能继续使用。",
      "auth.currentPassword": "当前密码",
      "auth.newPassword": "新密码（至少 12 个字符）",
      "auth.changeSubmit": "修改密码",
      "auth.changeFailed": "密码修改失败。",
      "auth.changed": "密码已修改，请用新密码重新登录。",
      "header.modeMock": "离线演示模式",
      "header.modeLive": "已接入真实大模型",
      "header.modeMockTitle": "当前不联网。合规判断使用本机预置的样例回答，适合演示与培训。",
      "header.modeLiveTitle": "当前会把打码后的文本发送给已配置的大模型服务，用于语义复检。姓名、电话等个人信息在发送前已替换为代号。",
      "header.modeLiveDegraded": "大模型未就绪",
      "header.modeLiveDegradedTitle": "已开启真实大模型模式，但服务未就绪（缺少密钥或网络不通）。此时系统不会放行任何高风险内容，而是转人工复核。",
      "nav.representative": "代表工作台",
      "nav.reviewer": "审核工作台",
      "nav.policy": "模型策略",
      "role.field_rep": "医药代表",
      "role.reviewer": "审核人",
      "role.pv_reviewer": "药物警戒审核人",
      "role.medical_reviewer": "医学审核人",
      "role.compliance_admin": "合规管理员",
      "role.architect": "架构师",
      "role.msl": "医学科学联络官（MSL）",
      "role.qppv": "药物警戒负责人（QPPV）",
      "role.mlr_reviewer": "MLR 审批人",
      "role.qa": "质量保证（QA）",
      "role.regulatory_affairs": "法规事务（RA）",
      "role.auditor": "内部审计",

      "gate.title": "当前角色无权访问该模块",
      "gate.body": "「{role}」没有该模块所需的权限。权限由服务端矩阵判定（GET /api/permissions），界面只是按其结果隐藏入口；每个受保护接口仍会独立校验。",
      "gate.needed": "所需权限",
      "gate.switchHint": "如需演示完整发布/回滚流程，请切换为「合规管理员」。",

      "rep.title": "拜访记录合规预检",
      "rep.lead": "在内容对外发出之前，由服务端判定可否放行。模型只产出候选，决策权不在模型。",
      "rep.sourceSection": "内容来源",
      "rep.connector": "来源系统",
      "rep.connectorHint": "来源已插件化：可对接 Veeva CRM / Vault，按 record_id 回读权威记录并拒绝过期版本。",
      "rep.record": "上游记录",
      "rep.recordPlaceholder": "选择一条记录…",
      "rep.loadRecord": "读取记录",
      "rep.recordLoaded": "已回读 {recordId}（版本 {version}）",
      "rep.recordVersion": "当前版本",
      "rep.rereadBadge": "回读自权威记录",
      "rep.contextSection": "业务上下文",
      "rep.product": "产品",
      "rep.market": "市场",
      "rep.channel": "渠道",
      "rep.contentLanguage": "内容语言",
      "rep.contentLanguageHint": "业务字段，决定证据检索范围，与界面语言相互独立。",
      "channel.call_report": "拜访记录",
      "channel.med_comms": "医学沟通",
      "rep.attachSection": "附件（图片 / 音频）",
      "rep.attachHint": "仅登记引用与元数据，不上传原始文件：附件可能含患者信息，本演示不在服务端留存原文。登记后将走多模态抽取路由。",
      "rep.addImage": "添加图片引用",
      "rep.addAudio": "添加音频引用",
      "rep.attachEmpty": "尚未添加附件。",
      "rep.attachRemove": "移除",
      "rep.attachRegistered": "已登记 {kind}：{filename}",
      "rep.scenarios": "演示场景",
      "rep.scenarioNote": "场景示例文本固定为中文：服务端风险关键词与证据库均为中文语料，翻译正文会让风险识别静默失效。",
      "scenario.normal": "常规",
      "scenario.ae": "不良事件",
      "scenario.pii": "个人信息",
      "scenario.off_label": "超说明书",
      "scenario.redline": "红线",
      "scenario.injection": "提示注入",
      "rep.contentLabel": "拜访记录正文",
      "rep.contentPlaceholder": "在此粘贴业务叙述。原文仅保留在你的视图中，服务端不留存。",
      "rep.submit": "运行合规预检",
      "rep.checking": "预检中…",
      "rep.checkingSlow": "正在等待模型返回语义复检结果，可能需要几秒…",
      "degraded.title": "AI 检查未完成，内容已保留",
      "degraded.body": "模型服务暂时不可用。系统不会因此放行内容，你写的原文已完整保存。",
      "degraded.next": "已转人工复核，有结论会通知你；无需重新提交。",
      "rep.emptyContent": "请先输入案例内容。",

      "result.heading": "预检结果",
      "result.decisionLabel": "服务端判定",
      "result.statusLabel": "流程状态",
      "result.severityLabel": "最高风险等级",
      "result.safeView": "安全视图（已脱敏）",
      "result.safeHint": "个人信息已替换为令牌，方括号内为令牌占位。",
      "result.findings": "风险发现",
      "result.evidence": "引用证据",
      "result.next": "后续动作",
      "result.rag": "证据检索过程（RAG）",
      "result.openTrace": "查看完整审计链路",
      "result.trace": "审计链路",
      "result.noFindings": "未发现风险。",
      "result.noEvidence": "未检索到可用证据（已显式记录为证据缺口）。",
      "result.noNext": "无需后续处理。",
      "result.matchedTerms": "命中词",
      "result.rule": "规则",
      "result.owner": "责任角色",
      "result.sla": "处理时限",
      "result.evidenceGap": "证据缺口",
      "result.missing": "缺少信息",
      "missing.labelFieldQualifier": "说明书字段·",

      "sev.legend": "风险等级说明",
      "sev.S0.name": "S0 · 红线",
      "sev.S0.desc": "最严重。严重不良事件、数据泄露、提示注入等，一律阻断并立即上报，不可自助放行。",
      "sev.S1.name": "S1 · 高风险",
      "sev.S1.desc": "需专业人工审核（药物警戒 / 医学 / 合规 / 安全），代表不能自行放行。",
      "sev.S2.name": "S2 · 需补充",
      "sev.S2.desc": "信息或证据不足，补齐后可再次预检。",
      "sev.S3.name": "S3 · 低风险",
      "sev.S3.desc": "仅格式或表述类提示，可直接放行。",

      "rag.query": "检索问句",
      "rag.tokens": "检索键",
      "rag.tokensHint": "中文按 2-gram 切分，使用脱敏后的文本，原文不参与检索。",
      "rag.stages": "检索流水线",
      "rag.candidates": "候选",
      "rag.chunks": "命中与排除明细",
      "rag.selected": "已采用",
      "rag.excluded": "已排除",
      "rag.score": "匹配分",
      "rag.snapshot": "知识快照",
      "rag.gaps": "证据缺口",
      "rag.supporting": "支持性证据",
      "rag.contradiction": "冲突证据",
      "rag.stage.query_build": "构建检索键",
      "rag.stage.metadata_filter": "元数据过滤",
      "rag.stage.lexical_score": "词面打分",
      "rag.stage.stance_split": "立场分流",
      "rag.stage.query_build.desc": "先脱敏，再把叙述切成检索键；中文用 2-gram。",
      "rag.stage.metadata_filter.desc": "打分之前先按租户、市场、产品、语言、状态、生效期与访问范围过滤，越权语料不参与检索。",
      "rag.stage.lexical_score.desc": "按检索键与语料块的重叠数量打分，零重叠直接丢弃。",
      "rag.stage.stance_split.desc": "分成支持性证据与冲突证据；非发布级来源不得作为放行依据。",
      "rag.excl.metadata_filter": "被元数据过滤（租户/市场/产品/语言/生效期不匹配）",
      "rag.excl.no_lexical_match": "与检索键无重叠",
      "rag.excl.non_release_source": "非发布级来源，不能作为放行依据",

      "rev.title": "专业审核",
      "rev.queue": "待审队列",
      "rev.empty": "暂无待审任务。",
      "rev.selectHint": "从左侧选择任务，查看证据、风险发现、模型路由与审计历史。",
      "rev.loadingCase": "正在加载案例 {caseId}…",
      "rev.case": "案例",
      "rev.safeCitation": "安全引用",
      "rev.riskFindings": "风险发现",
      "rev.evidenceBlock": "证据（说明书 / 声称 / SOP）",
      "rev.modelRoute": "模型路由",
      "rev.timeline": "状态时间线",
      "rev.decision": "审核判定",
      "rev.taskId": "任务编号",
      "rev.decisionField": "判定",
      "rev.accept": "接受（放行）",
      "rev.acceptBlocked": "接受（放行）—— {severity} 不允许自助放行",
      "rev.reject": "驳回（阻断）",
      "rev.escalate": "升级（转人工复核）",
      "rev.needsInfo": "退回补充信息",
      "rev.reason": "判定理由（必填）",
      "rev.reasonPlaceholder": "写明依据，例如引用了哪条证据、缺少什么信息。理由会进入审计记录。",

      "feedback.title": "这条判断有问题？",
      "feedback.hint": "标记后会生成一条候选回归用例，需另一位同事确认才会进入黄金集。这是让规则长期变准的唯一机制。",
      "feedback.kind": "问题类型",
      "feedback.falsePositive": "误报：内容其实没问题",
      "feedback.falseNegative": "漏报：应该拦但没拦住",
      "feedback.reason": "说明理由",
      "feedback.reasonPlaceholder": "例如：这是常规拜访描述，不涉及超适应症表述。",
      "feedback.submit": "标记并生成候选用例",
      "feedback.sent": "已记录，等待另一位同事确认。",
      "feedback.needReason": "请先说明理由：没有理由的候选用例无法复核。",
      "feedback.confirmNote": "候选用例只保留脱敏后的正文，不含个人信息。",
      "rev.submitDecision": "提交判定",
      "rev.reasonRequired": "审核判定必须填写理由。",
      "rev.decisionRecorded": "判定已记录：{decision}",
      "rev.sla": "处理时限",
      "rev.slaDeadline": "截止时间",
      "rev.requiredRole": "所需角色",
      "rev.systemDecision": "系统判定",
      "rev.spans": "执行跨度（{count} 个）",
      "rev.auditEvents": "审计事件（{count} 条）",
      "rev.timelineHint": "自上而下为实际执行顺序，每一步都写入审计账本。",

      "policy.title": "模型策略",
      "policy.lead": "模型档案与任务路由均为版本化配置，发布与回滚需要管理员权限。",
      "policy.refresh": "刷新",
      "policy.saveDraft": "保存草稿",
      "policy.testTask": "测试任务",
      "policy.mockTest": "连通性测试",
      "policy.publish": "发布",
      "policy.rollback": "回滚",
      "policy.working": "处理中…",
      "policy.profiles": "模型档案",
      "policy.routes": "任务路由",
      "policy.diff": "发布差异",
      "policy.history": "版本历史",
      "policy.noDraft": "暂无待发布草稿。",
      "policy.publishedVersion": "当前已发布版本 {version}",
      "policy.draftStaged": "草稿已暂存，请先核对差异再发布。",
      "policy.publishedToast": "已发布版本 {version}",
      "policy.rolledBackToast": "已回滚至版本 {version}",
      "policy.testResult": "测试{outcome} · 提供方 {provider} · 模型 {model} · 路由 {route} · 耗时 {latency}ms",
      "policy.testOk": "通过",
      "policy.testFailed": "失败",
      "policy.testError": "测试失败：{message}",
      "policy.masked": "已脱敏",
      "policy.on": "启用",
      "policy.off": "停用",
      "policy.stagedDraftHeader": "暂存草稿（尚未发布）",
      "policy.metrics": "运行指标",
      "policy.metricCases": "已接收案例",
      "policy.metricCompleted": "已完成",
      "policy.metricModelCalls": "模型调用",

      "th.profile": "档案",
      "th.provider": "提供方",
      "th.model": "模型",
      "th.capabilities": "能力",
      "th.dataClasses": "数据分级",
      "th.region": "区域",
      "th.credential": "凭据",
      "th.timeout": "超时（毫秒）",
      "th.budget": "令牌预算",
      "th.enabled": "状态",
      "th.task": "任务",
      "th.primary": "主用档案",
      "th.fallback": "备用档案",
      "th.requiredCaps": "必需能力",
      "th.regions": "允许区域",
      "th.routeVersion": "路由版本",
      "th.humanOnFailure": "失败转人工",

      "nav.governance": "质量与审计",
      "nav.records": "我的记录",
      "nav.shortcutHint": "按 1–5 可快速切换工作台（正在输入时不会触发）",

      "notif.label": "通知",
      "notif.title": "查看审核结论与通知",
      "notif.panelTitle": "审核结论与通知",
      "notif.empty": "暂无新的通知。",
      "notif.markRead": "标记已读",

      "rep.narrativeSection": "拜访记录正文",
      "rep.contentHelp": "边写边提示；正文完整保留，不会因为提示而被删改。",
      "rep.submitShortcut": "Cmd/Ctrl + Enter 提交",
      "rep.retry": "重试",
      "rep.examplesTitle": "示例与教学",
      "rep.precheckTitle": "提交前预检",
      "rep.precheckClean": "暂未发现需要处理的问题",
      "rep.precheckTiming": "本地判定，用时 {ms} 毫秒",
      "rep.draftFound": "发现一份未提交的草稿（{time}）。",
      "rep.draftRestore": "恢复草稿",
      "rep.draftDiscard": "丢弃",
      "rep.draftRestored": "草稿已恢复。",
      "rep.draftDiscarded": "草稿已丢弃。",
      "rep.serviceError": "服务暂时没有响应，你的草稿已保存在本机，可以稍后重试。",
      "rep.hintPrefix": "注意",
      "rep.hintPreliminary": "以下只是初步提示，最终结论以提交后的检查为准。",

      "result.technical": "技术详情（供审计核对）",
      "result.revise": "基于本稿修订后重新提交",
      "result.reviseTitle": "以这份记录为基础新建一版，原记录不会被覆盖。",

      "followup.title": "还差一点信息",
      "followup.submit": "提交补充信息",
      "followup.saving": "提交中…",
      "followup.done": "已补充，评估已更新。",
      "followup.empty": "请至少填写一项后再提交。",

      "rewrite.title": "怎么改",
      "rewrite.suggestionLabel": "建议改为（已再次检查，不含违规表述）",
      "rewrite.apply": "用这段替换正文",
      "rewrite.applied": "已替换为建议内容，请确认是否符合实际情况。",

      "appeal.title": "认为判断有误？",
      "appeal.hint": "提出申诉不会立即解除拦截，会由有权限的同事复核后决定。",
      "appeal.reasonLabel": "请说明理由",
      "appeal.reasonPlaceholder": "例如：这是客户主动提出的要求，我只是如实记录。",
      "appeal.submit": "提交申诉",
      "appeal.done": "申诉已提交，会有同事复核后通知你。",
      "appeal.needReason": "请先填写申诉理由。",

      "records.title": "我的记录",
      "records.lead": "提交过的内容都在这里，可以查看结论、跟进进度，或基于原稿修订后重新提交。",
      "records.filter": "按结论筛选",
      "records.filterAll": "全部",
      "records.refresh": "刷新",
      "records.time": "提交时间",
      "records.outcome": "结论",
      "records.product": "产品",
      "records.findings": "涉及问题",
      "records.action": "操作",
      "records.open": "查看",
      "records.empty": "还没有提交过记录。",
      "records.more": "加载更多",

      "gov.candidatesTitle": "待确认的回归用例",
      "gov.candidatesHint": "由审核人标记的误报/漏报。需要另一位同事确认后才会进入黄金集，一个人无法单独改变发布门禁。",
      "gov.candidatesSummary": "待确认 {pending} 条，已确认 {confirmed} 条。",
      "gov.candidatesEmpty": "暂无待确认的候选用例。",
      "gov.candidateConfirm": "确认并纳入黄金集",
      "gov.candidateConfirmed": "已确认，将纳入回归用例集。",

      "gov.chainTitle": "审计链完整性",
      "gov.chainHint": "每条记录都带上一条记录的指纹；任何改动或删除都会断链并被指出位置。",
      "gov.chainOk": "审计链完整，已校验 {count} 条记录。",
      "gov.chainBroken": "审计链已断裂：第 {seq} 条起不可信。{reason}",
      "gov.oversightTitle": "人工监督健康度",
      "gov.oversightHint": "推翻率过低反而是预警信号：说明审核可能流于形式。",

      "onboarding.title": "开始之前，三件事",
      "onboarding.whatTitle": "这个工具做什么",
      "onboarding.whatBody": "在拜访记录对外发出之前先检查一遍：涉及不良事件、个人信息、超说明书表述或合规红线时给出提示。原文完整保留，不会被删改。",
      "onboarding.roleTitle": "你的角色能做什么",
      "onboarding.roleBody": "界面只显示你有权限的模块；每个操作在服务端还会再校验一次。",
      "onboarding.tryTitle": "试一条",
      "onboarding.tryBody": "在正文里写一句「患者服药后出现皮疹」，边写就会看到提示。",
      "onboarding.start": "开始使用",

      "glossary.what": "这是什么意思？",

      "pv.title": "药物警戒评估（ICSR）",
      "pv.notRelevant": "本例未检出不良反应表述，不构成安全性报告。",
      "pv.criteriaTitle": "个例安全性报告四项最低要求",
      "pv.criteriaHint": "四项齐备才构成有效 ICSR。缺项属于随访补齐任务，不是丢弃安全信号的理由。",
      "pv.criterion.identifiable_patient": "可识别的患者",
      "pv.criterion.identifiable_reporter": "可识别的报告者",
      "pv.criterion.suspect_product": "可疑药品",
      "pv.criterion.suspect_reaction": "可疑不良反应",
      "pv.met": "已满足",
      "pv.unmet": "未满足",
      "pv.validIcsr": "有效 ICSR",
      "pv.invalidIcsr": "ICSR 不完整",
      "pv.seriousness": "严重性判定",
      "pv.clockTitle": "法定报告时限",
      "pv.dayZero": "第 0 天（企业首次获知）",
      "pv.due": "提交截止",
      "pv.expedited": "快速报告",
      "pv.aggregate": "汇总报告（PSUR/PBRER）",
      "pv.clockDays": "{days} 个自然日",
      "pv.followup": "需随访补齐",
      "pv.conflict": "策略判定与 ICSR 评估不一致，请人工复核",
      "pv.scopeNote": "本模块为演示用辅助判断，非经验证的安全数据库，不构成法规建议。",

      "sig.title": "电子签名",
      "sig.signer": "签名人",
      "sig.role": "职能",
      "sig.signedAt": "签署时间",
      "sig.meaning": "签名含义",
      "sig.digest": "内容摘要",
      "sig.kind": "签名强度",
      "sig.kind.demo_manifestation": "演示级签名表征（无独立身份源、无双因素）",
      "sig.meaning.approved_for_release": "批准发布",
      "sig.meaning.rejected_blocked_from_release": "驳回并禁止发布",
      "sig.meaning.escalated_for_further_review": "升级进一步审核",
      "sig.meaning.returned_for_additional_information": "退回补充信息",
      "sig.meaning.reviewed": "已审阅",
      "sig.hint": "签名与判定内容摘要绑定，任何字段变更都会导致摘要校验失败。",

      "gov.title": "质量与审计",
      "gov.lead": "面向 QA、审计与法规事务的检查就绪视图。",
      "gov.auditTitle": "审计轨迹（追加写入）",
      "gov.auditHint": "每条记录含执行主体、时间与状态迁移，仅追加，不可改写或删除。",
      "gov.integrity": "数据完整性（ALCOA+）",
      "gov.integrity.attributable": "可归属",
      "gov.integrity.legible": "可读",
      "gov.integrity.contemporaneous": "同步记录",
      "gov.integrity.original": "原始",
      "gov.integrity.accurate": "准确",
      "gov.integrity.complete_consistent_enduring_available": "完整·一致·持久·可取用",
      "gov.connectorTitle": "接口治理清单",
      "gov.connectorHint": "全部为契约级模拟接口，未连接任何真实租户，因此验证状态为「未验证」。",
      "gov.ledgerPath": "账本位置",
      "gov.eventCount": "已记录事件",
      "gov.refresh": "刷新",
      "gov.exportHint": "导出需 audit_export 权限（QA、审计、安全、法规事务、合规管理员）。",
      "gov.systemActor": "系统（自动执行步骤）",
      "gov.integrityDesc.attributable": "每条记录都带案例号与链路号；人工操作额外记录操作者，自动步骤归属系统而非个人。",
      "gov.integrityDesc.legible": "JSON Lines 格式，一行一条不可变记录，可直接阅读与解析。",
      "gov.integrityDesc.contemporaneous": "时间戳在该步骤执行的当刻写入，非事后补录。",
      "gov.integrityDesc.original": "仅追加写入；记录永不被改写或删除。",
      "gov.integrityDesc.accurate": "关键字段由服务端裁定，模型输出无法覆盖。",
      "gov.integrityDesc.complete_consistent_enduring_available": "完整保存状态迁移，可按案例逐条回放取用。",

      "th.vendor": "供应商",
      "th.interface": "接口",
      "th.authMode": "认证方式",
      "th.residency": "数据驻留地",
      "th.classification": "数据分级",
      "th.validation": "验证状态",
      "th.gxp": "GxP 相关",
      "th.sop": "适用 SOP",
      "th.retention": "保留期",
      "th.writeCapable": "可写回",
      "th.actor": "执行主体",
      "th.event": "事件",
      "th.time": "时间",
      "th.transition": "状态迁移",

      "toast.roleSet": "已切换为{role}",
      "toast.localeSet": "界面语言已切换为简体中文",
      "common.code": "代码",
      "common.none": "无",
      "common.copy": "复制",
      "common.expand": "展开",
      "common.collapse": "收起"
    },

    "en": {
      "app.title": "Compliance AI Guard",
      "app.subtitle": "Pharma compliance pre-check · pre-release decision gateway",
      "header.uiLanguage": "Interface language",
      "header.role": "Demo role",
      "header.demoOnly": "demo mode only",

      "auth.title": "Please sign in",
      "auth.lead": "A compliance record must be traceable to a person, so anonymous submission is not supported.",
      "auth.username": "Username",
      "auth.password": "Password",
      "auth.signIn": "Sign in",
      "auth.signOut": "Sign out",
      "auth.failed": "Sign-in failed. Check the username and password.",
      "auth.scopeNote": "A minimal local session, not enterprise SSO: no identity provider and no second factor.",
      "auth.changeTitle": "Change the initial password first",
      "auth.changeLead": "The initial password is generated and must be changed before you continue.",
      "auth.currentPassword": "Current password",
      "auth.newPassword": "New password (at least 12 characters)",
      "auth.changeSubmit": "Change password",
      "auth.changeFailed": "The password could not be changed.",
      "auth.changed": "Password changed. Please sign in again with the new one.",
      "header.modeMock": "Offline demo mode",
      "header.modeLive": "Live model connected",
      "header.modeMockTitle": "No network is used. Compliance checks run against pre-set sample answers stored on this machine, which suits demos and training.",
      "header.modeLiveTitle": "Masked text is sent to the configured model service for semantic review. Names, phone numbers and other personal details are replaced with codes before sending.",
      "header.modeLiveDegraded": "Model not ready",
      "header.modeLiveDegradedTitle": "Live model mode is on, but the service is not ready (missing key or no network). Nothing high-risk is released in this state; cases go to human review instead.",
      "nav.representative": "Representative",
      "nav.reviewer": "Reviewer",
      "nav.policy": "Model policy",
      "role.field_rep": "Field representative",
      "role.reviewer": "Reviewer",
      "role.pv_reviewer": "PV reviewer",
      "role.medical_reviewer": "Medical reviewer",
      "role.compliance_admin": "Compliance admin",
      "role.architect": "Architect",
      "role.msl": "Medical science liaison (MSL)",
      "role.qppv": "Qualified person for PV (QPPV)",
      "role.mlr_reviewer": "MLR reviewer",
      "role.qa": "Quality assurance (QA)",
      "role.regulatory_affairs": "Regulatory affairs (RA)",
      "role.auditor": "Internal audit",

      "gate.title": "This role cannot access this workspace",
      "gate.body": "\u201c{role}\u201d lacks the permission this workspace needs. Permissions come from the server matrix (GET /api/permissions); the UI only hides entry points based on it, and every protected route still checks independently.",
      "gate.needed": "Required permission",
      "gate.switchHint": "To demo the full publish/rollback loop, switch to Compliance admin.",

      "rep.title": "Call-report compliance pre-check",
      "rep.lead": "The server decides whether content may be released. The model only proposes candidates; it never owns the decision.",
      "rep.sourceSection": "Content source",
      "rep.connector": "Source system",
      "rep.connectorHint": "Sources are pluggable: Veeva CRM / Vault connectors re-read the authoritative record by record_id and reject stale versions.",
      "rep.record": "Upstream record",
      "rep.recordPlaceholder": "Select a record…",
      "rep.loadRecord": "Load record",
      "rep.recordLoaded": "Re-read {recordId} (version {version})",
      "rep.recordVersion": "Current version",
      "rep.rereadBadge": "re-read from source of record",
      "rep.contextSection": "Business context",
      "rep.product": "Product",
      "rep.market": "Market",
      "rep.channel": "Channel",
      "rep.contentLanguage": "Content language",
      "rep.contentLanguageHint": "Business field that scopes evidence retrieval. Independent of the interface language.",
      "channel.call_report": "Call report",
      "channel.med_comms": "MedComms",
      "rep.attachSection": "Attachments (image / audio)",
      "rep.attachHint": "Reference and metadata only; no binary is uploaded. An attachment can carry patient data, and this demo never stores raw content server-side. Registering one routes the case through multimodal extraction.",
      "rep.addImage": "Add image reference",
      "rep.addAudio": "Add audio reference",
      "rep.attachEmpty": "No attachments yet.",
      "rep.attachRemove": "Remove",
      "rep.attachRegistered": "Registered {kind}: {filename}",
      "rep.scenarios": "Demo scenarios",
      "rep.scenarioNote": "Scenario sample text stays in Chinese: server-side risk keywords and the evidence corpus are Chinese-only, so translating the narrative would silently disable risk detection.",
      "scenario.normal": "Normal",
      "scenario.ae": "Adverse event",
      "scenario.pii": "Personal data",
      "scenario.off_label": "Off-label",
      "scenario.redline": "Redline",
      "scenario.injection": "Prompt injection",
      "rep.contentLabel": "Call-report narrative",
      "rep.contentPlaceholder": "Paste the business narrative here. Your original text stays in your view only; the server does not retain it.",
      "rep.submit": "Run compliance check",
      "rep.checking": "Checking…",
      "rep.checkingSlow": "Waiting for the model's semantic review; this can take a few seconds…",
      "degraded.title": "The AI check did not finish. Your content is safe.",
      "degraded.body": "The model service is temporarily unavailable. Nothing is released because of it, and your narrative has been kept in full.",
      "degraded.next": "It has been routed to a person for review; you will be notified. No need to resubmit.",
      "rep.emptyContent": "Please enter case content.",

      "result.heading": "Pre-check result",
      "result.decisionLabel": "Server decision",
      "result.statusLabel": "Workflow status",
      "result.severityLabel": "Highest severity",
      "result.safeView": "Safe view (tokenized)",
      "result.safeHint": "Personal data is replaced by tokens; bracketed values are token placeholders.",
      "result.findings": "Risk findings",
      "result.evidence": "Cited evidence",
      "result.next": "Next actions",
      "result.rag": "Evidence retrieval (RAG)",
      "result.openTrace": "Open full audit trail",
      "result.trace": "Audit trail",
      "result.noFindings": "No risk findings.",
      "result.noEvidence": "No usable evidence retrieved (recorded as an explicit evidence gap).",
      "result.noNext": "No follow-up required.",
      "result.matchedTerms": "Matched terms",
      "result.rule": "Rule",
      "result.owner": "Accountable role",
      "result.sla": "SLA",
      "result.evidenceGap": "evidence gap",
      "result.missing": "Missing",
      "missing.labelFieldQualifier": "label field · ",

      "sev.legend": "Severity levels",
      "sev.S0.name": "S0 · Redline",
      "sev.S0.desc": "Most severe. Serious adverse events, data leaks, prompt injection: always blocked and escalated immediately; never self-approved.",
      "sev.S1.name": "S1 · High risk",
      "sev.S1.desc": "Requires professional review (PV / medical / compliance / security). A representative cannot release it alone.",
      "sev.S2.name": "S2 · Needs info",
      "sev.S2.desc": "Information or evidence is insufficient; re-run the check once it is supplied.",
      "sev.S3.name": "S3 · Low risk",
      "sev.S3.desc": "Formatting or wording guidance only; may be released.",

      "rag.query": "Retrieval query",
      "rag.tokens": "Retrieval keys",
      "rag.tokensHint": "CJK is split into 2-grams and the tokenized text is used; raw content never reaches retrieval.",
      "rag.stages": "Retrieval pipeline",
      "rag.candidates": "candidates",
      "rag.chunks": "Matches and exclusions",
      "rag.selected": "selected",
      "rag.excluded": "excluded",
      "rag.score": "score",
      "rag.snapshot": "Knowledge snapshot",
      "rag.gaps": "Evidence gaps",
      "rag.supporting": "Supporting evidence",
      "rag.contradiction": "Conflicting evidence",
      "rag.stage.query_build": "Build retrieval keys",
      "rag.stage.metadata_filter": "Metadata filter",
      "rag.stage.lexical_score": "Lexical scoring",
      "rag.stage.stance_split": "Stance split",
      "rag.stage.query_build.desc": "Tokenize first, then split the narrative into retrieval keys; CJK uses 2-grams.",
      "rag.stage.metadata_filter.desc": "Tenant, market, product, language, status, effective window and access scope are filtered before any scoring, so out-of-scope corpora never take part.",
      "rag.stage.lexical_score.desc": "Score chunks by retrieval-key overlap; zero-overlap items are dropped.",
      "rag.stage.stance_split.desc": "Split into supporting and conflicting evidence; non-release sources cannot justify a release.",
      "rag.excl.metadata_filter": "removed by metadata filter (tenant/market/product/language/effective window)",
      "rag.excl.no_lexical_match": "no overlap with the retrieval keys",
      "rag.excl.non_release_source": "non-release source; cannot justify a release",

      "rev.title": "Professional review",
      "rev.queue": "Review queue",
      "rev.empty": "No pending review tasks.",
      "rev.selectHint": "Pick a task on the left to see evidence, findings, model route, and audit history.",
      "rev.loadingCase": "Loading case {caseId}…",
      "rev.case": "Case",
      "rev.safeCitation": "Safe citation",
      "rev.riskFindings": "Risk findings",
      "rev.evidenceBlock": "Evidence (label / claim / SOP)",
      "rev.modelRoute": "Model route",
      "rev.timeline": "State timeline",
      "rev.decision": "Review decision",
      "rev.taskId": "Task id",
      "rev.decisionField": "Decision",
      "rev.accept": "Accept (allow)",
      "rev.acceptBlocked": "Accept (allow) — not permitted for {severity}",
      "rev.reject": "Reject (blocked)",
      "rev.escalate": "Escalate (human review)",
      "rev.needsInfo": "Return for more information",
      "rev.reason": "Reason (required)",
      "rev.reasonPlaceholder": "State the basis: which evidence you relied on, or what is missing. The reason enters the audit record.",

      "feedback.title": "Was this assessment wrong?",
      "feedback.hint": "Flagging it creates a candidate regression case; another colleague must confirm it before it enters the golden set. This is the only mechanism that makes the rules more accurate over time.",
      "feedback.kind": "What went wrong",
      "feedback.falsePositive": "False positive: the content was fine",
      "feedback.falseNegative": "Missed risk: this should have been caught",
      "feedback.reason": "Tell us why",
      "feedback.reasonPlaceholder": "For example: this is a routine visit note and makes no off-label claim.",
      "feedback.submit": "Flag and create a candidate case",
      "feedback.sent": "Recorded. Awaiting confirmation by another colleague.",
      "feedback.needReason": "Please give a reason: a candidate with no reason cannot be reviewed.",
      "feedback.confirmNote": "A candidate keeps only the masked narrative, never personal data.",
      "rev.submitDecision": "Submit decision",
      "rev.reasonRequired": "A reason is required for a review decision.",
      "rev.decisionRecorded": "Decision recorded: {decision}",
      "rev.sla": "SLA",
      "rev.slaDeadline": "Deadline",
      "rev.requiredRole": "Required role",
      "rev.systemDecision": "System decision",
      "rev.spans": "Execution spans ({count})",
      "rev.auditEvents": "Audit events ({count})",
      "rev.timelineHint": "Top to bottom is the real execution order; every step is written to the audit ledger.",

      "policy.title": "Model policy",
      "policy.lead": "Model profiles and task routes are versioned configuration. Publish and rollback require an admin role.",
      "policy.refresh": "Refresh",
      "policy.saveDraft": "Save draft",
      "policy.testTask": "Test task",
      "policy.mockTest": "Connectivity test",
      "policy.publish": "Publish",
      "policy.rollback": "Rollback",
      "policy.working": "Working…",
      "policy.profiles": "Model profiles",
      "policy.routes": "Task routes",
      "policy.diff": "Publish diff",
      "policy.history": "Version history",
      "policy.noDraft": "No staged draft.",
      "policy.publishedVersion": "Published version {version}",
      "policy.draftStaged": "Draft staged. Review the diff before publishing.",
      "policy.publishedToast": "Published version {version}",
      "policy.rolledBackToast": "Rolled back to version {version}",
      "policy.testResult": "Test {outcome} · provider {provider} · model {model} · route {route} · {latency}ms",
      "policy.testOk": "passed",
      "policy.testFailed": "failed",
      "policy.testError": "Test failed: {message}",
      "policy.masked": "masked",
      "policy.on": "enabled",
      "policy.off": "disabled",
      "policy.stagedDraftHeader": "Staged draft (not yet published)",
      "policy.metrics": "Runtime metrics",
      "policy.metricCases": "Cases received",
      "policy.metricCompleted": "Completed",
      "policy.metricModelCalls": "Model calls",

      "th.profile": "Profile",
      "th.provider": "Provider",
      "th.model": "Model",
      "th.capabilities": "Capabilities",
      "th.dataClasses": "Data classes",
      "th.region": "Region",
      "th.credential": "Credential",
      "th.timeout": "Timeout (ms)",
      "th.budget": "Token budget",
      "th.enabled": "State",
      "th.task": "Task",
      "th.primary": "Primary profile",
      "th.fallback": "Fallback profiles",
      "th.requiredCaps": "Required capabilities",
      "th.regions": "Allowed regions",
      "th.routeVersion": "Route version",
      "th.humanOnFailure": "Human on failure",

      "nav.governance": "Quality & audit",
      "nav.records": "My records",
      "nav.shortcutHint": "Press 1-5 to switch workspaces (ignored while typing)",

      "notif.label": "Notifications",
      "notif.title": "Review outcomes and notifications",
      "notif.panelTitle": "Review outcomes and notifications",
      "notif.empty": "Nothing new.",
      "notif.markRead": "Mark as read",

      "rep.narrativeSection": "Call report narrative",
      "rep.contentHelp": "Hints appear as you write. Your narrative is kept in full and is never edited by the tool.",
      "rep.submitShortcut": "Cmd/Ctrl + Enter to submit",
      "rep.retry": "Retry",
      "rep.examplesTitle": "Examples and training",
      "rep.precheckTitle": "Pre-submission check",
      "rep.precheckClean": "Nothing found that needs handling yet",
      "rep.precheckTiming": "Checked locally in {ms} ms",
      "rep.draftFound": "An unsubmitted draft was found ({time}).",
      "rep.draftRestore": "Restore draft",
      "rep.draftDiscard": "Discard",
      "rep.draftRestored": "Draft restored.",
      "rep.draftDiscarded": "Draft discarded.",
      "rep.serviceError": "The service did not respond. Your draft is saved on this machine; you can retry.",
      "rep.hintPrefix": "Heads up",
      "rep.hintPreliminary": "These are preliminary cues only; the submitted check is what decides.",

      "result.technical": "Technical details (for audit reconciliation)",
      "result.revise": "Revise this and submit again",
      "result.reviseTitle": "Creates a new version based on this record. The original is never overwritten.",

      "followup.title": "A little more information needed",
      "followup.submit": "Submit the additional details",
      "followup.saving": "Submitting…",
      "followup.done": "Added. The assessment has been updated.",
      "followup.empty": "Please fill in at least one field.",

      "rewrite.title": "How to fix it",
      "rewrite.suggestionLabel": "Suggested wording (re-checked; contains no flagged phrasing)",
      "rewrite.apply": "Replace the narrative with this",
      "rewrite.applied": "Replaced with the suggestion. Please confirm it still matches what happened.",

      "appeal.title": "Think this is wrong?",
      "appeal.hint": "An appeal does not lift the block. An authorised colleague reviews it and decides.",
      "appeal.reasonLabel": "Tell us why",
      "appeal.reasonPlaceholder": "For example: the customer raised this themselves and I recorded it verbatim.",
      "appeal.submit": "Submit appeal",
      "appeal.done": "Appeal submitted. You will be notified once someone has reviewed it.",
      "appeal.needReason": "Please give a reason for the appeal.",

      "records.title": "My records",
      "records.lead": "Everything you have submitted, with its outcome, progress, and the option to revise and resubmit.",
      "records.filter": "Filter by outcome",
      "records.filterAll": "All",
      "records.refresh": "Refresh",
      "records.time": "Submitted",
      "records.outcome": "Outcome",
      "records.product": "Product",
      "records.findings": "Issues",
      "records.action": "Action",
      "records.open": "Open",
      "records.empty": "Nothing submitted yet.",
      "records.more": "Load more",

      "gov.candidatesTitle": "Candidate regression cases",
      "gov.candidatesHint": "False positives and missed risks flagged by reviewers. Another colleague must confirm one before it enters the golden set, so no single person can change the release gate alone.",
      "gov.candidatesSummary": "{pending} awaiting confirmation, {confirmed} confirmed.",
      "gov.candidatesEmpty": "Nothing awaiting confirmation.",
      "gov.candidateConfirm": "Confirm and add to the golden set",
      "gov.candidateConfirmed": "Confirmed. It will join the regression set.",

      "gov.chainTitle": "Audit chain integrity",
      "gov.chainHint": "Each record carries a fingerprint of the one before it; any edit or deletion breaks the chain and is located.",
      "gov.chainOk": "Chain intact; {count} records verified.",
      "gov.chainBroken": "Chain broken: nothing from position {seq} onwards can be trusted. {reason}",
      "gov.oversightTitle": "Human oversight health",
      "gov.oversightHint": "A very low override rate is the warning sign: it suggests review has become a formality.",

      "onboarding.title": "Three things before you start",
      "onboarding.whatTitle": "What this tool does",
      "onboarding.whatBody": "It checks a call report before it goes out, flagging adverse events, personal data, off-label wording, and compliance redlines. Your narrative is kept in full and never edited.",
      "onboarding.roleTitle": "What your role can do",
      "onboarding.roleBody": "You only see the modules your role permits, and every action is checked again on the server.",
      "onboarding.tryTitle": "Try one",
      "onboarding.tryBody": "Type \u201c患者服药后出现皮疹\u201d in the narrative and watch the hints appear as you write.",
      "onboarding.start": "Get started",

      "glossary.what": "What does this mean?",

      "pv.title": "Pharmacovigilance assessment (ICSR)",
      "pv.notRelevant": "No adverse-reaction term detected; this case is not a safety report.",
      "pv.criteriaTitle": "Four ICSR minimum criteria",
      "pv.criteriaHint": "All four must be present for a valid ICSR. A missing criterion is a follow-up task, never a reason to drop a safety signal.",
      "pv.criterion.identifiable_patient": "Identifiable patient",
      "pv.criterion.identifiable_reporter": "Identifiable reporter",
      "pv.criterion.suspect_product": "Suspect medicinal product",
      "pv.criterion.suspect_reaction": "Suspect adverse reaction",
      "pv.met": "met",
      "pv.unmet": "not met",
      "pv.validIcsr": "Valid ICSR",
      "pv.invalidIcsr": "Incomplete ICSR",
      "pv.seriousness": "Seriousness",
      "pv.clockTitle": "Regulatory reporting clock",
      "pv.dayZero": "Day 0 (first company awareness)",
      "pv.due": "Submission due",
      "pv.expedited": "Expedited",
      "pv.aggregate": "Aggregate reporting (PSUR/PBRER)",
      "pv.clockDays": "{days} calendar days",
      "pv.followup": "Follow-up required",
      "pv.conflict": "Policy outcome and ICSR assessment disagree — human review required",
      "pv.scopeNote": "A demo triage aid, not a validated safety database and not regulatory advice.",

      "sig.title": "Electronic signature",
      "sig.signer": "Signer",
      "sig.role": "Function",
      "sig.signedAt": "Signed at",
      "sig.meaning": "Meaning of signature",
      "sig.digest": "Content digest",
      "sig.kind": "Signature strength",
      "sig.kind.demo_manifestation": "Demo manifestation (no identity provider, no second factor)",
      "sig.meaning.approved_for_release": "Approved for release",
      "sig.meaning.rejected_blocked_from_release": "Rejected, blocked from release",
      "sig.meaning.escalated_for_further_review": "Escalated for further review",
      "sig.meaning.returned_for_additional_information": "Returned for additional information",
      "sig.meaning.reviewed": "Reviewed",
      "sig.hint": "The signature is digest-bound to the decision content; changing any bound field fails verification.",

      "gov.title": "Quality & audit",
      "gov.lead": "Inspection-readiness view for QA, audit, and regulatory affairs.",
      "gov.auditTitle": "Audit trail (append-only)",
      "gov.auditHint": "Every record carries actor, timestamp, and state transition. Append-only: never rewritten or deleted.",
      "gov.integrity": "Data integrity (ALCOA+)",
      "gov.integrity.attributable": "Attributable",
      "gov.integrity.legible": "Legible",
      "gov.integrity.contemporaneous": "Contemporaneous",
      "gov.integrity.original": "Original",
      "gov.integrity.accurate": "Accurate",
      "gov.integrity.complete_consistent_enduring_available": "Complete · consistent · enduring · available",
      "gov.connectorTitle": "Interface governance register",
      "gov.connectorHint": "All interfaces are contract-only mocks against no real tenant, so validation status is \u201cnot validated\u201d.",
      "gov.ledgerPath": "Ledger location",
      "gov.eventCount": "Recorded events",
      "gov.refresh": "Refresh",
      "gov.exportHint": "Export requires audit_export (QA, audit, security, regulatory affairs, compliance admin).",
      "gov.systemActor": "System (automated step)",
      "gov.integrityDesc.attributable": "Every record carries case and trace ids; human actions also record the acting user, and automated steps are attributed to the system rather than a person.",
      "gov.integrityDesc.legible": "JSON Lines: one immutable record per line, directly readable and parsable.",
      "gov.integrityDesc.contemporaneous": "The timestamp is written at the moment the step executes, not backfilled.",
      "gov.integrityDesc.original": "Append-only; records are never rewritten or deleted.",
      "gov.integrityDesc.accurate": "Decisive fields are server-controlled; model output cannot overwrite them.",
      "gov.integrityDesc.complete_consistent_enduring_available": "State transitions are fully persisted and replayable per case.",

      "th.vendor": "Vendor",
      "th.interface": "Interface",
      "th.authMode": "Auth mode",
      "th.residency": "Data residency",
      "th.classification": "Data classification",
      "th.validation": "Validation status",
      "th.gxp": "GxP relevant",
      "th.sop": "Governing SOP",
      "th.retention": "Retention",
      "th.writeCapable": "Write capable",
      "th.actor": "Actor",
      "th.event": "Event",
      "th.time": "Time",
      "th.transition": "State transition",

      "toast.roleSet": "Switched to {role}",
      "toast.localeSet": "Interface language switched to English",
      "common.code": "code",
      "common.none": "none",
      "common.copy": "Copy",
      "common.expand": "Expand",
      "common.collapse": "Collapse"
    }
  };

  /* Vocabulary: server code -> readable phrase. The code itself stays visible
   * in the UI next to the phrase, so nothing here hides an audit value. */
  var VOCAB = {
    "zh-CN": {
      decision: {
        allow: "允许发布",
        needs_info: "需补充信息",
        human_review: "转人工审核",
        blocked: "阻断发布",
        refused: "拒绝处理"
      },
      decisionHint: {
        allow: "内容与说明书证据一致，可以对外使用。",
        needs_info: "缺少必要信息或证据，补齐后可重新预检。",
        human_review: "存在高风险信号，须由对应专业角色人工判定。",
        blocked: "触发红线规则，内容不得对外发出。",
        refused: "处理链路未能安全完成，已按失败安全处理，不做放行。"
      },
      state: {
        RECEIVED: "已接收",
        AUTHORIZED: "已鉴权",
        PREPROCESSED: "已脱敏预处理",
        CONTEXT_READY: "上下文就绪",
        CLASSIFIED: "已分类路由",
        EVIDENCE_READY: "证据已检索",
        EVALUATED: "模型已评估",
        VALIDATED: "结果已校验",
        DECISIONED: "已作出判定",
        ALLOWED: "已放行",
        NEEDS_INFO: "待补充信息",
        HUMAN_REVIEW: "待人工审核",
        BLOCKED: "已阻断",
        REFUSED: "已拒绝",
        AUDITED: "已写入审计",
        COMPLETED: "流程完成",
        FAILED_RETRYABLE: "可重试失败",
        FAILED_SAFE: "失败安全（不放行）",
        MANUAL_DEGRADED: "降级人工处理"
      },
      event: {
        case_received: "收到案例，记录原文摘要哈希（不留存原文）",
        security_findings: "完成安全扫描（个人信息、注入检测）",
        evidence_retrieved: "完成证据检索，生成知识快照",
        model_call: "调用模型产出候选结论",
        review_task_created: "创建人工审核任务",
        case_finalized: "锁定最终判定",
        case_unsafe_error: "出现不安全错误，转人工处理"
      },
      span: {
        run_check_case: "整体预检流程",
        "intake.authorize": "入口鉴权",
        "security.preprocess": "安全预处理与脱敏",
        "context.prepare": "准备业务上下文与策略包",
        "task.classify": "判定任务类型与模型路由",
        "knowledge.retrieve": "检索证据（RAG）",
        "model.evaluate": "模型评估（仅候选）",
        "policy.validate": "校验模型输出是否越权",
        "policy.decide": "服务端规则判定",
        "decision.human_review": "转入人工审核",
        "decision.allow": "判定为放行",
        "decision.blocked": "判定为阻断",
        "decision.needs_info": "判定为需补充",
        "audit.finalize": "写入审计账本",
        "workflow.complete": "流程收尾"
      },
      finding: {
        potential_adverse_event: "疑似不良事件",
        serious_adverse_event: "严重不良事件",
        bribery_or_inducement: "商业贿赂或不当利益",
        comparative_claim: "竞品比较声称",
        prompt_injection: "提示注入攻击",
        pii: "个人身份信息",
        phi: "患者健康信息",
        severe_pii_leak: "大规模个人信息泄露",
        off_label: "超说明书使用",
        evidence_conflict: "证据冲突",
        expired_evidence: "证据已过期",
        missing_evidence: "缺少支持证据",
        missing_context: "缺少必要上下文",
        permission_failure: "权限校验失败",
        irreversible_write: "不可逆写操作",
        security_issue: "安全风险",
        unapproved_promotion: "未批准的推广表述",
        formatting: "格式或表述问题"
      },
      findingWhy: {
        potential_adverse_event: "叙述中出现疑似不良反应描述，按药物警戒要求必须上报并由专业人员判断。",
        serious_adverse_event: "出现可能危及生命的描述，属最高优先级安全信号，须立即上报。",
        bribery_or_inducement: "涉及利益输送表述，存在合规与法律风险。",
        comparative_claim: "与竞品比较的表述需要有充分证据支持，否则构成不当宣传。",
        prompt_injection: "检测到试图让模型忽略规则的指令，已按攻击处理并阻断。",
        pii: "文本中含可直接识别个人的身份信息，已令牌化处理。",
        phi: "文本中含患者健康信息，需按隐私要求处理。",
        severe_pii_leak: "涉及批量个人信息外泄，按数据泄露事件处理。",
        off_label: "用法、剂量或适应症与获批说明书不一致。",
        evidence_conflict: "检索到相互矛盾的证据，需人工判断以哪条为准。",
        expired_evidence: "所依据的证据已超出生效期，需重新检索当前版本。",
        missing_evidence: "没有检索到可支持该表述的发布级证据。",
        missing_context: "缺少判断所需的上下文或实体信息。",
        permission_failure: "所需操作超出当前角色权限。",
        irreversible_write: "该操作不可撤销，需管理员批准。",
        security_issue: "存在安全层面的风险信号。",
        unapproved_promotion: "包含未经批准的推广性表述。",
        formatting: "仅为格式或措辞层面的建议，不影响合规结论。"
      },
      nextAction: {
        "route to pharmacovigilance intake and medical review": "转药物警戒接收与医学审核",
        "immediate pharmacovigilance intake and medical review": "立即转药物警戒接收与医学审核",
        "compliance and legal review; message blocked": "转合规与法务审核，内容先行阻断",
        "require comparison context evidence before release": "补齐比较类证据后才可发布",
        "block message and escalate to security": "阻断内容并上报安全团队",
        "route to privacy review and redaction check": "转隐私审核并核对脱敏结果",
        "block and escalate as data breach": "阻断并按数据泄露事件上报",
        "label field mismatch review": "核对说明书字段差异",
        "resolve conflicting evidence before release": "先解决证据冲突再发布",
        "re-retrieve current evidence; professional review": "重新检索当前证据并由专业人员复核",
        "collect supporting evidence": "补充支持性证据",
        "request missing context or entities": "补充缺失的上下文或实体信息",
        "block action; review tool permissions": "阻断该操作并复核工具权限",
        "block irreversible write; require admin approval": "阻断不可逆写入，需管理员批准",
        "security review": "转安全审核",
        "low-risk guidance: adjust formatting": "低风险提示：调整格式或措辞"
      },
      role: {
        representative: "医药代表",
        compliance: "合规",
        medical_review: "医学审核",
        pharmacovigilance: "药物警戒",
        legal: "法务",
        security: "安全",
        auditor: "审计",
        admin: "管理员",
        architect: "架构师",
        system: "系统",
        field_rep: "医药代表",
        reviewer: "审核人",
        pv_reviewer: "药物警戒审核人",
        medical_reviewer: "医学审核人",
        compliance_admin: "合规管理员",
        msl: "医学科学联络官",
        qppv: "药物警戒负责人",
        qa: "质量保证",
        regulatory_affairs: "法规事务",
        mlr_reviewer: "MLR 审批人"
      },
      // The five functions added for the pharma role matrix. Without these the
      // signature block, review queue, and audit trail print the raw code.
      roleFunction: {
        field_rep: "商务·field force",
        msl: "医学事务·MSL",
        reviewer: "通用审核",
        pv_reviewer: "药物警戒",
        qppv: "药物警戒负责人·QPPV",
        medical_reviewer: "医学事务",
        mlr_reviewer: "MLR 审批",
        compliance_admin: "合规",
        qa: "质量保证·QA",
        regulatory_affairs: "法规事务·RA",
        auditor: "内审",
        architect: "IT 架构"
      },
      seriousness: {
        fatal: "死亡",
        life_threatening: "危及生命",
        serious: "严重（住院/致残/先天畸形）",
        non_serious: "非严重"
      },
      validation: {
        not_validated: "未验证（演示用）",
        qualified: "已鉴定",
        validated: "已验证（CSV）"
      },
      authMode: {
        none: "无",
        oauth2_client_credentials: "OAuth2 客户端凭据",
        demo_role_header: "演示角色请求头（非真实身份认证）"
      },
      residency: { CN: "中国境内", EU: "欧盟", US: "美国" },
      dataClass: {
        public: "公开",
        internal: "内部",
        confidential: "机密",
        pii_tokenized: "个人信息（已令牌化）",
        phi_tokenized: "健康信息（已令牌化）"
      },
      yesno: { "true": "是", "false": "否" },
      interfaceKind: {
        "REST v24 (mock)": "REST v24（模拟）",
        "Vault REST v24 (mock)": "Vault REST v24（模拟）",
        "in-app form": "应用内表单"
      },
      icsrBasis: {
        term_present: "文本中出现「{value}」",
        tokenized_entity: "已识别患者实体（令牌化）",
        patient_token_present: "脱敏前存在患者标识信息（仅记录存在，不保留原值）",
        submitter_is_reporter: "提交本例的代表即报告者",
        product_in_context: "上下文产品 {value}",
        absent: "未获取到，需随访补齐"
      },
      missing: {
        evidence: "支持性证据",
        evidence_gap: "证据缺口",
        context: "上下文",
        entities: "关键实体"
      },
      attachKind: { image: "图片引用", audio: "音频引用" },
      labelField: {
        indication: "适应症",
        indication_id: "适应症编号",
        population: "适用人群",
        line: "治疗线数",
        dose: "剂量",
        route: "给药途径",
        duration: "疗程",
        combination: "联合用药"
      },
      capability: {
        view_case_summary: "查看案例",
        review_case: "审核案例",
        pv_review: "药物警戒审核",
        medical_review: "医学审核",
        reidentify_phi: "还原患者信息",
        case_escalate: "升级案例",
        architecture_review: "查看/起草模型策略",
        audit_export: "导出审计",
        config_publish: "发布配置",
        config_rollback: "回滚配置"
      },
      sla: { immediate: "立即", "4h": "4 小时内", "8h": "8 小时内", "24h": "24 小时内", "72h": "72 小时内" }
    },

    en: {
      decision: {
        allow: "Allow release",
        needs_info: "Needs more information",
        human_review: "Route to human review",
        blocked: "Block release",
        refused: "Refused"
      },
      decisionHint: {
        allow: "Content is consistent with label evidence and may be used externally.",
        needs_info: "Required information or evidence is missing; re-run once supplied.",
        human_review: "High-risk signals present; a qualified role must decide.",
        blocked: "A redline rule fired; the content must not be released.",
        refused: "The pipeline could not complete safely, so it failed safe rather than releasing."
      },
      state: {
        RECEIVED: "Received",
        AUTHORIZED: "Authorized",
        PREPROCESSED: "Tokenized / preprocessed",
        CONTEXT_READY: "Context ready",
        CLASSIFIED: "Classified and routed",
        EVIDENCE_READY: "Evidence retrieved",
        EVALUATED: "Model evaluated",
        VALIDATED: "Output validated",
        DECISIONED: "Decision made",
        ALLOWED: "Allowed",
        NEEDS_INFO: "Awaiting information",
        HUMAN_REVIEW: "Awaiting human review",
        BLOCKED: "Blocked",
        REFUSED: "Refused",
        AUDITED: "Written to audit",
        COMPLETED: "Completed",
        FAILED_RETRYABLE: "Retryable failure",
        FAILED_SAFE: "Failed safe (no release)",
        MANUAL_DEGRADED: "Degraded to manual handling"
      },
      event: {
        case_received: "Case received; input digest recorded (raw text not retained)",
        security_findings: "Security scan completed (personal data, injection)",
        evidence_retrieved: "Evidence retrieved; knowledge snapshot pinned",
        model_call: "Model called for a candidate result",
        review_task_created: "Human review task created",
        case_finalized: "Final decision locked",
        case_unsafe_error: "Unsafe error; routed to human handling"
      },
      span: {
        run_check_case: "Whole pre-check run",
        "intake.authorize": "Intake authorization",
        "security.preprocess": "Security preprocessing and tokenization",
        "context.prepare": "Prepare business context and policy bundle",
        "task.classify": "Classify task and resolve model route",
        "knowledge.retrieve": "Retrieve evidence (RAG)",
        "model.evaluate": "Model evaluation (candidate only)",
        "policy.validate": "Validate model output against server rules",
        "policy.decide": "Server-side rule decision",
        "decision.human_review": "Route to human review",
        "decision.allow": "Decided: allow",
        "decision.blocked": "Decided: block",
        "decision.needs_info": "Decided: needs information",
        "audit.finalize": "Write to audit ledger",
        "workflow.complete": "Workflow wrap-up"
      },
      finding: {
        potential_adverse_event: "Potential adverse event",
        serious_adverse_event: "Serious adverse event",
        bribery_or_inducement: "Bribery or improper inducement",
        comparative_claim: "Comparative claim",
        prompt_injection: "Prompt injection attempt",
        pii: "Personally identifiable information",
        phi: "Protected health information",
        severe_pii_leak: "Large-scale personal data leak",
        off_label: "Off-label use",
        evidence_conflict: "Conflicting evidence",
        expired_evidence: "Expired evidence",
        missing_evidence: "Missing supporting evidence",
        missing_context: "Missing required context",
        permission_failure: "Permission check failed",
        irreversible_write: "Irreversible write",
        security_issue: "Security risk",
        unapproved_promotion: "Unapproved promotional claim",
        formatting: "Formatting or wording issue"
      },
      findingWhy: {
        potential_adverse_event: "The narrative describes a suspected adverse reaction, which pharmacovigilance rules require to be reported and professionally assessed.",
        serious_adverse_event: "Language suggests a life-threatening outcome: the highest-priority safety signal, reportable immediately.",
        bribery_or_inducement: "Language implies improper benefit transfer, creating compliance and legal exposure.",
        comparative_claim: "Comparisons against competitors need sufficient evidence or they constitute improper promotion.",
        prompt_injection: "An instruction attempting to make the model ignore its rules was detected and blocked.",
        pii: "The text contains directly identifying personal data, which has been tokenized.",
        phi: "The text contains patient health information and must be handled under privacy rules.",
        severe_pii_leak: "Bulk personal data exposure; handled as a data-breach event.",
        off_label: "Usage, dose, or indication does not match the approved label.",
        evidence_conflict: "Retrieved evidence contradicts itself; a human must decide which governs.",
        expired_evidence: "The evidence relied on is outside its effective window; re-retrieve the current version.",
        missing_evidence: "No release-grade evidence supports the statement.",
        missing_context: "Context or entities needed for a decision are absent.",
        permission_failure: "The action exceeds the current role's permissions.",
        irreversible_write: "The operation cannot be undone and needs admin approval.",
        security_issue: "A security-level risk signal is present.",
        unapproved_promotion: "Contains promotional language that was never approved.",
        formatting: "Formatting or wording guidance only; it does not change the compliance outcome."
      },
      nextAction: {
        "route to pharmacovigilance intake and medical review": "Route to pharmacovigilance intake and medical review",
        "immediate pharmacovigilance intake and medical review": "Immediate pharmacovigilance intake and medical review",
        "compliance and legal review; message blocked": "Compliance and legal review; message blocked",
        "require comparison context evidence before release": "Require comparison evidence before release",
        "block message and escalate to security": "Block the message and escalate to security",
        "route to privacy review and redaction check": "Route to privacy review and check redaction",
        "block and escalate as data breach": "Block and escalate as a data breach",
        "label field mismatch review": "Review the label field mismatch",
        "resolve conflicting evidence before release": "Resolve conflicting evidence before release",
        "re-retrieve current evidence; professional review": "Re-retrieve current evidence and have it professionally reviewed",
        "collect supporting evidence": "Collect supporting evidence",
        "request missing context or entities": "Request the missing context or entities",
        "block action; review tool permissions": "Block the action and review tool permissions",
        "block irreversible write; require admin approval": "Block the irreversible write; require admin approval",
        "security review": "Security review",
        "low-risk guidance: adjust formatting": "Low-risk guidance: adjust formatting"
      },
      role: {
        representative: "Representative",
        compliance: "Compliance",
        medical_review: "Medical review",
        pharmacovigilance: "Pharmacovigilance",
        legal: "Legal",
        security: "Security",
        auditor: "Auditor",
        admin: "Admin",
        architect: "Architect",
        system: "System",
        field_rep: "Field representative",
        reviewer: "Reviewer",
        pv_reviewer: "PV reviewer",
        medical_reviewer: "Medical reviewer",
        compliance_admin: "Compliance admin",
        msl: "Medical science liaison",
        qppv: "Qualified person for PV",
        qa: "Quality assurance",
        regulatory_affairs: "Regulatory affairs",
        mlr_reviewer: "MLR reviewer"
      },
      roleFunction: {
        field_rep: "Commercial · field force",
        msl: "Medical affairs · MSL",
        reviewer: "General review",
        pv_reviewer: "Pharmacovigilance",
        qppv: "Qualified person for PV · QPPV",
        medical_reviewer: "Medical affairs",
        mlr_reviewer: "MLR approval",
        compliance_admin: "Compliance",
        qa: "Quality assurance · QA",
        regulatory_affairs: "Regulatory affairs · RA",
        auditor: "Internal audit",
        architect: "IT architecture"
      },
      seriousness: {
        fatal: "Fatal",
        life_threatening: "Life-threatening",
        serious: "Serious (hospitalisation / disability / congenital anomaly)",
        non_serious: "Non-serious"
      },
      validation: {
        not_validated: "Not validated (demo)",
        qualified: "Qualified",
        validated: "Validated (CSV)"
      },
      authMode: {
        none: "None",
        oauth2_client_credentials: "OAuth2 client credentials",
        demo_role_header: "Demo role header (not real authentication)"
      },
      residency: { CN: "China", EU: "European Union", US: "United States" },
      dataClass: {
        public: "Public",
        internal: "Internal",
        confidential: "Confidential",
        pii_tokenized: "Personal data (tokenized)",
        phi_tokenized: "Health data (tokenized)"
      },
      yesno: { "true": "Yes", "false": "No" },
      interfaceKind: {
        "REST v24 (mock)": "REST v24 (mock)",
        "Vault REST v24 (mock)": "Vault REST v24 (mock)",
        "in-app form": "in-app form"
      },
      icsrBasis: {
        term_present: "term \u201c{value}\u201d present in the narrative",
        tokenized_entity: "patient entity identified (tokenized)",
        patient_token_present: "a patient identifier was present before masking (presence only, value not retained)",
        submitter_is_reporter: "the submitting representative is the reporter",
        product_in_context: "product {value} in context",
        absent: "not captured; follow-up required"
      },
      missing: {
        evidence: "supporting evidence",
        evidence_gap: "evidence gap",
        context: "context",
        entities: "key entities"
      },
      attachKind: { image: "image reference", audio: "audio reference" },
      labelField: {
        indication: "indication",
        indication_id: "indication id",
        population: "population",
        line: "therapy line",
        dose: "dose",
        route: "route of administration",
        duration: "duration",
        combination: "combination use"
      },
      capability: {
        view_case_summary: "View cases",
        review_case: "Review cases",
        pv_review: "Pharmacovigilance review",
        medical_review: "Medical review",
        reidentify_phi: "Re-identify patient data",
        case_escalate: "Escalate cases",
        architecture_review: "View/draft model policy",
        audit_export: "Export audit",
        config_publish: "Publish config",
        config_rollback: "Roll back config"
      },
      sla: {
        immediate: "immediately",
        "4h": "within 4h",
        "8h": "within 8h",
        "24h": "within 24h",
        "72h": "within 72h"
      }
    }
  };

  var current = DEFAULT_LOCALE;
  var listeners = [];

  function isSupported(value) {
    return typeof value === "string" && LOCALES.indexOf(value) >= 0;
  }

  function readStored() {
    try {
      var stored = global.localStorage ? global.localStorage.getItem(STORAGE_KEY) : null;
      return isSupported(stored) ? stored : null;
    } catch (err) {
      return null; // storage blocked (private mode): fall back to the default
    }
  }

  function writeStored(value) {
    try {
      if (global.localStorage) { global.localStorage.setItem(STORAGE_KEY, value); }
    } catch (err) {
      /* non-fatal: the choice stays session-only */
    }
  }

  function t(key, vars) {
    var value = (STRINGS[current] || {})[key];
    if (value == null) { value = (STRINGS[FALLBACK_LOCALE] || {})[key]; }
    if (value == null) { return key; }
    if (!vars) { return value; }
    return value.replace(/\{(\w+)\}/g, function (match, name) {
      return Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : match;
    });
  }

  /* Look up a vocabulary phrase. Returns the raw code when unmapped, so a new
   * server value degrades to something truthful instead of silently blank. */
  function term(group, code, vars) {
    if (code == null || code === "") { return ""; }
    var table = (VOCAB[current] || {})[group] || {};
    var value = null;
    if (Object.prototype.hasOwnProperty.call(table, code)) {
      value = table[code];
    } else {
      var fallback = (VOCAB[FALLBACK_LOCALE] || {})[group] || {};
      if (Object.prototype.hasOwnProperty.call(fallback, code)) {
        value = fallback[code];
      }
    }
    if (value == null) { return String(code); }
    if (!vars) { return value; }
    // Some vocabulary entries carry placeholders (e.g. the ICSR basis strings),
    // so interpolate the same way `t()` does rather than leaking "{value}".
    return value.replace(/\{(\w+)\}/g, function (match, name) {
      return Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : match;
    });
  }

  function hasTerm(group, code) {
    var table = (VOCAB[current] || {})[group] || {};
    return Object.prototype.hasOwnProperty.call(table, code);
  }

  /* Missing-information codes are partly dynamic: the policy engine emits
   * "label_field:<field>" for every label mismatch. Resolve the prefix so the
   * UI shows "剂量" instead of the raw "label_field:dose", while unknown
   * fields still degrade to the literal code rather than vanishing. */
  function missingTerm(code) {
    if (code == null || code === "") { return ""; }
    var raw = String(code);
    var prefix = "label_field:";
    if (raw.indexOf(prefix) === 0) {
      var field = raw.slice(prefix.length);
      var name = term("labelField", field);
      var qualifier = t("missing.labelFieldQualifier");
      return qualifier ? qualifier + name : name;
    }
    return term("missing", raw);
  }

  function applyStatic(root) {
    var scope = root || global.document;
    if (!scope || !scope.querySelectorAll) { return; }
    Array.prototype.forEach.call(scope.querySelectorAll("[data-i18n]"), function (node) {
      node.textContent = t(node.getAttribute("data-i18n"));
    });
    Array.prototype.forEach.call(scope.querySelectorAll("[data-i18n-placeholder]"), function (node) {
      node.setAttribute("placeholder", t(node.getAttribute("data-i18n-placeholder")));
    });
    Array.prototype.forEach.call(scope.querySelectorAll("[data-i18n-title]"), function (node) {
      node.setAttribute("title", t(node.getAttribute("data-i18n-title")));
    });
  }

  function setLocale(next, options) {
    if (!isSupported(next)) { return current; }
    current = next;
    writeStored(next);
    if (global.document && global.document.documentElement) {
      global.document.documentElement.setAttribute("lang", next);
    }
    applyStatic();
    if (!(options && options.silent)) {
      listeners.forEach(function (fn) {
        try { fn(next); } catch (err) { /* one bad listener must not block the rest */ }
      });
    }
    return current;
  }

  function init() {
    return setLocale(readStored() || DEFAULT_LOCALE, { silent: true });
  }

  global.CGI18n = {
    t: t,
    term: term,
    hasTerm: hasTerm,
    missingTerm: missingTerm,
    locale: function () { return current; },
    setLocale: setLocale,
    onChange: function (fn) { if (typeof fn === "function") { listeners.push(fn); } },
    init: init,
    applyStatic: applyStatic,
    locales: LOCALES.slice()
  };
})(window);
