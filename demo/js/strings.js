export const LANGS = ['zh', 'en', 'ja', 'ko', 'de', 'uk', 'in', 'br'];

export const T = {
  headline: '把隐私交给 AI 之前，先脱敏',
  headlineEn: 'Redact PII before it reaches an AI',
  trust: '🔒 全部在你的浏览器里运行，数据不上传 · runs locally, nothing uploaded',
  loading: '加载中… · loading',
  ready: '● 已就绪 · ready',
  failed: '⚠ 加载失败 · failed: ',
  tryLabel: '试试 · Try:',
  redact: '一键脱敏 · Redact',
  yourText: '你的原文 · Your text',
  aiSees: 'AI 看到的 · What the AI sees',
  restoredOk: '✓ 还能一字不差地还原 · restored exactly',
  howTitle: '怎么做到的 · How it works',
  steps: ['① 找出隐私信息 · find personal info', '② 换成安全替身 · swap in safe look-alikes', '③ 回复里再换回来 · restore from the reply'],
  badges: ['74 类隐私信息', '8 种语言', '可逆还原', '开源 Apache-2.0', '身份证/银行卡校验'],
  limitNote: '⚠ 脱敏移除显式 PII，但不能保证抵御从残留上下文的推理式重识别 · removes explicit PII, not a guarantee against inference-based re-identification',
  llmProof: '真实大模型，这个场景零泄漏 · Real AIs, zero leaks in this case',
  llmProvenance: '来源 · Source: ',
  llmCaptionTail: '。非对抗输入下的缓存结果，非绝对保证 · cached reference run, not a guarantee against adversarial input.',
  devFold: '开发者选项 · For developers',
  devInput: '在这里输入或粘贴文本 · type or paste text',
  devStrategyTitle: '每类信息的处理方式 · Per-type handling',
  devNames: '已知姓名（逗号分隔）· known names',
  devLang: '语言 · Languages',
  devSeed: '种子 · seed',
  randomize: '🎲 随机 · Randomize',
  devRun: '脱敏 · Redact',
  keyJson: '密钥 · Key (JSON)',
  copy: '复制 · Copy',
  redacted: '脱敏后 · Redacted',
  restored: '还原 · Restored',
  streamTitle: '流式处理 · Streaming',
  streamRun: '开始流式 · Stream it',

  // Guarded restore panel — see demo/js/guarded.js (initGuarded). No live LLM
  // is wired up in this demo: the panel drives the guard with a SIMULATED
  // echoed reply (happy path) and lets the visitor edit/clear it to see the
  // fail-closed path, never implying a real model round-trip.
  guardedTitle: '带防护的还原（模拟回复）· Guarded restore (simulated reply)',
  guardedNote:
    '⚠ 这里没有接入真实大模型：下面的"模拟回复"演示两条路径——正常回显后完整还原，或验证令牌缺失/被篡改后安全拒绝还原 · No live LLM here — the "simulated reply" below demonstrates both paths: a normal echo restores everything, a missing/tampered verification token safely refuses the restore.',
  guardedBuild: '脱敏并生成验证提示 · Redact & build the verification prompt',
  guardedLblRedacted: 'AI 看到的（脱敏后）· What the AI sees (redacted)',
  guardedLblPrompt: '发给大模型的验证提示（可复制）· Verification prompt to send your LLM (copyable)',
  guardedLblReply:
    '模拟的大模型回复 — 编辑或清空来试试安全拒绝 · Simulated LLM reply — edit or clear it to try the fail-closed path',
  guardedRun: '带防护地还原 · Guarded restore',
  guardedResultLbl: '还原结果 · Restored result',
  guardedWithheldLbl: '被保留（未还原）的项 · Withheld items',

  // Copy keyed by the guard's stable event-kind vocabulary (identical strings
  // the PyO3 and wasm bindings both emit — see guard_event_kind_str in
  // crates/argus-redact-wasm/src/lib.rs). Structured events carry no prose of
  // their own by design; this is where the demo owns that prose.
  guardKind: {
    guard_no_anchor:
      '没有提供验证锚点，出于安全考虑拒绝还原 · No verification anchor was supplied, so the restore was refused for safety',
    provenance_failed:
      '回复中没有找到验证令牌，无法证明这是同一次对话，还原被拒绝 · The verification token was not found in the reply, so provenance could not be proven and the restore was refused',
    empty_key_with_scope:
      '提供了授权范围但密钥为空，没有可还原的内容 · A scope was supplied but the key was empty, so there was nothing to restore',
    out_of_scope_pseudonym:
      '回复中出现了超出本次授权范围的替身编码，已保留未还原 · The reply contained a pseudonym code outside the scope authorized for this restore, so it was withheld',
    alias_collision:
      '检测到别名冲突，为安全起见保留了该项 · An alias collision was detected, so that item was withheld for safety',
  },

  // Copy keyed by the guard's stable outcome vocabulary (restore_outcome_str).
  guardOutcome: {
    blocked: '❌ 已阻止 — 没有任何原文被还原 · Blocked — nothing was restored',
    partial: '⚠ 部分还原 — 超出授权范围的项被保留 · Partial — out-of-scope items were withheld',
    complete: '✓ 完全还原 · Complete — everything was restored',
  },
};
