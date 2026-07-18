// Browser-side producer helpers for the guarded restore flow: a nonce
// generator, an echo-prompt injector, and an anchor builder. These build
// the `anchor` object `window.argus.restore_guarded(text, key, anchor)`
// expects, mirroring `src/argus_redact/compose/anchor.py`'s `make_anchor`
// / `prompt_anchor` nonce-echo templates so a browser session can build a
// valid anchor without a server round-trip. Also wires the visible panel
// (`initGuarded`) that drives the flow end to end for a demo visitor.

import { T } from './strings.js';
import { escapeHtml, highlight } from './findings.js';

// 16 random bytes -> 32 hex chars. Parity with Python's
// `secrets.token_hex(16)` (`make_anchor`) — pin any test to `=== 32`, not
// `>= 16`; a shorter nonce still clears a naive length check but ships
// half the entropy.
export function makeNonce() {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}

// Mirrors `_NONCE_ECHO_EN` / `_NONCE_ECHO_ZH` in `compose/anchor.py`
// byte-for-byte. The reply a model sends back is checked against this
// nonce verbatim by the core guard, so do not reword this without
// updating the Python constants (and the tests that pin them) in lockstep.
const NONCE_ECHO_EN = '\n\nEnd your reply with this exact verification token on its own line: ';
const NONCE_ECHO_ZH = '\n\n请在回复末尾以独立的一行输出这个验证令牌：';

// Echo-instruction addendum for a system prompt: asks the model to repeat
// `nonce` back on its own line. Unknown `lang` values fall back to English,
// matching `prompt_anchor`'s default.
export function promptAnchor(nonce, lang) {
  const prefix = lang === 'zh' ? NONCE_ECHO_ZH : NONCE_ECHO_EN;
  return prefix + nonce;
}

// The `{ nonce, scope }` anchor shape `restore_guarded` expects: a fresh
// nonce plus the pseudonym codes this exchange is allowed to restore
// (every key returned by `redact`).
export function buildAnchor(key) {
  return { nonce: makeNonce(), scope: Object.keys(key) };
}

// ── panel: drives the guarded restore flow for a demo visitor ───────────────

// A sentence already proven to round-trip exactly through the plain restore
// path (see tests/demo/smoke.spec.mjs's GOLDEN_* constants) and through
// restore_guarded itself (this file's own "full guarded roundtrip" test in
// tests/demo/guarded.spec.mjs) — reused here so the panel's happy path is
// deterministic without inventing a new example.
const GUARDED_PREFILL = 'Contact Alice Johnson at the office.';
const GUARDED_OPTS = { mode: 'fast', lang: 'en', salt: 42, names: ['Alice Johnson'] };

// Wires the guarded-restore panel (`<section id="guarded">` in index.html): a
// visitor types text, redacts it, gets a copyable verification prompt to send
// an LLM, and drives `restore_guarded` over a SIMULATED echoed reply — there
// is no live model in this demo. The reply textarea is editable/clearable so
// a visitor can see the fail-closed path too (a missing or tampered
// verification token blocks the restore rather than silently leaking the
// pseudonym codes back to plaintext, or silently substituting nothing).
export function initGuarded(api) {
  const $ = (id) => document.getElementById(id);

  $('guarded-title').textContent = T.guardedTitle;
  $('guarded-note').textContent = T.guardedNote;
  $('guarded-input').placeholder = T.devInput;
  $('guarded-build').textContent = T.guardedBuild;
  $('guarded-lbl-redacted').textContent = T.guardedLblRedacted;
  $('guarded-lbl-prompt').textContent = T.guardedLblPrompt;
  $('guarded-copy-prompt').textContent = T.copy;
  $('guarded-lbl-reply').textContent = T.guardedLblReply;
  $('guarded-run').textContent = T.guardedRun;
  $('guarded-result-title').textContent = T.guardedResultLbl;

  $('guarded-input').value = GUARDED_PREFILL;

  // Set by a successful build(): the key + anchor the current redacted text
  // was produced with. `restore_guarded` needs both to run.
  let state = null;

  function resetOutput() {
    $('guarded-error').textContent = '';
    $('guarded-outcome').textContent = '';
    $('guarded-outcome').removeAttribute('data-outcome');
    $('guarded-result').textContent = '';
    $('guarded-withheld').textContent = '';
  }

  function build() {
    resetOutput();
    $('guarded-run').disabled = true;
    state = null;
    try {
      const out = api.redact($('guarded-input').value, GUARDED_OPTS);
      const anchor = api.buildAnchor(out.key);
      state = { key: out.key, anchor };
      $('guarded-redacted').innerHTML = highlight(out.text, out.key);
      $('guarded-prompt').textContent = api.promptAnchor(anchor.nonce, 'zh');
      // The SIMULATED echoed reply a cooperative model would send back:
      // the redacted text plus the verification nonce on its own line,
      // exactly as the prompt above asks for. Editable/clearable below to
      // exercise the fail-closed path — no live LLM produced this.
      $('guarded-reply').value = out.text + '\n' + anchor.nonce;
      $('guarded-run').disabled = false;
    } catch (e) {
      $('guarded-error').textContent = '⚠ ' + (e?.message || e);
    }
  }

  function run() {
    $('guarded-error').textContent = '';
    if (!state) return;
    try {
      // VERBATIM — no .trim()/.trimEnd() on the reply. JS trim strips
      // U+001C–U+001F, which the core guard's nonce/provenance check does
      // not; trimming here would silently change what the guard sees versus
      // what the textarea actually holds.
      const reply = $('guarded-reply').value;
      const result = api.restore_guarded(reply, state.key, state.anchor);

      const outcomeEl = $('guarded-outcome');
      outcomeEl.textContent = T.guardOutcome[result.outcome] || result.outcome;
      outcomeEl.dataset.outcome = result.outcome;
      $('guarded-result').textContent = result.restored;

      const withheldEl = $('guarded-withheld');
      const anyTokens = result.events.some((ev) => (ev.tokens || []).length);
      const rows = result.events.map((ev) => {
        const label = T.guardKind[ev.kind] || ev.kind;
        const tokens = ev.tokens || [];
        const tail = tokens.length ? ' — ' + escapeHtml(tokens.join(', ')) : '';
        return `<div>${escapeHtml(label)}${tail}</div>`;
      });
      const heading = anyTokens ? `<strong>${escapeHtml(T.guardedWithheldLbl)}</strong>` : '';
      withheldEl.innerHTML = heading + rows.join('');
    } catch (e) {
      $('guarded-error').textContent = '⚠ ' + (e?.message || e);
    }
  }

  $('guarded-build').addEventListener('click', build);
  $('guarded-run').addEventListener('click', run);
  $('guarded-copy-prompt').addEventListener('click', () => {
    navigator.clipboard?.writeText($('guarded-prompt').textContent);
  });
}
