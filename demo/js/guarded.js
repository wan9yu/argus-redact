// Browser-side producer helpers for the guarded restore flow: a nonce
// generator, an echo-prompt injector, and an anchor builder. These build
// the `anchor` object `window.argus.restore_guarded(text, key, anchor)`
// expects, mirroring `src/argus_redact/compose/anchor.py`'s `make_anchor`
// / `prompt_anchor` nonce-echo templates so a browser session can build a
// valid anchor without a server round-trip.

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
