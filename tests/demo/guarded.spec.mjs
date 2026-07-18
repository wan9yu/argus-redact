import { test, expect } from '@playwright/test';
import { T } from '../../demo/js/strings.js';

const NONCE_ECHO_EN = 'End your reply with this exact verification token on its own line: ';
const NONCE_ECHO_ZH = '请在回复末尾以独立的一行输出这个验证令牌：';

// The guard's stable event-kind vocabulary (crates/argus-redact-wasm/src/lib.rs
// guard_event_kind_str) and outcome vocabulary (restore_outcome_str) — the demo
// panel owes every one of these a non-blank zh/en copy entry.
const GUARD_KINDS = [
  'guard_no_anchor',
  'provenance_failed',
  'empty_key_with_scope',
  'out_of_scope_pseudonym',
  'alias_collision',
];
const GUARD_OUTCOMES = ['blocked', 'partial', 'complete'];

async function ready(page) {
  await page.goto('/index.html');
  await page.waitForFunction(() => window.argusReady !== undefined);
  await page.evaluate(() => window.argusReady);
}

test('makeNonce produces a 32-hex-char nonce (16 bytes, parity with Python secrets.token_hex(16))', async ({ page }) => {
  await ready(page);
  const nonce = await page.evaluate(() => window.argus.makeNonce());
  expect(nonce.length).toBe(32);
  expect(nonce).toMatch(/^[0-9a-f]{32}$/);
});

test('makeNonce is unpredictable across calls', async ({ page }) => {
  await ready(page);
  const [a, b] = await page.evaluate(() => [window.argus.makeNonce(), window.argus.makeNonce()]);
  expect(a).not.toBe(b);
});

test('promptAnchor (en) ends with the nonce on its own trailing content and carries the exact echo instruction', async ({ page }) => {
  await ready(page);
  const nonce = '0123456789abcdef0123456789abcdef';
  const out = await page.evaluate((n) => window.argus.promptAnchor(n, 'en'), nonce);
  expect(out.endsWith(nonce)).toBe(true);
  expect(out).toContain(NONCE_ECHO_EN);
});

test('promptAnchor (zh) ends with the nonce and carries the exact echo instruction', async ({ page }) => {
  await ready(page);
  const nonce = '0123456789abcdef0123456789abcdef';
  const out = await page.evaluate((n) => window.argus.promptAnchor(n, 'zh'), nonce);
  expect(out.endsWith(nonce)).toBe(true);
  expect(out).toContain(NONCE_ECHO_ZH);
});

test('promptAnchor falls back to en for an unknown lang, mirroring the Python default', async ({ page }) => {
  await ready(page);
  const nonce = '0123456789abcdef0123456789abcdef';
  const out = await page.evaluate((n) => window.argus.promptAnchor(n, 'fr'), nonce);
  expect(out).toContain(NONCE_ECHO_EN);
});

test('buildAnchor derives scope from the key object keys and a fresh nonce', async ({ page }) => {
  await ready(page);
  const anchor = await page.evaluate(() => window.argus.buildAnchor({ 'P-1': 'Alice', 'P-2': 'Bob' }));
  expect(anchor.nonce.length).toBe(32);
  expect([...anchor.scope].sort()).toEqual(['P-1', 'P-2']);
});

test('restore_guarded is wired into window.argus', async ({ page }) => {
  await ready(page);
  expect(await page.evaluate(() => typeof window.argus.restore_guarded)).toBe('function');
});

test('full guarded roundtrip: buildAnchor + restore_guarded recovers the original via an unmodified reply', async ({ page }) => {
  await ready(page);
  const result = await page.evaluate(() => {
    const out = window.argus.redact('Contact Alice Johnson at the office.', {
      salt: 42, lang: 'en', names: ['Alice Johnson'], mode: 'fast',
    });
    const anchor = window.argus.buildAnchor(out.key);
    // Simulates a model reply that echoes the redacted text plus the nonce,
    // exactly as promptAnchor's instruction asks it to. Passed to
    // restore_guarded UNMODIFIED (no .trim() anywhere on this path).
    const reply = out.text + '\n' + anchor.nonce;
    const restored = window.argus.restore_guarded(reply, out.key, anchor);
    return { restored: restored.restored, outcome: restored.outcome };
  });
  expect(result.outcome).toBe('complete');
  expect(result.restored).toBe('Contact Alice Johnson at the office.');
});

// ── panel: every guard kind + outcome has non-blank zh/en copy ──────────────

test('every guard event-kind key has non-blank zh and en copy', () => {
  for (const kind of GUARD_KINDS) {
    const s = T.guardKind?.[kind];
    expect(s, `T.guardKind.${kind} must exist`).toBeTruthy();
    const [zh, en] = s.split(' · ');
    expect(zh?.trim().length, `zh half of guardKind.${kind}`).toBeGreaterThan(0);
    expect(en?.trim().length, `en half of guardKind.${kind}`).toBeGreaterThan(0);
  }
});

test('every guard outcome key has non-blank zh and en copy', () => {
  for (const outcome of GUARD_OUTCOMES) {
    const s = T.guardOutcome?.[outcome];
    expect(s, `T.guardOutcome.${outcome} must exist`).toBeTruthy();
    const [zh, en] = s.split(' · ');
    expect(zh?.trim().length, `zh half of guardOutcome.${outcome}`).toBeGreaterThan(0);
    expect(en?.trim().length, `en half of guardOutcome.${outcome}`).toBeGreaterThan(0);
  }
});

// ── panel: happy path (simulated echoed reply) ───────────────────────────────

test('guarded panel: happy path with the prefilled simulated reply restores exactly and reports complete', async ({ page }) => {
  await ready(page);
  const original = await page.inputValue('#guarded-input');
  await page.click('#guarded-build');
  // The reply textarea is prefilled with a SIMULATED echo (redacted text + the
  // prompt's own nonce line) — no live LLM involved. Run the guarded restore
  // over that prefill unmodified.
  await page.click('#guarded-run');
  await expect(page.locator('#guarded-outcome')).toHaveAttribute('data-outcome', 'complete');
  await expect(page.locator('#guarded-result')).toHaveText(original);
});

// ── panel: fail-closed when the reply never echoes the nonce back ───────────

test('guarded panel: a reply missing the verification token is blocked and the text stays redacted', async ({ page }) => {
  await ready(page);
  await page.click('#guarded-build');
  const redactedText = await page.locator('#guarded-redacted').innerText();
  // Tamper the simulated reply: drop the nonce line the happy path relies on,
  // keep the redacted text — simulates a reply that never echoed the token.
  await page.fill('#guarded-reply', redactedText);
  await page.click('#guarded-run');
  await expect(page.locator('#guarded-outcome')).toHaveAttribute('data-outcome', 'blocked');
  await expect(page.locator('#guarded-result')).toHaveText(redactedText);
  await expect(page.locator('#guarded-withheld')).not.toBeEmpty();
});

// ── panel: an empty reply is also blocked (fail-closed, not a crash) ────────

test('guarded panel: clearing the reply entirely is blocked, not a crash', async ({ page }) => {
  await ready(page);
  await page.click('#guarded-build');
  await page.fill('#guarded-reply', '');
  await page.click('#guarded-run');
  await expect(page.locator('#guarded-outcome')).toHaveAttribute('data-outcome', 'blocked');
  await expect(page.locator('#guarded-error')).toBeEmpty();
});
