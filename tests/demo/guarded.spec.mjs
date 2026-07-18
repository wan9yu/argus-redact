import { test, expect } from '@playwright/test';

const NONCE_ECHO_EN = 'End your reply with this exact verification token on its own line: ';
const NONCE_ECHO_ZH = '请在回复末尾以独立的一行输出这个验证令牌：';

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
