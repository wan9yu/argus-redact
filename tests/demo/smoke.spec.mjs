import { test, expect } from '@playwright/test';

const GOLDEN_IN = 'Contact Alice Johnson at the office.';
const GOLDEN_OPTS = { salt: 42, lang: 'en', names: ['Alice Johnson'], mode: 'fast' };
const GOLDEN_OUT = 'Contact P-83811 at the office.';

test('wasm initializes in a real browser', async ({ page }) => {
  await page.goto('/index.html');
  await page.waitForFunction(() => window.argusReady !== undefined);
  await page.evaluate(() => window.argusReady);
  expect(await page.evaluate(() => typeof window.argus.redact)).toBe('function');
});

test('one-shot redact matches the core golden (P-83811)', async ({ page }) => {
  await page.goto('/index.html');
  await page.evaluate(() => window.argusReady);
  const out = await page.evaluate(
    ({ text, opts }) => window.argus.redact(text, opts),
    { text: GOLDEN_IN, opts: GOLDEN_OPTS }
  );
  expect(out.text).toBe(GOLDEN_OUT);
  expect(typeof out.key).toBe('object');
});

test('restore round-trips', async ({ page }) => {
  await page.goto('/index.html');
  await page.evaluate(() => window.argusReady);
  const restored = await page.evaluate(({ text, opts }) => {
    const out = window.argus.redact(text, opts);
    return window.argus.restore(out.text, out.key);
  }, { text: GOLDEN_IN, opts: GOLDEN_OPTS });
  expect(restored).toBe(GOLDEN_IN);
});

test('streaming never half-leaks an entity across a chunk boundary', async ({ page }) => {
  await page.goto('/index.html');
  await page.evaluate(() => window.argusReady);
  const result = await page.evaluate(() => {
    const sr = new window.argus.StreamingRedactor({ salt: 42, lang: 'en', names: ['Alice Johnson'], mode: 'fast' });
    const emits = [];
    emits.push(sr.feed('Contact Alice ').downstreamText);
    emits.push(sr.feed('Johnson at the office.').downstreamText);
    emits.push(sr.flush().downstreamText);
    return { downstream: emits.join(''), emits };
  });
  expect(result.downstream).toBe('Contact P-83811 at the office.');
  for (const e of result.emits) expect(e).not.toContain('Johnson');
});

test('hero UI is wired (fill → redact → see code)', async ({ page }) => {
  await page.goto('/index.html');
  await page.evaluate(() => window.argusReady);
  await page.fill('#hero-input', GOLDEN_IN);
  await page.fill('#hero-names', 'Alice Johnson');
  await page.selectOption('#hero-lang', 'en');
  await page.fill('#hero-salt', '42');
  await page.click('#hero-redact');
  await expect(page.locator('#hero-redacted')).toContainText('P-83811');
  await expect(page.locator('#hero-original')).toContainText('Alice Johnson');
});
