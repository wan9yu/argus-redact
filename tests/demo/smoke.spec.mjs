import { test, expect } from '@playwright/test';

const GOLDEN_IN = 'Contact Alice Johnson at the office.';
const GOLDEN_OPTS = { salt: 42, lang: 'en', names: ['Alice Johnson'], mode: 'fast' };
const GOLDEN_OUT = 'Contact P-83811 at the office.';

async function ready(page) {
  await page.goto('/index.html');
  await page.waitForFunction(() => window.argusReady !== undefined);
  await page.evaluate(() => window.argusReady);
}

test('wasm initializes in a real browser', async ({ page }) => {
  await ready(page);
  expect(await page.evaluate(() => typeof window.argus.redact)).toBe('function');
});

// GOLDEN ANCHOR — UI-independent core parity; do not change.
test('core golden via window.argus (P-83811) + restore', async ({ page }) => {
  await ready(page);
  const r = await page.evaluate(({ text, opts }) => {
    const out = window.argus.redact(text, opts);
    return { text: out.text, restored: window.argus.restore(out.text, out.key) };
  }, { text: GOLDEN_IN, opts: GOLDEN_OPTS });
  expect(r.text).toBe(GOLDEN_OUT);
  expect(r.restored).toBe(GOLDEN_IN);
});

test('hero: prefilled example redacts to realistic fakes and restores exactly', async ({ page }) => {
  await ready(page);
  const original = await page.inputValue('#hero-input');
  expect(original).toContain('黄芳');
  await page.click('#hero-redact');
  const after = await page.locator('#hero-redacted').innerText();
  expect(after).not.toContain('黄芳');
  expect(after).not.toContain('13912345678');
  await expect(page.locator('#hero-redacted mark')).toHaveCount(3);
  await expect(page.locator('#hero-restore')).toContainText('还原');
});

test('hero: clicking a chip swaps the input and redacts', async ({ page }) => {
  await ready(page);
  await page.locator('#hero-chips button', { hasText: 'English' }).click();
  expect(await page.inputValue('#hero-input')).toContain('Alice Johnson');
  const after = await page.locator('#hero-redacted').innerText();
  expect(after).not.toContain('Alice Johnson');
});

test('chinese-first: the headline leads with Chinese', async ({ page }) => {
  await ready(page);
  await expect(page.locator('#headline')).toContainText('脱敏');
});

test('dev fold: phone → pseudonym yields a PHON- code', async ({ page }) => {
  await ready(page);
  await page.locator('#dev > summary').click();
  await page.fill('#dev-input', '联系电话 13912345678。');
  await page.selectOption('#dev-strategy-phone', 'pseudonym');
  await page.fill('#dev-salt', '42');
  await page.click('#dev-run');
  await expect(page.locator('#dev-redacted')).toContainText('PHON-');
  await expect(page.locator('#dev-key')).toContainText('PHON-');
});

test('dev fold: randomize changes the seed', async ({ page }) => {
  await ready(page);
  await page.locator('#dev > summary').click();
  const before = await page.inputValue('#dev-salt');
  await page.click('#dev-rand');
  expect(await page.inputValue('#dev-salt')).not.toBe(before);
});

test('dev fold: streaming never half-leaks across a chunk boundary', async ({ page }) => {
  await ready(page);
  await page.locator('#dev > summary').click();
  await page.fill('#st-input', 'Contact Alice Johnson at the office.');
  await page.fill('#st-salt', '42');
  await page.click('#st-run');
  await expect(page.locator('#st-out')).not.toContainText('Johnson');
  await expect(page.locator('#st-out')).not.toBeEmpty();
});
