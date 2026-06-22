import { test, expect } from '@playwright/test';
import { summarizeFindings, highlight } from '../../demo/js/findings.js';

test('counts key entries and derives best-effort type chips', () => {
  const result = { key: { 'P-83811': 'Alice Johnson', 'IP-94349': '8.8.8.8' }, aliases: {} };
  const s = summarizeFindings(result);
  expect(s.count).toBe(2);
  expect(s.types.person).toBe(1);
  expect(s.types.ip).toBe(1);
});

test('highlight wraps each fake token with its original in a title', () => {
  const html = highlight('Contact P-83811 now.', { 'P-83811': 'Alice Johnson' });
  expect(html).toContain('<mark title="Alice Johnson">P-83811</mark>');
  expect(html).toContain('Contact ');
});

test('highlight handles a token that is a prefix of another without nesting', () => {
  // "P-12" is a substring of "P-1234"; a naive sequential replace would nest <mark>.
  const html = highlight('see P-1234 and P-12 end', { 'P-1234': 'Long', 'P-12': 'Short' });
  expect(html).toBe(
    'see <mark title="Long">P-1234</mark> and <mark title="Short">P-12</mark> end'
  );
  expect(html).not.toContain('<mark title="Short"><mark'); // no nested marks
});

test('highlight escapes surrounding text and original values', () => {
  const html = highlight('a <b> P-1', { 'P-1': '<script>' });
  expect(html).toContain('a &lt;b&gt; ');
  expect(html).toContain('<mark title="&lt;script&gt;">P-1</mark>');
});
