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
