// Best-effort: derived from the redaction result only (the wasm has no report API).
// PREFIX_TYPE is populated from crates/argus-redact-core/src/typeinfo.rs default
// prefixes (DEFAULT_PREFIXES): person -> "P", ip_address -> "IP", organization -> "O".
// Tokens are formed as `{prefix}-{code}`, so the keys here carry the trailing "-".
// Unmapped prefixes fall back to their lowercased prefix label; fakes with no
// `X-` prefix (mask / realistic) count toward the total but get no chip.
const PREFIX_TYPE = { 'P-': 'person', 'IP-': 'ip', 'O-': 'organization' };

export function escapeHtml(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

export function summarizeFindings(result) {
  const fakes = Object.keys(result?.key || {});
  const types = {};
  for (const f of fakes) {
    const m = f.match(/^([A-Z]+-)/);
    const t = m ? (PREFIX_TYPE[m[1]] || m[1].slice(0, -1).toLowerCase()) : 'other';
    types[t] = (types[t] || 0) + 1;
  }
  return { count: fakes.length, types };
}

// Single left-to-right pass over the raw redacted text: each fake token is wrapped
// exactly once and the surrounding text is escaped. Alternation is longest-first so a
// token that is a prefix of another (e.g. "P-12" vs "P-1234") never produces nested
// <mark> tags, and matching never re-scans already-inserted markup.
export function highlight(redactedText, key) {
  const fakes = Object.keys(key || {}).sort((a, b) => b.length - a.length); // longest-first
  if (fakes.length === 0) return escapeHtml(redactedText);
  const alt = fakes.map((f) => f.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
  const re = new RegExp(alt, 'g');
  let out = '';
  let last = 0;
  let m;
  while ((m = re.exec(redactedText)) !== null) {
    out += escapeHtml(redactedText.slice(last, m.index));
    const tok = m[0];
    out += `<mark title="${escapeHtml(key[tok] ?? '')}">${escapeHtml(tok)}</mark>`;
    last = m.index + tok.length;
    if (m.index === re.lastIndex) re.lastIndex++; // guard against a zero-length match
  }
  out += escapeHtml(redactedText.slice(last));
  return out;
}

export function renderFindings(el, result, label) {
  const { count, types } = summarizeFindings(result);
  const chips = Object.entries(types)
    .map(([t, n]) => `<span class="chip">${escapeHtml(t)}: ${n}</span>`)
    .join('');
  el.innerHTML = `<strong>${count}</strong> ${escapeHtml(label)} ${chips}`;
}
