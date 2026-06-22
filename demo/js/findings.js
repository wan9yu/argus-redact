// Best-effort: derived from the redaction result only (the wasm has no report API).
// PREFIX_TYPE is populated from crates/argus-redact-core/src/typeinfo.rs default
// prefixes (DEFAULT_PREFIXES): person -> "P", ip_address -> "IP", organization -> "O".
// Tokens are formed as `{prefix}-{code}`, so the keys here carry the trailing "-".
// Unmapped prefixes fall back to their lowercased prefix label; fakes with no
// `X-` prefix (mask / realistic) count toward the total but get no chip.
const PREFIX_TYPE = { 'P-': 'person', 'IP-': 'ip', 'O-': 'organization' };

function escapeHtml(s) {
  return s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
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

export function highlight(redactedText, key) {
  const fakes = Object.keys(key || {}).sort((a, b) => b.length - a.length); // longest-first
  let html = escapeHtml(redactedText);
  for (const f of fakes) {
    const safe = escapeHtml(f).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    html = html.replace(new RegExp(safe, 'g'), `<mark title="${escapeHtml(key[f])}">${escapeHtml(f)}</mark>`);
  }
  return html;
}

export function renderFindings(el, result, label) {
  const { count, types } = summarizeFindings(result);
  const chips = Object.entries(types).map(([t, n]) => `<span class="chip">${t}: ${n}</span>`).join('');
  el.innerHTML = `<strong>${count}</strong> ${label} ${chips}`;
}
