import { T } from './strings.js';
import { escapeHtml } from './findings.js';

export async function renderLlmProof() {
  const sec = document.getElementById('llm-proof');
  let data;
  try {
    data = await (await fetch('./prvl_cache.json')).json();
  } catch {
    sec.innerHTML = `<h2>${T.llmProof}</h2><p class="error">prvl_cache.json unavailable</p>`;
    return;
  }
  // prvl_cache.json ships in the repo (trusted), but escape on the way into the DOM
  // anyway — a redaction demo has no business being an HTML-injection sink.
  const rows = (data.rows || []).map((r) => `
    <tr><td>${escapeHtml(r.model)}</td>
        <td><code>${escapeHtml(r.downstream_text)}</code></td>
        <td>${escapeHtml(r.llm_reply)}</td>
        <td>${escapeHtml(r.leaked)} / ${escapeHtml(r.total_pii)}</td>
        <td>${escapeHtml(r.utility)}</td></tr>`).join('');
  sec.innerHTML = `
    <h2>${T.llmProof}</h2>
    <table>
      <thead><tr><th>LLM</th><th>${T.redacted}</th><th>reply · 回复</th><th>leaked · 泄漏</th><th>utility · 效用</th></tr></thead>
      <tbody>${rows}</tbody>
      <caption>${T.llmProvenance}${escapeHtml(data.source_run)} · case ${escapeHtml(data.case_id)} · profile ${escapeHtml(data.profile)}${T.llmCaptionTail}</caption>
    </table>`;
}
