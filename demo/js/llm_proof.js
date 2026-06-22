import { T } from './strings.js';

export async function renderLlmProof() {
  const sec = document.getElementById('llm-proof');
  let data;
  try {
    data = await (await fetch('./prvl_cache.json')).json();
  } catch {
    sec.innerHTML = `<h2>${T.llmProof}</h2><p class="error">prvl_cache.json unavailable</p>`;
    return;
  }
  const rows = (data.rows || []).map((r) => `
    <tr><td>${r.model}</td>
        <td><code>${r.downstream_text}</code></td>
        <td>${r.llm_reply}</td>
        <td>${r.leaked} / ${r.total_pii}</td>
        <td>${r.utility}</td></tr>`).join('');
  sec.innerHTML = `
    <h2>${T.llmProof}</h2>
    <table>
      <thead><tr><th>LLM</th><th>${T.redacted}</th><th>reply · 回复</th><th>leaked · 泄漏</th><th>utility · 效用</th></tr></thead>
      <tbody>${rows}</tbody>
      <caption>${T.llmProvenance}${data.source_run} · case ${data.case_id} · profile ${data.profile}. Scoped to this cached reference run — not a guarantee against adversarial input.</caption>
    </table>`;
}
