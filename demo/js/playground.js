import { T, LANGS } from './strings.js';
import { highlight } from './findings.js';

const STRATEGIES = ['pseudonym', 'realistic', 'mask', 'category', 'remove'];

export function initPlayground(api) {
  const body = document.getElementById('playground-body');
  body.innerHTML = `
    <textarea id="pg-input" rows="4" placeholder="${T.input}"></textarea>
    <div class="controls">
      <input id="pg-names" type="text" placeholder="${T.names}" />
      <label>${T.lang} <select id="pg-lang" multiple size="4"></select></label>
      <label>person <select id="pg-strategy">${STRATEGIES.map((s) => `<option>${s}</option>`).join('')}</select></label>
      <input id="pg-salt" type="text" value="42" />
      <button id="pg-run" type="button">${T.redact}</button>
    </div>
    <div class="three-up">
      <div><h3>${T.redacted}</h3><pre id="pg-redacted"></pre></div>
      <div><h3>${T.keyJson}</h3><pre id="pg-key"></pre><button id="pg-copy" type="button">${T.copy}</button></div>
      <div><h3>${T.restored}</h3><pre id="pg-restored"></pre></div>
    </div>
    <div id="pg-error" class="error"></div>`;

  const $ = (id) => document.getElementById(id);
  const langSel = $('pg-lang');
  for (const c of LANGS) { const o = document.createElement('option'); o.value = c; o.textContent = c; langSel.appendChild(o); }

  $('pg-run').addEventListener('click', () => {
    $('pg-error').textContent = '';
    try {
      const langs = [...langSel.selectedOptions].map((o) => o.value);
      const opts = { mode: 'fast', salt: Number($('pg-salt').value), lang: langs.length ? langs : ['en'] };
      const nm = $('pg-names').value.split(',').map((s) => s.trim()).filter(Boolean);
      if (nm.length) opts.names = nm;
      opts.config = { person: { strategy: $('pg-strategy').value } };
      const out = api.redact($('pg-input').value, opts);
      $('pg-redacted').innerHTML = highlight(out.text, out.key);
      $('pg-key').textContent = JSON.stringify(out.key, null, 2);
      $('pg-restored').textContent = api.restore(out.text, out.key);
    } catch (e) {
      $('pg-error').textContent = '⚠ ' + (e?.message || e);
    }
  });

  $('pg-copy').addEventListener('click', () => navigator.clipboard?.writeText($('pg-key').textContent));
}
