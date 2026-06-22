import { T, LANGS } from './strings.js';
import { highlight } from './findings.js';

const STRATEGIES = ['pseudonym', 'realistic', 'mask', 'category', 'remove', 'keep'];
// `def` mirrors the core's per-type default strategy (typeinfo.rs default_strategy).
// `prefix` mirrors the core's per-type pseudonym prefix (typeinfo.rs DEFAULT_PREFIXES,
// with the type.upper()[:4] fallback). The core's plain `pseudonym` strategy collapses
// every non-org type onto the shared `P` generator; threading the per-type prefix in
// via config (the supported prefix-override path) keeps each code type-meaningful here
// (a phone pseudonym reads PHON-…, not P-…) so the editor demonstrates per-type handling.
const DEV_TYPES = [
  { type: 'person', label: '姓名 · name', def: 'pseudonym', prefix: 'P' },
  { type: 'phone', label: '手机号 · phone', def: 'mask', prefix: 'PHON' },
  { type: 'email', label: '邮箱 · email', def: 'mask', prefix: 'EMAI' },
  { type: 'address', label: '地址 · address', def: 'remove', prefix: 'ADDR' },
  { type: 'id_number', label: '身份证 · ID', def: 'remove', prefix: 'ID' },
  { type: 'ip_address', label: 'IP', def: 'remove', prefix: 'IP' },
  { type: 'credit_card', label: '信用卡 · credit card', def: 'mask', prefix: 'CRED' },
  { type: 'bank_card', label: '银行卡 · bank card', def: 'mask', prefix: 'BANK' },
  { type: 'ssn', label: 'SSN', def: 'remove', prefix: 'SSN' },
];

function randomSeed() { const a = new Uint32Array(1); crypto.getRandomValues(a); return a[0]; }

export function initDeveloper(api) {
  const body = document.getElementById('dev-body');
  const typeRows = DEV_TYPES.map((t) => `
    <label class="dev-row">${t.label}
      <select id="dev-strategy-${t.type}">${STRATEGIES.map((s) => `<option${s === t.def ? ' selected' : ''}>${s}</option>`).join('')}</select>
    </label>`).join('');
  const langOpts = LANGS.map((c) => `<option value="${c}">${c}</option>`).join('');
  body.innerHTML = `
    <textarea id="dev-input" rows="4" placeholder="${T.devInput}"></textarea>
    <div class="dev-row"><input id="dev-names" type="text" placeholder="${T.devNames}" /></div>
    <fieldset><legend>${T.devStrategyTitle}</legend>${typeRows}</fieldset>
    <div class="dev-row">
      <label>${T.devLang} <select id="dev-lang" multiple size="3">${langOpts}</select></label>
      <label>${T.devSeed} <input id="dev-salt" type="text" value="42" /></label>
      <button id="dev-rand" type="button">${T.randomize}</button>
      <button id="dev-run" type="button">${T.devRun}</button>
    </div>
    <div class="two-up">
      <div><h3>${T.redacted}</h3><pre id="dev-redacted"></pre></div>
      <div><h3>${T.keyJson}</h3><pre id="dev-key"></pre><button id="dev-copy" type="button">${T.copy}</button></div>
    </div>
    <div><h3>${T.restored}</h3><pre id="dev-restored"></pre></div>
    <div id="dev-error" class="error"></div>
    <h3>${T.streamTitle}</h3>`;

  const $ = (id) => document.getElementById(id);
  $('dev-rand').addEventListener('click', () => { $('dev-salt').value = String(randomSeed()); });

  $('dev-run').addEventListener('click', () => {
    $('dev-error').textContent = '';
    try {
      const langs = [...$('dev-lang').selectedOptions].map((o) => o.value);
      const config = {};
      for (const t of DEV_TYPES) config[t.type] = { strategy: $(`dev-strategy-${t.type}`).value, prefix: t.prefix };
      const opts = { mode: 'fast', salt: Number($('dev-salt').value), lang: langs.length ? langs : ['zh', 'en'], config };
      const nm = $('dev-names').value.split(',').map((s) => s.trim()).filter(Boolean);
      if (nm.length) opts.names = nm;
      const out = api.redact($('dev-input').value, opts);
      $('dev-redacted').innerHTML = highlight(out.text, out.key);
      $('dev-key').textContent = JSON.stringify(out.key, null, 2);
      $('dev-restored').textContent = api.restore(out.text, out.key);
    } catch (e) {
      $('dev-error').textContent = '⚠ ' + (e?.message || e);
    }
  });

  $('dev-copy').addEventListener('click', () => navigator.clipboard?.writeText($('dev-key').textContent));
}
