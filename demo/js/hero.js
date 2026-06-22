import { T } from './strings.js';
import { highlight, renderFindings } from './findings.js';

function randomSalt() {
  const a = new Uint32Array(1); crypto.getRandomValues(a); return a[0];
}

export function initHero(api) {
  const $ = (id) => document.getElementById(id);
  const input = $('hero-input'), names = $('hero-names'), lang = $('hero-lang'),
        salt = $('hero-salt'), err = $('hero-error');

  $('hero-salt-rand').addEventListener('click', () => { salt.value = String(randomSalt()); });

  $('hero-redact').addEventListener('click', () => {
    err.textContent = '';
    try {
      const opts = { mode: 'fast', lang: lang.value, salt: Number(salt.value) };
      const nm = names.value.split(',').map((s) => s.trim()).filter(Boolean);
      if (nm.length) opts.names = nm;
      const out = api.redact(input.value, opts);
      $('hero-original').textContent = input.value;
      $('hero-redacted').innerHTML = highlight(out.text, out.key);
      $('hero-restored').textContent = api.restore(out.text, out.key);
      renderFindings($('hero-findings'), out, T.items);
    } catch (e) {
      err.textContent = '⚠ ' + (e?.message || e);
    }
  });
}
