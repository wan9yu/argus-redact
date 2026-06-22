import { T } from './strings.js';
import { PREFILL, CHIPS } from './examples.js';
import { highlight } from './findings.js';

// Realistic fakes for the common headline types (the strongest "looks real, but safe"
// moment). Types without a built-in faker fall back to a pseudonym code in the core.
const REALISTIC_CONFIG = {
  person: { strategy: 'realistic' },
  phone: { strategy: 'realistic' },
  address: { strategy: 'realistic' },
  id_number: { strategy: 'realistic' },
  email: { strategy: 'realistic' },
  bank_card: { strategy: 'realistic' },
};
const HERO_SALT = 42;

export function initHero(api) {
  const $ = (id) => document.getElementById(id);
  const input = $('hero-input');
  input.value = PREFILL;

  const chipBox = $('hero-chips');
  for (const c of CHIPS) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'chip-btn';
    b.textContent = c.label;
    b.addEventListener('click', () => { input.value = c.text; run(c.lang); });
    chipBox.appendChild(b);
  }

  function run(lang) {
    $('hero-error').textContent = '';
    try {
      const out = api.redact(input.value, {
        mode: 'fast',
        lang: lang || ['zh', 'en'],   // English chip passes ['en'] so the person faker uses the en pool
        salt: HERO_SALT,
        config: REALISTIC_CONFIG,
      });
      $('hero-original').textContent = input.value;
      $('hero-redacted').innerHTML = highlight(out.text, out.key);
      const restored = api.restore(out.text, out.key);
      const ok = restored === input.value;
      $('hero-restore').textContent = ok ? T.restoredOk : ('⚠ ' + restored);
    } catch (e) {
      $('hero-error').textContent = '⚠ ' + (e?.message || e);
    }
  }

  $('hero-redact').addEventListener('click', () => run());
}
