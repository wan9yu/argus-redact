import init, { redact, restore, StreamingRedactor } from '../pkg-web/argus_redact_wasm.js';
import { T, LANGS } from './strings.js';
import { initHero } from './hero.js';
import { initPlayground } from './playground.js';
import { initStreaming } from './streaming.js';
import { renderLlmProof } from './llm_proof.js';

function applyStaticStrings() {
  document.getElementById('tagline').textContent = T.tagline;
  document.getElementById('status').textContent = T.loading;
  document.getElementById('hero-input').placeholder = T.input;
  document.getElementById('hero-names').placeholder = T.names;
  const heroSalt = document.getElementById('hero-salt');
  heroSalt.title = T.salt;
  heroSalt.setAttribute('aria-label', T.salt);
  document.getElementById('hero-salt-rand').textContent = T.randomize;
  document.getElementById('hero-redact').textContent = T.redact;
  document.getElementById('lbl-original').textContent = T.original;
  document.getElementById('lbl-redacted').textContent = T.redacted;
  document.getElementById('lbl-restored').textContent = T.restored;
  document.querySelector('#playground > summary').textContent = T.playground;
  document.querySelector('#streaming > summary').textContent = T.streaming;
  const sel = document.getElementById('hero-lang');
  for (const code of LANGS) {
    const o = document.createElement('option'); o.value = code; o.textContent = code; sel.appendChild(o);
  }
  sel.value = 'en';
}

const api = { redact, restore, StreamingRedactor };

window.argusReady = (async () => {
  applyStaticStrings();
  await init();
  window.argus = api;
  const status = document.getElementById('status');
  status.textContent = T.ready; status.className = 'status-ready';
  document.getElementById('hero-redact').disabled = false;
  initHero(api);
  initPlayground(api);
  initStreaming(api);
  await renderLlmProof();
})();

window.argusReady.catch((err) => {
  const status = document.getElementById('status');
  status.textContent = T.failed + (err?.message || err); status.className = 'status-failed';
});
