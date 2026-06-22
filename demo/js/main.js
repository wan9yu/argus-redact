import init, { redact, restore, StreamingRedactor } from '../pkg-web/argus_redact_wasm.js';
import { T } from './strings.js';
import { initHero } from './hero.js';
import { initDeveloper } from './developer.js';
import { initStreaming } from './streaming.js';
import { renderLlmProof } from './llm_proof.js';

function applyStatic() {
  document.getElementById('headline').textContent = T.headline;
  document.getElementById('headline-en').textContent = T.headlineEn;
  document.getElementById('trust').textContent = T.trust;
  document.getElementById('status').textContent = T.loading;
  document.getElementById('hero-redact').textContent = T.redact;
  document.getElementById('hero-try').textContent = T.tryLabel + ' ';
  document.getElementById('lbl-your').textContent = T.yourText;
  document.getElementById('lbl-ai').textContent = T.aiSees;
  document.getElementById('how-title').textContent = T.howTitle;
  const ol = document.getElementById('how-steps');
  T.steps.forEach((s) => { const li = document.createElement('li'); li.textContent = s; ol.appendChild(li); });
  const badges = document.getElementById('badges');
  T.badges.forEach((b) => { const sp = document.createElement('span'); sp.textContent = b; badges.appendChild(sp); });
  document.getElementById('how-limit').textContent = T.limitNote;
  document.getElementById('dev-summary').textContent = T.devFold;
}

const api = { redact, restore, StreamingRedactor };

window.argusReady = (async () => {
  applyStatic();
  await init();
  window.argus = api;
  const st = document.getElementById('status');
  st.textContent = T.ready; st.className = 'status-ready';
  document.getElementById('hero-redact').disabled = false;
  initHero(api);
  initDeveloper(api);
  initStreaming(api);
  await renderLlmProof();
})();

window.argusReady.catch((err) => {
  const st = document.getElementById('status');
  st.textContent = T.failed + (err?.message || err); st.className = 'status-failed';
});
