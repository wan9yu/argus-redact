import init, { redact, restore, restore_guarded, StreamingRedactor } from '../pkg-web/argus_redact_wasm.js';
import { T } from './strings.js';
import { initHero } from './hero.js';
import { initDeveloper } from './developer.js';
import { initStreaming } from './streaming.js';
import { renderLlmProof } from './llm_proof.js';
import { makeNonce, promptAnchor, buildAnchor } from './guarded.js';

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

// makeNonce/promptAnchor/buildAnchor are the JS producer side of the
// guarded restore flow: they build the anchor restore_guarded expects.
// Exposed here (not just used internally) so the demo panel that drives
// the guarded flow can call them the same way it calls redact/restore.
const api = { redact, restore, restore_guarded, StreamingRedactor, makeNonce, promptAnchor, buildAnchor };

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
