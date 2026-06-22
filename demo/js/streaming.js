import { T } from './strings.js';

export function initStreaming(api) {
  const body = document.getElementById('streaming-body');
  body.innerHTML = `
    <textarea id="st-input" rows="4" placeholder="${T.input}"></textarea>
    <div class="controls">
      <label>${T.salt} <input id="st-salt" type="text" value="42" /></label>
      <button id="st-run" type="button">${T.streamRun}</button>
    </div>
    <pre id="st-out"></pre>
    <div id="st-error" class="error"></div>`;

  const $ = (id) => document.getElementById(id);
  $('st-run').addEventListener('click', () => {
    $('st-error').textContent = ''; $('st-out').textContent = '';
    try {
      const sr = new api.StreamingRedactor({ mode: 'fast', lang: 'en', salt: Number($('st-salt').value) });
      const text = $('st-input').value;
      let acc = '';
      for (let i = 0; i < text.length; i += 12) acc += sr.feed(text.slice(i, i + 12)).downstreamText;
      acc += sr.flush().downstreamText;
      $('st-out').textContent = acc;
    } catch (e) {
      $('st-error').textContent = '⚠ ' + (e?.message || e);
    }
  });
}
