'use strict';
// Minimal progressive enhancement: sidebar toggle, copy buttons, playground.
document.addEventListener('click', async (e) => {
  const t = e.target.closest('[data-action]');
  if (!t) return;
  const action = t.dataset.action;
  if (action === 'menu') document.querySelector('.sidebar')?.classList.toggle('open');
  if (action === 'copy') {
    const text = t.dataset.copy || '';
    try { await navigator.clipboard.writeText(text); t.textContent = 'Copied'; }
    catch { t.textContent = 'Copy failed'; }
    setTimeout(() => { t.textContent = t.dataset.label || 'Copy'; }, 1500);
  }
});

async function playgroundSend(ev) {
  ev.preventDefault();
  const f = ev.target;
  const log = document.getElementById('chatlog');
  const btn = f.querySelector('button[type=submit]');
  const prompt = f.prompt.value.trim();
  if (!prompt) return;
  const model = f.model.value;
  const system = (f.system && f.system.value || '').trim();
  const temperature = f.temperature ? parseFloat(f.temperature.value) : 0.7;
  const maxTokens = f.max_tokens ? parseInt(f.max_tokens.value, 10) : 512;
  const stream = f.stream.checked;
  const messages = [];
  if (system) messages.push({ role: 'system', content: system });
  messages.push({ role: 'user', content: prompt });
  log.insertAdjacentHTML('beforeend', `<div class="msg user"></div>`);
  log.lastElementChild.textContent = prompt;
  const ai = document.createElement('div');
  ai.className = 'msg ai';
  ai.textContent = '…';
  log.appendChild(ai);
  log.scrollTop = log.scrollHeight;
  f.prompt.value = '';
  btn.disabled = true;
  const t0 = performance.now();
  try {
    const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
    const res = await fetch('/api/playground', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrf },
      body: JSON.stringify({ model, messages, temperature, max_tokens: maxTokens, stream }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      ai.textContent = 'Error ' + res.status + ': ' + (err.error?.message || res.statusText);
      return;
    }
    if (!stream) {
      const data = await res.json();
      ai.textContent = data.content || '(empty response)';
      meta(((performance.now() - t0) | 0), data.usage);
    } else {
      ai.textContent = '';
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = '';
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        const parts = buf.split('\n\n');
        buf = parts.pop();
        for (const p of parts) {
          const line = p.split('\n').find((l) => l.startsWith('data:'));
          if (!line) continue;
          const payload = line.slice(5).trim();
          if (payload === '[DONE]') continue;
          try {
            const d = JSON.parse(payload).choices?.[0]?.delta?.content || '';
            ai.textContent += d;
            log.scrollTop = log.scrollHeight;
          } catch { /* skip */ }
        }
      }
      meta(((performance.now() - t0) | 0), null);
    }
  } catch (err) {
    ai.textContent = 'Request failed: ' + err.message;
  } finally {
    btn.disabled = false;
    log.scrollTop = log.scrollHeight;
  }
}

function meta(ms, usage) {
  const el = document.getElementById('pgmeta');
  if (!el) return;
  el.textContent = usage
    ? `latency ${ms} ms · ${usage.input_tokens} in / ${usage.output_tokens} out`
    : `latency ${ms} ms (streamed)`;
}
window.playgroundSend = playgroundSend;
