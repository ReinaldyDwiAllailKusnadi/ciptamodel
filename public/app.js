'use strict';
// Progressive enhancement: nav toggles, copy buttons, confirm dialogs, playground.
document.addEventListener('click', async (e) => {
  const t = e.target.closest('[data-action]');
  if (!t) return;
  const action = t.dataset.action;
  if (action === 'menu') document.querySelector('.sidebar')?.classList.toggle('open');
  if (action === 'pubmenu') {
    const nav = document.getElementById('pubnav');
    const open = nav?.classList.toggle('open');
    t.setAttribute('aria-expanded', open ? 'true' : 'false');
  }
  if (action === 'docsnav') {
    const n = document.getElementById('docsnav');
    if (!n) return;
    const hidden = n.style.display === 'none';
    n.style.display = hidden ? '' : 'none';
    t.setAttribute('aria-expanded', hidden ? 'true' : 'false');
  }
  if (action === 'copy') {
    const text = t.dataset.copy || '';
    try { await navigator.clipboard.writeText(text); t.textContent = 'Copied'; }
    catch { t.textContent = 'Copy failed'; }
    setTimeout(() => { t.textContent = t.dataset.label || 'Copy'; }, 1500);
  }
});

// Confirm dialogs (delegated — keeps CSP script-src 'self' intact, no inline handlers).
document.addEventListener('submit', (e) => {
  const f = e.target.closest('form[data-confirm]');
  if (f && !window.confirm(f.dataset.confirm)) e.preventDefault();
});

// Add copy buttons to docs/SDK/example code blocks (only when a copy source exists).
for (const pre of document.querySelectorAll('pre')) {
  if (pre.querySelector('.copybtn') || pre.closest('.term')) continue;
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'copybtn';
  btn.textContent = 'Copy';
  btn.dataset.action = 'copy';
  btn.dataset.label = 'Copy';
  btn.dataset.copy = pre.textContent;
  btn.setAttribute('aria-label', 'Copy code block');
  pre.appendChild(btn);
}

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
      ai.textContent = (data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content) || '(empty response)';
      const u = data.usage || null;
      meta(((performance.now() - t0) | 0), u ? { input_tokens: u.prompt_tokens, output_tokens: u.completion_tokens } : null);
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
            const evt = JSON.parse(payload);
            if (evt.error) { ai.textContent = 'Error: ' + (evt.error.message || evt.error.code || 'provider error'); return; }
            const d = (evt.choices && evt.choices[0] && evt.choices[0].delta && evt.choices[0].delta.content) || '';
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
  el.textContent = usage && usage.input_tokens !== undefined
    ? `latency ${ms} ms · ${usage.input_tokens} in / ${usage.output_tokens} out`
    : `latency ${ms} ms (streamed)`;
}
window.playgroundSend = playgroundSend;
document.getElementById('pgform')?.addEventListener('submit', playgroundSend);
