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
  if (action === 'pgcopy') {
    const last = document.querySelector('#chatlog .msg.ai:last-of-type, #chatlog .msg.err:last-of-type');
    const msg = last && last.textContent.trim() ? last.textContent : '';
    if (!msg) { t.textContent = 'Nothing to copy'; }
    else {
      try { await navigator.clipboard.writeText(msg); t.textContent = 'Copied'; }
      catch { t.textContent = 'Copy failed'; }
    }
    setTimeout(() => { t.textContent = 'Copy response'; }, 1500);
  }
  if (action === 'pgclear') {
    const log = document.getElementById('chatlog');
    if (log) log.innerHTML = '<div class="msg sys">Cleared. Type a new prompt to start a fresh test.</div>';
    const m = document.getElementById('pgmeta');
    if (m) m.textContent = '';
    document.getElementById('pgprompt')?.focus();
    return;
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
  const promptEl = f.prompt;
  const prompt = promptEl.value.trim();
  // Inline validation state (no alert): mark field + explain.
  document.getElementById('pg-err')?.remove();
  promptEl.removeAttribute('aria-invalid');
  if (!prompt) {
    promptEl.setAttribute('aria-invalid', 'true');
    promptEl.insertAdjacentHTML('afterend', '<p class="field-err" id="pg-err" role="alert">Type a prompt first — the gateway rejects empty message lists with 400.</p>');
    promptEl.focus();
    return;
  }
  const model = f.model.value;
  if (!model) {
    f.model.insertAdjacentHTML('afterend', '<p class="field-err" id="pg-err" role="alert">No model is enabled. Ask the operator to enable one in the registry.</p>');
    return;
  }
  const system = (f.system && f.system.value || '').trim();
  const temperature = f.temperature ? parseFloat(f.temperature.value) : 0.7;
  const maxTokens = f.max_tokens ? parseInt(f.max_tokens.value, 10) : 512;
  const stream = f.stream.checked;
  const messages = [];
  if (system) messages.push({ role: 'system', content: system });
  messages.push({ role: 'user', content: prompt });
  // Before-request: echo effective config so state is explicit.
  log.insertAdjacentHTML('beforeend', `<div class="msg user"></div>`);
  log.lastElementChild.textContent = prompt;
  const cfg = document.createElement('div');
  cfg.className = 'msg sys';
  cfg.textContent = `POST /v1/chat/completions · model=${model} · temperature=${temperature} · max_tokens=${maxTokens} · stream=${stream}`;
  log.appendChild(cfg);
  const ai = document.createElement('div');
  ai.className = 'msg ai';
  ai.setAttribute('role', 'status');
  ai.innerHTML = '<span class="spin" aria-hidden="true"></span> Sending…';
  log.appendChild(ai);
  log.scrollTop = log.scrollHeight;
  f.prompt.value = '';
  btn.disabled = true;
  btn.setAttribute('aria-busy', 'true');
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
      ai.className = 'msg err';
      ai.textContent = pgHelp(res.status, err.error);
      meta(((performance.now() - t0) | 0), null, model);
      return;
    }
    if (!stream) {
      const data = await res.json();
      ai.textContent = (data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content) || '(empty response — the provider returned no text)';
      const u = data.usage || null;
      meta(((performance.now() - t0) | 0), u ? { input_tokens: u.prompt_tokens, output_tokens: u.completion_tokens } : null, model);
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
            if (evt.error) { ai.className = 'msg err'; ai.textContent = pgHelp(200, evt.error); meta(((performance.now() - t0) | 0), null, model); return; }
            const d = (evt.choices && evt.choices[0] && evt.choices[0].delta && evt.choices[0].delta.content) || '';
            ai.textContent += d;
            log.scrollTop = log.scrollHeight;
          } catch { /* skip */ }
        }
      }
      if (!ai.textContent) ai.textContent = '(empty response — the provider returned no text)';
      meta(((performance.now() - t0) | 0), null, model);
    }
  } catch (err) {
    ai.className = 'msg err';
    ai.textContent = 'Request failed before reaching the gateway: ' + err.message + ' — check your connection and retry.';
  } finally {
    btn.disabled = false;
    btn.removeAttribute('aria-busy');
    log.scrollTop = log.scrollHeight;
  }
}

// Map gateway error codes to problem → cause → next step (never raw code alone).
function pgHelp(status, e) {
  const code = (e && e.code) || '';
  const msg = (e && e.message) || '';
  const req = (e && e.request_id) ? ` (request ${e.request_id})` : '';
  const map = {
    provider_not_connected: `Problem: the provider behind this model is not connected${req}.\nCause: provider credentials are not configured server-side.\nNext step: enable a connected provider's model, or ask the operator to configure credentials. Inference returns 503 by design until then — never a fake reply. Raw: ${msg}`,
    model_not_found: `Problem: this model is unknown or disabled${req}.\nCause: the registry has no enabled entry for it.\nNext step: pick a model from the dropdown (populated from the live registry). Raw: ${msg}`,
    rate_limit_exceeded: `Problem: rate limit hit (HTTP 429)${req}.\nCause: too many requests in the last minute.\nNext step: wait ~60s and retry. Raw: ${msg}`,
    insufficient_quota: `Problem: daily plan quota exhausted (HTTP 429)${req}.\nCause: this account hit its requests/day or tokens/day cap.\nNext step: check Usage, or upgrade the plan. Raw: ${msg}`,
  };
  if (map[code]) return `Error ${status} · ${code}\n` + map[code];
  if (status === 401 || code === 'unauthorized') return `Error 401 · session expired.\nCause: your sign-in session ended.\nNext step: reload the page and sign in again.`;
  if (status === 403) return `Error 403 · ${code || 'forbidden'}${req}.\nCause: missing or stale CSRF token.\nNext step: reload the page and retry. Raw: ${msg}`;
  return `Error ${status}${code ? ' · ' + code : ''}${req}.\n${msg || 'The gateway rejected the request.'}\nNext step: see /docs/errors for the full contract.`;
}

function meta(ms, usage, model) {
  const el = document.getElementById('pgmeta');
  if (!el) return;
  const m = model ? ` · ${model}` : '';
  el.textContent = usage && usage.input_tokens !== undefined
    ? `latency ${ms} ms · ${usage.input_tokens} in / ${usage.output_tokens} out${m}`
    : `latency ${ms} ms (streamed)${m}`;
}
window.playgroundSend = playgroundSend;
document.getElementById('pgform')?.addEventListener('submit', playgroundSend);

// Public nav active state (server doesn't pass page to publicShell).
for (const a of document.querySelectorAll('.pubnav nav a.navlink')) {
  try {
    if (new URL(a.href).pathname === location.pathname) { a.classList.add('active'); a.setAttribute('aria-current', 'page'); }
  } catch { /* ignore */ }
}

// ---------- refinement: toasts ----------
function toast(msg, kind) {
  const box = document.getElementById('toasts');
  if (!box) return;
  const el = document.createElement('div');
  el.className = 'toast' + (kind ? ' ' + kind : '');
  el.textContent = msg;
  box.appendChild(el);
  setTimeout(() => { el.classList.add('out'); setTimeout(() => el.remove(), 250); }, 2200);
}
document.addEventListener('click', (e) => {
  if (e.target.closest('[data-action="copy"], [data-action="pgcopy"]')) toast('Copied to clipboard');
});

// ---------- collapsible sidebar (desktop; persisted) ----------
(function () {
  try {
    if (localStorage.getItem('cm-nav') === 'hidden') document.body.classList.add('nav-hidden');
  } catch { /* ignore */ }
  document.addEventListener('click', (e) => {
    const t = e.target.closest('[data-action="collapse"]');
    if (!t) return;
    const hidden = document.body.classList.toggle('nav-hidden');
    t.setAttribute('aria-expanded', hidden ? 'false' : 'true');
    try { localStorage.setItem('cm-nav', hidden ? 'hidden' : 'shown'); } catch { /* ignore */ }
  });
})();

// ---------- models: client-side search / filter / sort (registry data only) ----------
(function () {
  const q = document.getElementById('mq');
  const tb = document.getElementById('modelrows');
  if (!q || !tb) return;
  const rows = () => [...tb.querySelectorAll('tr[data-name]')];
  const fCap = document.getElementById('mcap');
  const fStat = document.getElementById('mstat');
  const fSort = document.getElementById('msort');
  const count = document.getElementById('modelcount');
  function apply() {
    const needle = q.value.trim().toLowerCase();
    const cap = fCap && fCap.value;
    const st = fStat && fStat.value;
    const vis = rows().filter((r) => {
      const hay = ((r.dataset.name || '') + ' ' + (r.dataset.caps || '')).toLowerCase();
      const show = (!needle || hay.includes(needle))
        && (!cap || (r.dataset.caps || '').split(' ').includes(cap))
        && (!st || r.dataset.status === st);
      r.style.display = show ? '' : 'none';
      return show;
    });
    if (fSort && fSort.value === 'ctx') vis.sort((a, b) => Number(b.dataset.ctx || 0) - Number(a.dataset.ctx || 0)).forEach((r) => tb.appendChild(r));
    else if (fSort && fSort.value === 'name') vis.sort((a, b) => String(a.dataset.name).localeCompare(String(b.dataset.name))).forEach((r) => tb.appendChild(r));
    if (count) count.textContent = vis.length + ' of ' + rows().length + ' shown';
  }
  [q, fCap, fStat, fSort].forEach((el) => el && el.addEventListener('input', apply));
  document.getElementById('mtoolbar')?.addEventListener('submit', (e) => e.preventDefault());
})();

// ---------- logs: request detail drawer (progressive enhancement) ----------
(function () {
  const dlg = document.getElementById('reqdrawer');
  if (!dlg) return;
  const body = dlg.querySelector('.drawer-body');
  dlg.addEventListener('click', (e) => {
    if (e.target === dlg || e.target.closest('[data-action="drawer-close"]')) dlg.close();
  });
  document.addEventListener('click', async (e) => {
    const a = e.target.closest('a.req-link');
    if (!a) return;
    e.preventDefault();
    if (body) body.innerHTML = '<div class="skel" style="height:18px;width:60%"></div><div class="skel" style="height:120px"></div><div class="skel" style="height:60px"></div>';
    if (typeof dlg.showModal === 'function') dlg.showModal();
    else { location.href = a.href; return; }
    try {
      const res = await fetch(a.href, { headers: { Accept: 'text/html' } });
      const doc = new DOMParser().parseFromString(await res.text(), 'text/html');
      const main = doc.querySelector('#main');
      if (body) body.innerHTML = main ? main.innerHTML : '<p>Could not load request detail.</p>';
    } catch {
      if (body) body.innerHTML = '<p>Could not load request detail. <a href="' + a.href + '">Open full page →</a></p>';
    }
  });
})();

// ---------- playground: request-as-cURL snippet (generated locally) ----------
(function () {
  const form = document.getElementById('pgform');
  const pre = document.getElementById('pgsnip');
  if (!form || !pre) return;
  function render() {
    const model = (form.model && form.model.value) || 'deepseek-v4.1-flash';
    const temp = (form.temperature && form.temperature.value) || '0.7';
    const max = (form.max_tokens && form.max_tokens.value) || '512';
    const sys = ((form.system && form.system.value) || '').trim();
    const prompt = (((form.prompt && form.prompt.value) || '').trim()) || 'Hello';
    const msgs = sys
      ? `[{"role":"system","content":${JSON.stringify(sys)}},{"role":"user","content":${JSON.stringify(prompt)}}]`
      : `[{"role":"user","content":${JSON.stringify(prompt)}}]`;
    pre.textContent = `curl ${location.origin}/v1/chat/completions \\\n  -H "Authorization: Bearer $CIPTAMODEL_API_KEY" \\\n  -H "Content-Type: application/json" \\\n  -d '{"model":"${model}","temperature":${temp},"max_tokens":${max},"messages":${msgs}}'`;
  }
  form.addEventListener('input', render);
  render();
  document.addEventListener('click', async (e) => {
    if (!e.target.closest('[data-action="pgsnip-copy"]')) return;
    try { await navigator.clipboard.writeText(pre.textContent); toast('cURL copied'); }
    catch { toast('Copy failed', 'bad'); }
  });
})();
