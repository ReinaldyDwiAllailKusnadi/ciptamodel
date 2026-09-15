'use strict';

// CiptaModel — Phase 1: PLATFORM FOUNDATION.
// SaaS console + auth + API-key management + model/provider registries +
// logs/usage/billing foundations + docs. No upstream AI calls exist here:
// every inference path returns an explicit 503 `provider_not_connected`
// until Phase 2 wires real provider adapters behind src/providers.js.
//
// Public contract (stable): https://ciptamodel.com/v1
//   GET  /v1/models            (registry read — available in Phase 1)
//   POST /v1/chat/completions  (contract defined, 503 until Phase 2)

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const fastify = require('fastify');

const config = require('./config');
const dbm = require('./db');
const { connect, getDb, uid, generateApiKey, hashSecret, maskKey, listModels, listProviders, audit } = dbm;
const { buildRouter, newRequestId, sanitizeRequestId, ProviderError, ProviderNotConnectedError } = require('./providers');
const { createMemoryBackend, checkRate, checkQuota } = require('./limits');

// Test hook: gateway tests inject deterministic mock adapters via
// setRouterOverrides({ adapters: { deepseek: mock } }). Production never sets this.
let routerOverrides = null;
function setRouterOverrides(o) { routerOverrides = o; }
function getRouter() { return buildRouter(dbm, config, routerOverrides || {}); }

// Load .env if present (no dotenv dependency — tiny inline loader).
(function loadEnv() {
  const p = path.resolve('.env');
  if (!fs.existsSync(p)) return;
  for (const line of fs.readFileSync(p, 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
})();

const app = fastify({ logger: false, trustProxy: true, bodyLimit: config.gateway.bodyLimitBytes });
app.register(require('@fastify/cookie'), { secret: config.sessionSecret });
app.register(require('@fastify/formbody'));

// ---------- security headers ----------
app.addHook('onSend', async (req, reply) => {
  reply.header('X-Content-Type-Options', 'nosniff');
  reply.header('X-Frame-Options', 'DENY');
  reply.header('Referrer-Policy', 'strict-origin-when-cross-origin');
  reply.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  reply.header('Content-Security-Policy',
    "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'");
});

// ---------- structured logging (never secrets: no headers, no keys, no bodies) ----------
function logEvent(ev) {
  process.stdout.write(JSON.stringify({ ts: new Date().toISOString(), svc: 'ciptamodel', ...ev }) + '\n');
}

// ---------- helpers ----------
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function errBody(message, type, code, extra) {
  return { error: { message, type, code, ...(extra || {}) } };
}

const STATUS = { 400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found', 409: 'Conflict', 429: 'Too Many Requests', 500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable' };
function sendErr(reply, status, message, type, code, extra) {
  return reply.code(status).send(errBody(message, type || STATUS[status].toLowerCase().replace(/ /g, '_'), code || `http_${status}`, extra));
}

function timeAgo(iso) {
  if (!iso) return 'never';
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}

const shortId = (id) => String(id || '').length > 19 ? String(id).slice(0, 15) + '…' : String(id || '—');

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(email || '').trim());
}

// ---------- session auth ----------
async function currentUser(req) {
  const token = req.cookies.cm_session;
  if (!token) return null;
  const db = getDb();
  const row = db.prepare(`SELECT s.user_id, s.expires_at, s.csrf_token, u.email, u.plan, u.name
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ?`).get(hashSecret(token));
  if (!row || new Date(row.expires_at) < new Date()) return null;
  if (!row.csrf_token) {
    row.csrf_token = crypto.randomBytes(32).toString('hex');
    try { db.prepare('UPDATE sessions SET csrf_token = ? WHERE token_hash = ?').run(row.csrf_token, hashSecret(token)); } catch { /* ignore */ }
  }
  return { id: row.user_id, email: row.email, plan: row.plan, name: row.name, csrf: row.csrf_token };
}

function createSession(userId, reply) {
  const token = crypto.randomBytes(32).toString('base64url');
  const csrf = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + 7 * 86400e3).toISOString();
  getDb().prepare('INSERT INTO sessions (token_hash, user_id, expires_at, csrf_token) VALUES (?,?,?,?)')
    .run(hashSecret(token), userId, expires, csrf);
  reply.setCookie('cm_session', token, { path: '/', httpOnly: true, sameSite: 'lax', maxAge: 7 * 86400 });
}

function destroySession(req, reply) {
  const token = req.cookies.cm_session;
  if (token) getDb().prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashSecret(token));
  reply.clearCookie('cm_session', { path: '/' });
}

// CSRF: cookie-authenticated state-changing routes must present the
// per-session token via body._csrf or x-csrf-token. /v1/* uses Bearer keys — exempt.
app.addHook('preHandler', async (req, reply) => {
  if (req.method === 'GET' || req.method === 'HEAD' || req.url.startsWith('/v1/')) return;
  const user = await currentUser(req);
  if (!user) return; // login/register handled by their own handlers
  const presented = req.body?._csrf || req.headers['x-csrf-token'];
  if (!user.csrf || presented !== user.csrf) {
    return sendErr(reply, 403, 'Invalid CSRF token. Reload the page and retry.', 'auth_error', 'csrf_invalid');
  }
});

async function requireUser(req, reply) {
  const user = await currentUser(req);
  if (!user) { reply.redirect('/login'); return null; }
  return user;
}

// ---------- plans / limits / usage ----------
const limiter = createMemoryBackend();

function getPlan(name) {
  const row = getDb().prepare('SELECT * FROM plans WHERE name = ?').get(name || 'free');
  return row || getDb().prepare('SELECT * FROM plans WHERE name = ?').get('free');
}

function dayStartIso() {
  const d = new Date();
  d.setHours(0, 0, 0, 0);
  return d.toISOString();
}

function ensureSubscription(userId, plan) {
  const db = getDb();
  const row = db.prepare('SELECT * FROM subscriptions WHERE user_id = ?').get(userId);
  if (!row) {
    db.prepare('INSERT INTO subscriptions (user_id, plan, status) VALUES (?,?,?)').run(userId, plan || 'free', 'active');
    return db.prepare('SELECT * FROM subscriptions WHERE user_id = ?').get(userId);
  }
  if (row.plan !== plan) db.prepare('UPDATE subscriptions SET plan = ? WHERE user_id = ?').run(plan, userId);
  return db.prepare('SELECT * FROM subscriptions WHERE user_id = ?').get(userId);
}

function logUsage({ requestId = null, userId, keyId, modelId, provider, inputTokens, outputTokens, latencyMs, status, errorCode, estCost = null }) {
  try {
    getDb().prepare(`INSERT INTO requests
      (id, request_id, user_id, api_key_id, model_id, provider, input_tokens, output_tokens, total_tokens, latency_ms, status, error_code, est_cost)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
      uid('req'), requestId, userId, keyId, modelId, provider,
      inputTokens || 0, outputTokens || 0, (inputTokens || 0) + (outputTokens || 0),
      latencyMs || 0, status, errorCode || null, estCost);
  } catch { logEvent({ level: 'error', msg: 'usage log failed' }); }
}

function logAttempt({ requestId, provider, model, status, errorCode, latencyMs, attemptNo }) {
  try {
    getDb().prepare(`INSERT INTO provider_attempts (id, request_id, provider, model, status, error_code, latency_ms, attempt_no)
      VALUES (?,?,?,?,?,?,?,?)`).run(uid('att'), requestId, provider, model, status, errorCode || null, latencyMs || 0, attemptNo || 1);
  } catch { /* attempts must never break the request */ }
}

// Cost from the model registry pricing fields. Null when unknown —
// never $0.00 for a priced-unknown model.
function estimateCost(entry, inputTokens, outputTokens) {
  if (entry == null || inputTokens == null || outputTokens == null) return null;
  const ip = Number(entry.price_input_per_1k);
  const op = Number(entry.price_output_per_1k);
  if (!Number.isFinite(ip) || !Number.isFinite(op)) return null;
  if (ip === 0 && op === 0) {
    // Registry explicitly prices this model at zero.
    return 0;
  }
  return (inputTokens / 1000) * ip + (outputTokens / 1000) * op;
}

function userStats(userId) {
  const db = getDb();
  const total = db.prepare('SELECT COUNT(*) c FROM requests WHERE user_id = ?').get(userId).c;
  const tokens = db.prepare('SELECT COALESCE(SUM(total_tokens),0) t FROM requests WHERE user_id = ?').get(userId).t;
  const inTok = db.prepare('SELECT COALESCE(SUM(input_tokens),0) t FROM requests WHERE user_id = ?').get(userId).t;
  const outTok = db.prepare('SELECT COALESCE(SUM(output_tokens),0) t FROM requests WHERE user_id = ?').get(userId).t;
  const today = db.prepare('SELECT COUNT(*) c FROM requests WHERE user_id = ? AND created_at >= ?').get(userId, dayStartIso()).c;
  const month = db.prepare("SELECT COUNT(*) c FROM requests WHERE user_id = ? AND created_at >= date('now','start of month')").get(userId).c;
  const errs = db.prepare("SELECT COUNT(*) c FROM requests WHERE user_id = ? AND status != 'success'").get(userId).c;
  const p50 = db.prepare('SELECT latency_ms v FROM requests WHERE user_id = ? ORDER BY latency_ms LIMIT 1 OFFSET (SELECT COUNT(*)/2 FROM requests WHERE user_id = ?)').get(userId, userId)?.v ?? null;
  const activeKeys = db.prepare("SELECT COUNT(*) c FROM api_keys WHERE user_id = ? AND status = 'active'").get(userId).c;
  const byModel = db.prepare('SELECT model_id, COUNT(*) n, COALESCE(SUM(input_tokens),0) i, COALESCE(SUM(output_tokens),0) o, COALESCE(SUM(total_tokens),0) t FROM requests WHERE user_id = ? GROUP BY model_id ORDER BY n DESC').all(userId);
  const byKey = db.prepare(`SELECT k.name, k.key_prefix, COUNT(r.id) n, COALESCE(SUM(r.total_tokens),0) t
    FROM api_keys k LEFT JOIN requests r ON r.api_key_id = k.id
    WHERE k.user_id = ? GROUP BY k.id ORDER BY n DESC`).all(userId);
  const daily = db.prepare("SELECT date(created_at) d, COUNT(*) n, COALESCE(SUM(total_tokens),0) t FROM requests WHERE user_id = ? AND created_at >= date('now','-14 days') GROUP BY d ORDER BY d DESC").all(userId);
  const recent = db.prepare(`SELECT r.*, k.name key_name FROM requests r LEFT JOIN api_keys k ON k.id = r.api_key_id
    WHERE r.user_id = ? ORDER BY r.created_at DESC LIMIT 8`).all(userId);
  return { total, tokens, inTok, outTok, today, month, errRate: total ? ((errs / total) * 100).toFixed(1) + '%' : '0%', p50: p50 ?? '—', activeKeys, byModel, byKey, daily, recent };
}

// ============================================================
// HTML views (server-rendered, no build step)
// ============================================================
const CSS = '/styles.css';
const DASH_NAV = [
  ['Dashboard', '/dashboard', null],
  ['AI GATEWAY', null, 'sec'],
  ['Playground', '/dashboard/playground', null],
  ['API Keys', '/dashboard/api-keys', null],
  ['Models', '/dashboard/models', null],
  ['Logs', '/dashboard/logs', null],
  ['DEVELOPER', null, 'sec'],
  ['Documentation', '/docs', null],
  ['SDK', '/sdk', null],
  ['Examples', '/examples', null],
  ['BILLING', null, 'sec'],
  ['Plan', '/dashboard/billing', null],
  ['Usage', '/dashboard/usage', null],
  ['ACCOUNT', null, 'sec'],
  ['Settings', '/dashboard/settings', null],
];

function layout({ title, user, active, body, dash = true }) {
  const links = (dash ? DASH_NAV : []).map(([label, href, kind]) => kind === 'sec'
    ? `<div class="navsec">${label}</div>`
    : `<a href="${href}" class="${active === label ? 'active' : ''}">${label}</a>`).join('');
  const side = dash
    ? `<aside class="sidebar" aria-label="Dashboard navigation"><div class="brand">Cipta<span>Model</span></div>
       <nav class="nav">${links}</nav>
       <div class="side-foot">${user ? `${esc(user.email)}<br><a href="/logout" style="color:#93c5fd">Sign out</a>` : '<a href="/login" style="color:#93c5fd">Sign in</a>'}</div></aside>`
    : '';
  return `<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} · CiptaModel</title><link rel="stylesheet" href="${CSS}"></head><body>
<div class="shell">${side}
<div class="main"><div class="topbar"><button class="menu-btn" data-action="menu" aria-label="Toggle navigation">☰</button>
<strong>${esc(title)}</strong><span class="who">Gateway: <code class="inline">/v1</code> · OpenAI-compatible</span></div>
<main class="content">${body}</main></div></div>
<script src="/app.js"></script></body></html>`;
}

function publicShell({ title, body }) {
  return `<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} · CiptaModel</title><link rel="stylesheet" href="${CSS}"></head><body>
<header class="pubnav"><div class="pubnav-in"><a class="pubbrand" href="/">Cipta<span>Model</span></a>
<nav aria-label="Public"><a href="/models">Models</a><a href="/pricing">Pricing</a><a href="/docs">Docs</a><a href="/login">Sign in</a><a class="btn sm" href="/register">Get started</a></nav></div></header>
${body}
<footer class="pubfoot"><div class="pubfoot-in"><span><strong>CiptaModel</strong> — One API. Multiple AI Models.</span>
<span><a href="/docs">Docs</a> · <a href="/pricing">Pricing</a> · <a href="/docs/quickstart">Quickstart</a> · <a href="/login">Sign in</a></span></div></footer>
</body></html>`;
}

function phase2Badge() {
  return ' <span class="badge warn">Coming in Phase 2</span>';
}

const views = {
  landing() {
    return publicShell({ title: 'One API. Multiple AI Models', body: `
<div class="landing"><div class="hero">
<p class="eyebrow">UNIFIED AI API GATEWAY</p>
<h1>One API.<br>Multiple AI Models.</h1>
<p>CiptaModel gives developers a single OpenAI-compatible interface for many AI models. One <code class="inline">sk-cm-…</code> key, one base URL — swap providers without rewriting your integration.</p>
<p><a class="btn" href="/register">Get started free</a> &nbsp; <a class="btn ghost" href="/docs">Read the docs</a></p>
<pre style="text-align:left" aria-label="API code preview">curl ${esc(config.publicApiBaseUrl)}/chat/completions \\
  -H "Authorization: Bearer sk-cm-live-..." \\
  -H "Content-Type: application/json" \\
  -d '{"model": "deepseek-v4.1-flash",
       "messages": [{"role": "user", "content": "Hello"}]}'</pre>
<p><small>Live gateway — point any OpenAI-compatible client at the base URL above.</small></p>
</div>
<h2 style="text-align:center">How it works</h2>
<div class="feat">
<div class="card"><h3>1 · GET A KEY</h3><div class="stat" style="font-size:19px">sk-cm-live-…</div><small>Create one key in the dashboard. Hashed at rest, shown once.</small></div>
<div class="card"><h3>2 · POINT YOUR CLIENT</h3><div class="stat" style="font-size:19px">/v1 base URL</div><small>Cursor, Cline, Open WebUI, or any OpenAI SDK.</small></div>
<div class="card"><h3>3 · PICK A MODEL</h3><div class="stat" style="font-size:19px">Stable IDs</div><small>Providers change behind the scenes. Your code stays the same.</small></div>
</div>
<h2 style="text-align:center">Why CiptaModel</h2>
<div class="feat">
<div class="card"><h3>OPENAI-COMPATIBLE</h3><small>Drop-in <code class="inline">/v1</code> API: chat completions, SSE streaming, standard error shapes.</small></div>
<div class="card"><h3>MODEL ROUTER</h3><small>Registry-driven routing with per-model fallback — no provider lock-in.</small></div>
<div class="card"><h3>BUILT FOR TEAMS</h3><small>Per-key quotas, rate limits, request logs, and usage metering from day one.</small></div>
</div>
<h2 style="text-align:center">Pricing preview</h2>
<div class="feat">
<div class="card"><h3>FREE</h3><div class="stat" style="font-size:19px">$0</div><small>100 req/day · 50K tokens/day · community support.</small></div>
<div class="card"><h3>DEVELOPER</h3><div class="stat" style="font-size:19px">Soon</div><small>5K req/day · 2M tokens/day · higher rate limits.</small></div>
<div class="card"><h3>PRO / ENTERPRISE</h3><div class="stat" style="font-size:19px">Soon</div><small>High volume, custom quotas, priority support. <a href="/pricing">Details →</a></small></div>
</div>
<h2 style="text-align:center">FAQ</h2>
<div class="card"><h3>IS THE API LIVE?</h3><small>Yes — <code class="inline">POST /v1/chat/completions</code> serves real DeepSeek inference through the gateway (Bearer key required). Without server-side provider credentials it returns an honest <code class="inline">503 provider_not_connected</code>.</small></div><br>
<div class="card"><h3>WHICH CLIENTS ARE SUPPORTED?</h3><small>Anything speaking OpenAI-compatible HTTP: Cursor, Cline, Roo Code, Claude Code, Aider, Open WebUI, and the official OpenAI SDKs.</small></div><br>
<div class="card"><h3>CAN I CHANGE PROVIDERS LATER?</h3><small>Yes — that is the point. Your client talks to CiptaModel; the router picks the provider. Model IDs stay stable.</small></div><br>
<p style="text-align:center"><a class="btn" href="/register">Create your free account</a></p>
</div>` });
  },

  pricing(plans) {
    const cards = plans.map((p) => {
      const name = String(p.name).toUpperCase();
      const req = p.requests_per_day < 0 ? 'Unlimited requests' : `${Number(p.requests_per_day).toLocaleString()} req/day`;
      const tok = p.tokens_per_day < 0 ? 'unlimited tokens' : `${Number(p.tokens_per_day).toLocaleString()} tokens/day`;
      const rpm = p.rpm < 0 ? 'no rate cap' : `${p.rpm}/min`;
      return `<div class="card"><h3>${esc(name)}</h3><div class="stat" style="font-size:19px">${p.name === 'free' ? '$0' : 'Soon'}</div><small>${req} · ${tok} · ${rpm}.</small></div>`;
    }).join('');
    return publicShell({ title: 'Pricing', body: `
<div class="landing"><div class="hero"><h1>Pricing</h1>
<p>Start free. Upgrade when your usage grows. Quotas are enforced per plan — no surprise bills.</p></div>
<div class="feat" style="grid-template-columns:repeat(4,1fr)">${cards}</div>
<p style="text-align:center"><a class="btn" href="/register">Start free</a> &nbsp; <a class="btn ghost" href="/docs">Read the docs</a></p>
<p style="text-align:center"><small>Payments activate after Phase 1. Current billing state is tracked in <a href="/dashboard/billing">your dashboard</a>.</small></p></div>` });
  },

  auth(mode, error) {
    const isReg = mode === 'register';
    return layout({ title: isReg ? 'Create account' : 'Sign in', user: null, active: '', dash: false, body: `
<h1>${isReg ? 'Create your account' : 'Welcome back'}</h1>
<p class="sub">${isReg ? 'Free tier included. No credit card required.' : 'Sign in to your CiptaModel console.'}</p>
${error ? `<div class="alert bad" role="alert">${esc(error)}</div>` : ''}
<form method="post" action="/${mode}" class="form-narrow">
<label for="email">Email</label><input id="email" type="email" name="email" required autocomplete="email">
<label for="password">Password <small style="font-weight:400">(min 8 characters, hashed with bcrypt)</small></label><input id="password" type="password" name="password" required minlength="8" autocomplete="${isReg ? 'new-password' : 'current-password'}">
<p><button class="btn" type="submit">${isReg ? 'Create account' : 'Sign in'}</button></p>
<p><small>${isReg ? 'Have an account? <a href="/login">Sign in</a>' : 'New here? <a href="/register">Create an account</a>'}</small></p>
</form>` });
  },

  dashboard(user, s, providers) {
    const card = (h, v, sub) => `<div class="card"><h3>${h}</h3><div class="stat">${v}</div><small>${sub}</small></div>`;
    const provRows = providers.map((p) =>
      `<tr><td><strong>${esc(p.display_name)}</strong></td><td class="mono">${esc(p.name)}</td>
       <td>${p.enabled ? '<span class="badge info">Enabled</span>' : '<span class="badge">Disabled</span>'}</td>
       <td><span class="badge ${p.status === 'connected' || p.status === 'configured' ? 'ok' : 'warn'}">${esc(p.status)}</span></td></tr>`).join('');
    const recent = (s.recent || []).map((r) => `<tr><td class="mono"><small>${esc(r.created_at)}</small></td>
<td class="mono">${esc(r.model_id)}</td><td>${r.total_tokens}</td>
<td>${r.status === 'success' ? '<span class="badge ok">ok</span>' : `<span class="badge bad">${esc(r.error_code || r.status)}</span>`}</td></tr>`).join('');
    return layout({ title: 'Dashboard', user, active: 'Dashboard', body: `
<h1>Dashboard</h1><p class="sub">Plan <span class="badge info">${esc(user.plan)}</span> · Gateway <code class="inline">${esc(config.publicApiBaseUrl)}</code></p>
<div class="grid c4">
${card('Total requests', s.total ?? 0, 'logged gateway calls')}
${card('Total tokens', Number(s.tokens ?? 0).toLocaleString(), 'input + output')}
${card('Active API keys', s.activeKeys ?? 0, '<a href="/dashboard/api-keys">manage keys →</a>')}
${card('Error rate', (s.errRate ?? '0%'), 'failed / total · p50 ' + (s.p50 ?? '—') + ' ms')}
</div><br>
<div class="grid c2">
<div class="card"><h3>SYSTEM STATUS — PROVIDERS</h3>
<table><tr><th>PROVIDER</th><th>ID</th><th>REGISTRY</th><th>CONNECTION</th></tr>${provRows}</table>
<p><small>Gateway status: live DeepSeek adapter when <code class="inline">DEEPSEEK_API_KEY</code> is configured server-side, otherwise honest <code class="inline">503 provider_not_connected</code> — statuses flip without API changes.</small></p></div>
<div class="card"><h3>RECENT REQUESTS</h3>
${recent ? `<table><tr><th>TIME</th><th>MODEL</th><th>TOKENS</th><th>STATUS</th></tr>${recent}</table><p><a href="/dashboard/logs">All logs →</a></p>`
  : '<div class="empty">No requests yet. Logs will appear here once the gateway is used.</div>'}</div>
</div>` });
  },

  keys(user, keys, usageByKey, newSecret) {
    const rows = keys.map((k) => {
      const u = (usageByKey || {})[k.id] || { n: 0, t: 0 };
      return `<tr>
<td><strong>${esc(k.name)}</strong><br><small style="color:var(--muted)">${esc(shortId(k.id))} · created ${esc((k.created_at || '').slice(0, 10))}</small></td>
<td class="mono">${esc(maskKey(k.key_prefix))}</td>
<td>${Number(u.n).toLocaleString()} req<br><small style="color:var(--muted)">${Number(u.t).toLocaleString()} tok</small></td>
<td>${timeAgo(k.last_used_at)}</td>
<td>${k.status === 'active' ? '<span class="badge ok">Active</span>' : '<span class="badge bad">Revoked</span>'}</td>
<td>${k.status === 'active'
  ? `<form method="post" action="/dashboard/api-keys/${k.id}/revoke" style="display:inline" onsubmit="return confirm('Revoke this key? Integrations using it will stop working.')"><input type="hidden" name="_csrf" value="${esc(user.csrf || '')}"><button class="btn danger sm">Revoke</button></form>`
  : `<form method="post" action="/dashboard/api-keys/${k.id}/delete" style="display:inline" onsubmit="return confirm('Permanently delete this key record?')"><input type="hidden" name="_csrf" value="${esc(user.csrf || '')}"><button class="btn ghost sm">Delete</button></form>`}</td>
</tr>`;
    }).join('');
    return layout({ title: 'API Keys', user, active: 'API Keys', body: `
<h1>Manajemen API Keys</h1>
<p class="sub">Kelola kunci API untuk menghubungkan Cursor, Cline, Open WebUI, dan aplikasi developer.</p>
${newSecret ? `<div class="alert warn" role="alert"><strong>Copy this key now — it is shown in full only once.</strong> Afterwards only the masked value is visible.</div>
<div class="secret-box"><code>${esc(newSecret)}</code>
<button class="btn sm" data-action="copy" data-copy="${esc(newSecret)}" data-label="Copy">Copy</button></div><br>` : ''}
<div class="row"><div class="spacer"></div>
<form method="post" action="/dashboard/api-keys" class="row" aria-label="Create API key"><input type="hidden" name="_csrf" value="${esc(user.csrf || '')}"><label class="sr" for="keyname">Key name</label><input id="keyname" type="text" name="name" placeholder="Key name, e.g. Cursor Development" required maxlength="80" style="width:260px"><button class="btn">+ Buat Key Baru</button></form></div><br>
<table><tr><th>NAMA KUNCI</th><th>API KEY</th><th>USAGE</th><th>TERAKHIR DIPAKAI</th><th>STATUS</th><th>AKSI</th></tr>
${rows || '<tr><td colspan="6"><div class="empty">Belum ada API key. Buat key pertama untuk mulai memakai gateway.</div></td></tr>'}</table>
<p><small>Secrets are stored as SHA-256 hashes and can never be recovered after this page. Quotas follow your <a href="/dashboard/billing">plan</a>.</small></p>` });
  },

  modelsPage(user, models, providers) {
    const provName = Object.fromEntries(providers.map((p) => [p.name, p]));
    const cards = models.map((m) => {
      const p = provName[m.provider];
      const conn = p ? p.status : 'unknown';
      return `<div class="card">
<h3>${esc(m.display_name).toUpperCase()}</h3>
<div class="stat mono" style="font-size:16px">${esc(m.id)}</div>
<p><small>Provider: <strong>${esc(m.provider)}</strong> (<span class="badge warn">${esc(conn)}</span>) · Context: <strong>${Number(m.context_window).toLocaleString()} tokens</strong> · Max out: <strong>${Number(m.max_output_tokens).toLocaleString()}</strong> · Status: ${m.enabled ? '<span class="badge ok">Available</span>' : '<span class="badge bad">Disabled</span>'}</small></p>
<p>${(m.capabilities || []).map((c) => `<span class="badge info">${esc(c)}</span>`).join(' ')}</p>
<p><small>${esc(m.description || '')}</small></p>
<p><small>In: $${m.price_input_per_1k}/1K · Out: $${m.price_output_per_1k}/1K${m.fallback ? ` · Fallback: <code class="inline">${esc(m.fallback.model)}</code>` : ''}</small></p></div>`;
    }).join('');
    return layout({ title: 'Models', user, active: 'Models', body: `
<h1>Models</h1><p class="sub">Registry data — public model IDs stay stable even when upstream providers change. Only enabled models accept traffic.</p>
<div class="grid c2">${cards || '<div class="empty">No models in registry.</div>'}</div>` });
  },

  logs(user, rows) {
    const tr = rows.map((r) => `<tr><td class="mono"><small>${esc(r.created_at)}</small></td>
<td class="mono"><small>${esc(shortId(r.id))}</small></td>
<td>${r.key_name ? `<strong>${esc(r.key_name)}</strong><br>` : ''}<small class="mono">${r.key_prefix ? esc(maskKey(r.key_prefix)) : '—'}</small></td>
<td class="mono">${esc(r.model_id)}</td><td class="mono">${esc(r.provider)}</td>
<td>${r.inTok} / ${r.outTok} / <strong>${r.total_tokens}</strong></td><td>${r.latency_ms} ms</td>
<td>${r.status === 'success' ? '<span class="badge ok">success</span>' : `<span class="badge bad">${esc(r.error_code || r.status)}</span>`}</td></tr>`).join('');
    return layout({ title: 'Logs', user, active: 'Logs', body: `
<h1>Logs</h1><p class="sub">Last 100 gateway requests on your account. Columns: timestamp · request id · API key · model · provider · in/out/total tokens · latency · status.</p>
${tr ? `<table><tr><th>TIMESTAMP</th><th>REQUEST</th><th>API KEY</th><th>MODEL</th><th>PROVIDER</th><th>TOKENS</th><th>LATENCY</th><th>STATUS</th></tr>${tr}</table>`
  : '<div class="empty">No requests logged yet. Logs will appear here after the API is used — nothing is fabricated.</div>'}` });
  },

  playground(user, models) {
    const opts = models.filter((m) => m.enabled).map((m) => `<option value="${esc(m.id)}">${esc(m.id)}</option>`).join('');
    return layout({ title: 'Playground', user, active: 'Playground', body: `
<h1>Playground</h1><p class="sub">Developer test console — runs the same gateway pipeline as <code class="inline">/v1</code> using your signed-in session (no API key needed in the browser). <span id="pgmeta"></span></p>
<meta name="csrf-token" content="${esc(user.csrf || '')}">
<div class="chatlog" id="chatlog" aria-live="polite"><div class="msg sys">Pick a model and send a prompt. Responses stream token-by-token when the provider is connected.</div></div><br>
<form onsubmit="playgroundSend(event)" class="grid" style="grid-template-columns:1fr" aria-label="Playground">
<div class="row"><label class="sr" for="pgmodel">Model</label><select id="pgmodel" name="model" style="max-width:260px">${opts}</select>
<label for="pgtemp">Temperature</label><input id="pgtemp" type="number" name="temperature" min="0" max="2" step="0.1" value="0.7" style="max-width:90px">
<label for="pgmax">Max tokens</label><input id="pgmax" type="number" name="max_tokens" min="1" max="32000" value="512" style="max-width:110px">
<label style="display:inline;font-weight:400"><input type="checkbox" name="stream" checked style="width:auto"> stream</label></div>
<label class="sr" for="pgsys">System prompt</label><input id="pgsys" type="text" name="system" placeholder="System prompt (optional)">
<div class="row"><label class="sr" for="pgprompt">Prompt</label><input id="pgprompt" type="text" name="prompt" placeholder="Type a prompt…" required><button class="btn" type="submit">Send</button></div>
</form>` });
  },

  billing(user, sub, plan, plans, usage) {
    const cards = plans.map((p) => {
      const cur = p.name === sub.plan;
      return `<div class="card"><h3>${esc(p.name.toUpperCase())}${cur ? ' · <span class="badge ok">CURRENT</span>' : ''}</h3>
<div class="stat" style="font-size:19px">${p.requests_per_day < 0 ? 'Unlimited' : Number(p.requests_per_day).toLocaleString() + '/day'}</div>
<small>${p.tokens_per_day < 0 ? 'unlimited' : Number(p.tokens_per_day).toLocaleString() + ' tokens/day'} · ${p.rpm < 0 ? 'no rate cap' : p.rpm + '/min'}</small></div>`;
    }).join('');
    return layout({ title: 'Billing', user, active: 'Plan', body: `
<h1>Billing</h1><p class="sub">Plan, usage, and limits. Payments are not yet enabled — the schema already tracks plan, quota, usage, and subscription status.</p>
<div class="grid c2">
<div class="card"><h3>CURRENT PLAN</h3><div class="stat">${esc(sub.plan)}</div><small>Status: ${esc(sub.status)} · Used today: ${usage.reqs} req / ${Number(usage.toks).toLocaleString()} tokens</small></div>
<div class="card"><h3>UPGRADE</h3><small>Self-serve upgrades and usage-based invoicing land after Phase 1. Contact us to change plans meanwhile.</small><br><br><a class="btn ghost sm" href="/pricing">Compare plans</a></div>
</div><br><div class="grid c4">${cards}</div>` });
  },

  usagePage(user, s) {
    const rows = (s.daily || []).map((r) =>
      `<tr><td class="mono">${esc(r.d)}</td><td>${r.n}</td><td>${Number(r.t).toLocaleString()}</td></tr>`).join('');
    const byModel = (s.byModel || []).map((r) =>
      `<tr><td class="mono">${esc(r.model_id)}</td><td>${r.n}</td><td>${Number(r.i).toLocaleString()}</td><td>${Number(r.o).toLocaleString()}</td><td>${Number(r.t).toLocaleString()}</td></tr>`).join('');
    const byKey = (s.byKey || []).map((r) =>
      `<tr><td><strong>${esc(r.name)}</strong> <small class="mono">${esc(maskKey(r.key_prefix))}</small></td><td>${r.n}</td><td>${Number(r.t).toLocaleString()}</td></tr>`).join('');
    const empty = '<div class="empty">No data yet — metrics populate automatically once the gateway is used.</div>';
    return layout({ title: 'Usage', user, active: 'Usage', body: `
<h1>Usage</h1><p class="sub">Requests, tokens, cost estimate, and breakdowns on your account.</p>
<div class="grid c4">
<div class="card"><h3>REQUESTS</h3><div class="stat">${s.total}</div><small>${s.month} this month</small></div>
<div class="card"><h3>INPUT TOKENS</h3><div class="stat">${Number(s.inTok).toLocaleString()}</div></div>
<div class="card"><h3>OUTPUT TOKENS</h3><div class="stat">${Number(s.outTok).toLocaleString()}</div></div>
<div class="card"><h3>EST. COST</h3><div class="stat">$0.00</div><small>metered pricing activates with billing</small></div>
</div><br>
<div class="card"><h3>USAGE BY MODEL</h3>${byModel ? `<table><tr><th>MODEL</th><th>REQUESTS</th><th>IN</th><th>OUT</th><th>TOTAL</th></tr>${byModel}</table>` : empty}</div><br>
<div class="card"><h3>USAGE BY API KEY</h3>${byKey ? `<table><tr><th>KEY</th><th>REQUESTS</th><th>TOKENS</th></tr>${byKey}</table>` : empty}</div><br>
<div class="card"><h3>DAILY (14 DAYS)</h3>${rows ? `<table><tr><th>DATE</th><th>REQUESTS</th><th>TOKENS</th></tr>${rows}</table>` : empty}</div>` });
  },

  settings(user, msg, error) {
    return layout({ title: 'Settings', user, active: 'Settings', body: `
<h1>Settings</h1><p class="sub">Profile, account security, and preferences.</p>
${msg ? `<div class="alert ok" role="status">${esc(msg)}</div>` : ''}
${error ? `<div class="alert bad" role="alert">${esc(error)}</div>` : ''}
<div class="grid c2">
<div class="card"><h3>PROFILE</h3>
<form method="post" action="/dashboard/settings/profile" class="form-narrow">
<input type="hidden" name="_csrf" value="${esc(user.csrf || '')}">
<label for="setname">Display name</label><input id="setname" type="text" name="name" maxlength="80" value="${esc(user.name || '')}" placeholder="Your name">
<label>Email</label><input type="email" value="${esc(user.email)}" disabled>
<p><button class="btn" type="submit">Save profile</button></p></form></div>
<div class="card"><h3>SECURITY</h3>
<form method="post" action="/dashboard/settings/password" class="form-narrow">
<input type="hidden" name="_csrf" value="${esc(user.csrf || '')}">
<label for="setpass">New password (min 8 chars)</label><input id="setpass" type="password" name="password" minlength="8" required autocomplete="new-password">
<p><button class="btn" type="submit">Update password</button></p></form>
<p><small>Sessions expire after 7 days. Passwords are bcrypt-hashed; API keys are SHA-256 hashed.</small></p></div>
</div>` });
  },

  sdk() {
    return layout({ title: 'SDK', user: null, active: 'SDK', dash: false, body: `
<h1>SDK</h1><p class="sub">CiptaModel speaks the OpenAI API — every OpenAI SDK works. Just point the base URL at us.</p>
<h2>Python</h2><pre>from openai import OpenAI

client = OpenAI(
    base_url="${esc(config.publicApiBaseUrl)}",
    api_key="sk-cm-live-...",
)
r = client.chat.completions.create(
    model="deepseek-v4.1-flash",
    messages=[{"role": "user", "content": "Hello"}],
)
print(r.choices[0].message.content)</pre>
<h2>JavaScript / TypeScript</h2><pre>// npm i openai
import OpenAI from "openai";
const client = new OpenAI({
  baseURL: "${esc(config.publicApiBaseUrl)}",
  apiKey: process.env.CIPTAMODEL_API_KEY,
});
const r = await client.chat.completions.create({
  model: "deepseek-v4.1-flash",
  messages: [{ role: "user", content: "Hello" }],
});</pre>` });
  },

  examples() {
    return layout({ title: 'Examples', user: null, active: 'Examples', dash: false, body: `
<h1>Examples</h1><p class="sub">Copy-paste recipes for common clients.</p>
<h2>cURL — chat completion</h2><pre>curl ${esc(config.publicApiBaseUrl)}/chat/completions \\
  -H "Authorization: Bearer $CIPTAMODEL_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"model":"deepseek-v4.1-flash","messages":[{"role":"user","content":"Write a haiku about APIs"}]}'</pre>
<h2>cURL — streaming</h2><pre>curl -N ${esc(config.publicApiBaseUrl)}/chat/completions \\
  -H "Authorization: Bearer $CIPTAMODEL_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"model":"deepseek-v4.1-flash","stream":true,
       "messages":[{"role":"user","content":"Count to five"}]}'</pre>
<h2>cURL — list models</h2><pre>curl ${esc(config.publicApiBaseUrl)}/models \\
  -H "Authorization: Bearer $CIPTAMODEL_API_KEY"</pre>` });
  },
};

// Static docs (intended API contract; Phase-2 endpoints are badged, not claimed live)
const DOCS = {
  introduction: { title: 'Introduction', phase2: false, body: `
<p>CiptaModel is a unified AI API gateway: <strong>one API key, many AI models</strong>, over an OpenAI-compatible HTTP API.</p>
<p>Public base URL: <code class="inline">${esc(config.publicApiBaseUrl)}</code></p>
<p>Architecture: your client → CiptaModel gateway → model router → provider adapter. Providers can be swapped without changing your integration.</p>
<p>DeepSeek is the first live provider. Set <code class="inline">DEEPSEEK_API_KEY</code> server-side to enable inference; without it chat returns <code class="inline">503 provider_not_connected</code>.</p>` },
  quickstart: { title: 'Quickstart', phase2: false, body: `
<ol><li>Create an account and <a href="/dashboard/api-keys">create an API key</a>.</li>
<li>Base URL: <code class="inline">${esc(config.publicApiBaseUrl)}</code></li>
<li>Model: <code class="inline">deepseek-v4.1-flash</code></li></ol>
<pre>curl ${esc(config.publicApiBaseUrl)}/chat/completions \\
  -H "Authorization: Bearer sk-cm-live-..." \\
  -H "Content-Type: application/json" \\
  -d '{"model": "deepseek-v4.1-flash",
       "messages": [{"role": "user", "content": "Hello"}]}'</pre>
<p>Every response and error carries an <code class="inline">X-Request-ID</code> header for tracing. Send your own <code class="inline">X-Request-ID</code> (alphanumeric, max 64 chars) or one is generated.</p>` },
  authentication: { title: 'Authentication', phase2: false, body: `
<p>All <code class="inline">/v1</code> endpoints require a Bearer API key created in the dashboard:</p>
<pre>Authorization: Bearer sk-cm-live-...</pre>
<p>Keys are stored as SHA-256 hashes. The full secret is shown <strong>once</strong> at creation. Revoked keys return <code class="inline">401 invalid_api_key</code>.</p>` },
  models: { title: 'Models', phase2: false, body: `
<p>List enabled models with <code class="inline">GET /v1/models</code> <span class="badge ok">Available</span> — a registry read, no provider call.</p>
<pre>curl ${esc(config.publicApiBaseUrl)}/models \\
  -H "Authorization: Bearer sk-cm-live-..."</pre>
<p>Registry default: <code class="inline">deepseek-v4.1-flash</code> (1M context, chat · coding · streaming). Public IDs stay stable when providers change.</p>` },
  'chat-completions': { title: 'Chat Completions', phase2: false, body: `
<p>OpenAI-compatible <code class="inline">POST /v1/chat/completions</code> <span class="badge ok">Live</span>. Supports <code class="inline">model</code>, <code class="inline">messages</code>, <code class="inline">stream</code>, <code class="inline">temperature</code> (0–2), <code class="inline">max_tokens</code>, <code class="inline">top_p</code>, <code class="inline">stop</code>.</p>
<pre>curl ${esc(config.publicApiBaseUrl)}/chat/completions \\
  -H "Authorization: Bearer sk-cm-live-..." \\
  -H "Content-Type: application/json" \\
  -d '{"model": "deepseek-v4.1-flash", "temperature": 0.7,
       "messages": [{"role": "system", "content": "You are concise."},
                    {"role": "user", "content": "Explain rate limiting."}]}'</pre>
<p>Non-streaming returns a <code class="inline">chat.completion</code> object with real provider <code class="inline">usage</code> (prompt/completion/total tokens). Token counts come from the provider — never fabricated. A cost estimate appears when the model registry carries pricing.</p>` },
  streaming: { title: 'Streaming', phase2: false, body: `
<p>Set <code class="inline">"stream": true</code> <span class="badge ok">Live</span> to receive <code class="inline">text/event-stream</code> chunks in OpenAI format, terminated by <code class="inline">data: [DONE]</code>. Chunks flush as the provider emits them — nothing is buffered server-side.</p>
<pre>curl -N ${esc(config.publicApiBaseUrl)}/chat/completions \\
  -H "Authorization: Bearer sk-cm-live-..." \\
  -H "Content-Type: application/json" \\
  -d '{"model": "deepseek-v4.1-flash", "stream": true,
       "messages": [{"role": "user", "content": "Count to five"}]}'</pre>
<p>Mid-stream provider failures arrive as an OpenAI-shaped error event followed by <code class="inline">[DONE]</code> — the HTTP status stays 200 once streaming has started.</p>` },
  'api-keys': { title: 'API Keys', phase2: false, body: `
<p>Create keys at <a href="/dashboard/api-keys">Dashboard → API Keys</a>. Format: <code class="inline">sk-cm-live-…</code>. Manage lifecycle (revoke/delete) there; usage per key appears under <a href="/dashboard/usage">Usage</a>.</p>` },
  errors: { title: 'Errors', phase2: false, body: `
<p>Errors follow the OpenAI shape: <code class="inline">{"error": {"message", "type", "code"}}</code>. No stack traces or provider credentials are ever exposed.</p>
<table><tr><th>HTTP</th><th>CODE</th><th>MEANING</th></tr>
<tr><td>400</td><td class="mono">invalid_request</td><td>Bad body / unknown field</td></tr>
<tr><td>401</td><td class="mono">invalid_api_key</td><td>Missing, unknown or revoked key</td></tr>
<tr><td>404</td><td class="mono">model_not_found</td><td>Unknown or disabled model</td></tr>
<tr><td>429</td><td class="mono">rate_limit_exceeded / insufficient_quota</td><td>Slow down or upgrade plan (includes <code class="inline">Retry-After</code>)</td></tr>
<tr><td>503</td><td class="mono">provider_not_connected</td><td>Provider credentials not configured server-side</td></tr>
<tr><td>504</td><td class="mono">provider_timeout</td><td>Upstream timed out (retryable)</td></tr>
<tr><td>502/503</td><td class="mono">provider_error</td><td>Upstream failed (retry + fallback attempted for transient errors)</td></tr></table>
<p>All gateway errors include an OpenAI-shaped <code class="inline">error</code> object plus <code class="inline">request_id</code> and an <code class="inline">X-Request-ID</code> header. Provider failures are normalized — no API keys, headers, stacks, or paths leak.</p>` },
  'rate-limits': { title: 'Rate Limits', phase2: false, body: `
<p>Limits apply per API key, per user, per IP, and per model, plus daily request/token quotas per plan. Defaults: Free 10 req/min, 100 req/day, 50K tokens/day — all configurable in the <code class="inline">plans</code> table without code changes.</p>
<p>Exceeded minute limits return <code class="inline">429 rate_limit_exceeded</code>; exhausted daily quotas return <code class="inline">429 insufficient_quota</code> — both with <code class="inline">Retry-After</code> and without contacting any upstream provider.</p>
<p>The in-memory limiter is single-instance. Set <code class="inline">REDIS_URL</code> when running multiple instances — the swap is contained in <code class="inline">src/limits.js</code>.</p>` },
  usage: { title: 'Usage', phase2: false, body: `
<p>Every gateway call records model, provider, input/output tokens, latency, status, and error code. Inspect yours at <a href="/dashboard/usage">Dashboard → Usage</a> and <a href="/dashboard/logs">Logs</a>.</p>` },
  sdk: { title: 'SDK', phase2: false, body: `<p>Use any OpenAI SDK with <code class="inline">baseURL ${esc(config.publicApiBaseUrl)}</code>. See the <a href="/sdk">SDK page</a> for Python/JS snippets. The gateway is OpenAI-compatible: Bearer auth, <code class="inline">/v1/models</code>, <code class="inline">/v1/chat/completions</code>, SSE streaming, and standard error shapes all work with unmodified clients (Cursor, Cline, Open WebUI).</p>` },
  examples: { title: 'Examples', phase2: false, body: `<p>Copy-paste recipes live on the <a href="/examples">Examples page</a> (cURL, streaming, list models).</p>
<p><strong>Cursor:</strong> see <a href="/docs/cursor">Cursor setup</a>. <strong>Cline / Roo Code:</strong> see <a href="/docs/cline">Cline setup</a>. <strong>Open WebUI:</strong> see <a href="/docs/open-webui">Open WebUI setup</a>.</p>` },
  cursor: { title: 'Cursor', phase2: false, body: `
<p>Use CiptaModel as a drop-in OpenAI-compatible provider in Cursor.</p>
<ol><li>Open <strong>Cursor Settings → Models → OpenAI API Key</strong> and paste your key: <code class="inline">sk-cm-live-...</code> (create one at <a href="/dashboard/api-keys">Dashboard → API Keys</a>).</li>
<li>Set <strong>Override OpenAI Base URL</strong> to <code class="inline">${esc(config.publicApiBaseUrl)}</code>.</li>
<li>Add custom model <code class="inline">deepseek-v4.1-flash</code>.</li></ol>
<p>Verify with <code class="inline">GET /v1/models</code> using the same key — the model list your client sees comes straight from the registry.</p>` },
  cline: { title: 'Cline / Roo Code', phase2: false, body: `
<p>Use CiptaModel from Cline or Roo Code via the OpenAI-Compatible provider type.</p>
<ol><li>Open the provider settings, choose <strong>OpenAI Compatible</strong>.</li>
<li>Base URL: <code class="inline">${esc(config.publicApiBaseUrl)}</code></li>
<li>API key: <code class="inline">sk-cm-live-...</code></li>
<li>Model: <code class="inline">deepseek-v4.1-flash</code></li></ol>
<p>Streaming (<code class="inline">stream: true</code>) is supported, so completions arrive token-by-token as these tools expect.</p>` },
  'open-webui': { title: 'Open WebUI', phase2: false, body: `
<p>Connect Open WebUI to CiptaModel as an OpenAI endpoint.</p>
<ol><li>Go to <strong>Settings → Connections → OpenAI</strong>.</li>
<li>Set base URL to <code class="inline">${esc(config.publicApiBaseUrl)}</code> and paste your <code class="inline">sk-cm-live-...</code> key.</li>
<li>Refresh models — <code class="inline">deepseek-v4.1-flash</code> appears automatically via <code class="inline">GET /v1/models</code>.</li></ol>` },
};

function docsPage(slug) {
  const d = DOCS[slug];
  if (!d) return null;
  const items = Object.entries(DOCS).map(([k, v]) =>
    `<a href="/docs/${k}" class="${k === slug ? 'active' : ''}">${v.title}${v.phase2 ? ' ⏳' : ''}</a>`).join('');
  return layout({ title: d.title, user: null, active: 'Documentation', dash: false, body: `
<h1>${esc(d.title)}${d.phase2 ? phase2Badge() : ''}</h1><div class="docs"><nav aria-label="Documentation sections">${items}</nav><div class="doc-body">${d.body}</div></div>` });
}

// ============================================================
// Routes — public
// ============================================================
app.get('/', async () => views.landing());
app.get('/pricing', async () => views.pricing(getDb().prepare('SELECT * FROM plans ORDER BY requests_per_day').all()));

// Health: app liveness + per-provider status WITHOUT secrets. Provider
// detail endpoint is admin/session-authenticated; health shows names only.
function providerHealth() {
  const router = getRouter();
  return Object.values(router.adapters).map((a) => {
    let status = a.status;
    if (a.name === 'deepseek') {
      if (!a.enabled) status = 'disabled';
      else if (!a.configured) status = 'not_configured';
      else status = 'configured';
    } else if (!a.enabled) {
      status = 'disabled';
    }
    return { name: a.name, status };
  });
}
app.get('/healthz', async () => ({ ok: true, phase: '2-gateway', providers: providerHealth() }));
app.get('/health', async (req, reply) => {
  // Alias for orchestrators; same payload, no secrets.
  reply.header('Cache-Control', 'no-store');
  return { ok: true, phase: '2-gateway', providers: providerHealth() };
});

app.get('/styles.css', async (req, reply) => {
  reply.header('Content-Type', 'text/css; charset=utf-8');
  return fs.readFileSync(path.join(__dirname, '..', 'public', 'styles.css'), 'utf8');
});
app.get('/app.js', async (req, reply) => {
  reply.header('Content-Type', 'application/javascript; charset=utf-8');
  return fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
});

// ---------- auth ----------
app.get('/register', async () => views.auth('register'));
app.get('/login', async () => views.auth('login'));
app.post('/register', async (req, reply) => {
  const { email, password } = req.body || {};
  const cleanEmail = String(email || '').toLowerCase().trim();
  if (!isValidEmail(cleanEmail)) return views.auth('register', 'Enter a valid email address.');
  if (!password || String(password).length < 8) return views.auth('register', 'Password must be at least 8 characters.');
  const bcrypt = require('bcryptjs');
  try {
    const id = uid('usr');
    getDb().prepare('INSERT INTO users (id, email, password_hash) VALUES (?,?,?)')
      .run(id, cleanEmail, bcrypt.hashSync(String(password), 10));
    ensureSubscription(id, 'free');
    audit({ userId: id, action: 'user.register', ip: req.ip });
    createSession(id, reply);
    logEvent({ level: 'info', msg: 'user registered' });
    return reply.redirect('/dashboard');
  } catch {
    return views.auth('register', 'Email already registered. Try signing in.');
  }
});
app.post('/login', async (req, reply) => {
  const { email, password } = req.body || {};
  const bcrypt = require('bcryptjs');
  const row = getDb().prepare('SELECT * FROM users WHERE email = ?').get(String(email || '').toLowerCase().trim());
  if (!row || !bcrypt.compareSync(String(password || ''), row.password_hash)) {
    logEvent({ level: 'warn', msg: 'failed login' });
    return views.auth('login', 'Invalid email or password.');
  }
  audit({ userId: row.id, action: 'user.login', ip: req.ip });
  createSession(row.id, reply);
  return reply.redirect('/dashboard');
});
app.get('/logout', async (req, reply) => { destroySession(req, reply); return reply.redirect('/'); });

// ============================================================
// Routes — dashboard (authenticated)
// ============================================================
app.get('/dashboard', async (req, reply) => {
  const user = await requireUser(req, reply);
  if (!user) return;
  const live = providerHealth();
  const byName = Object.fromEntries(live.map((p) => [p.name, p.status]));
  const merged = listProviders().map((p) => ({ ...p, status: byName[p.name] || p.status }));
  return views.dashboard(user, userStats(user.id), merged);
});

// API keys
app.get('/dashboard/api-keys', async (req, reply) => {
  const user = await requireUser(req, reply);
  if (!user) return;
  const db = getDb();
  const keys = db.prepare('SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at DESC').all(user.id);
  const usage = db.prepare('SELECT api_key_id, COUNT(*) n, COALESCE(SUM(total_tokens),0) t FROM requests WHERE user_id = ? AND api_key_id IS NOT NULL GROUP BY api_key_id').all(user.id);
  const usageByKey = Object.fromEntries(usage.map((u) => [u.api_key_id, u]));
  const pending = req.cookies.cm_newkey;
  if (pending) reply.clearCookie('cm_newkey', { path: '/' });
  let newSecret = null;
  if (pending) {
    try { newSecret = Buffer.from(pending, 'base64url').toString(); } catch { newSecret = null; }
  }
  return views.keys(user, keys, usageByKey, newSecret);
});
app.post('/dashboard/api-keys', async (req, reply) => {
  const user = await requireUser(req, reply);
  if (!user) return;
  const name = String(req.body?.name || 'Untitled key').trim().slice(0, 80) || 'Untitled key';
  const { secret, hash, prefix } = generateApiKey();
  const id = uid('key');
  getDb().prepare('INSERT INTO api_keys (id, user_id, name, key_hash, key_prefix) VALUES (?,?,?,?,?)')
    .run(id, user.id, name, hash, prefix);
  audit({ userId: user.id, action: 'api_key.create', targetType: 'api_key', targetId: id, ip: req.ip });
  logEvent({ level: 'info', msg: 'api key created' });
  reply.setCookie('cm_newkey', Buffer.from(secret).toString('base64url'), { path: '/', httpOnly: true, maxAge: 120 });
  return reply.redirect('/dashboard/api-keys');
});
app.post('/dashboard/api-keys/:id/revoke', async (req, reply) => {
  const user = await requireUser(req, reply);
  if (!user) return;
  getDb().prepare("UPDATE api_keys SET status='revoked', revoked_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=? AND user_id=?")
    .run(req.params.id, user.id);
  audit({ userId: user.id, action: 'api_key.revoke', targetType: 'api_key', targetId: req.params.id, ip: req.ip });
  return reply.redirect('/dashboard/api-keys');
});
app.post('/dashboard/api-keys/:id/delete', async (req, reply) => {
  const user = await requireUser(req, reply);
  if (!user) return;
  getDb().prepare('DELETE FROM api_keys WHERE id=? AND user_id=?').run(req.params.id, user.id);
  audit({ userId: user.id, action: 'api_key.delete', targetType: 'api_key', targetId: req.params.id, ip: req.ip });
  return reply.redirect('/dashboard/api-keys');
});

app.get('/dashboard/models', async (req, reply) => {
  const user = await requireUser(req, reply);
  if (!user) return;
  return views.modelsPage(user, listModels({ enabledOnly: false }), listProviders());
});
app.get('/models', async (req, reply) => {
  const user = await currentUser(req);
  if (!user) return reply.redirect('/login');
  return views.modelsPage(user, listModels({ enabledOnly: false }), listProviders());
});
app.get('/dashboard/logs', async (req, reply) => {
  const user = await requireUser(req, reply);
  if (!user) return;
  const rows = getDb().prepare(`SELECT r.*, r.input_tokens inTok, r.output_tokens outTok, k.name key_name, k.key_prefix
    FROM requests r LEFT JOIN api_keys k ON k.id = r.api_key_id
    WHERE r.user_id = ? ORDER BY r.created_at DESC LIMIT 100`).all(user.id);
  return views.logs(user, rows);
});
app.get('/dashboard/playground', async (req, reply) => {
  const user = await requireUser(req, reply);
  if (!user) return;
  return views.playground(user, listModels({ enabledOnly: false }));
});
// Playground: session-authenticated console route that executes the SAME
// gateway pipeline as /v1 (validation → router → adapter) without ever
// exposing a user's secret API key to the browser.
app.post('/api/playground', async (req, reply) => {
  const user = await currentUser(req);
  if (!user) return sendErr(reply, 401, 'Sign in required.', 'auth_error', 'unauthorized');
  const { model, messages, prompt, temperature, max_tokens, top_p, stop, stream } = req.body || {};
  const modelId = model || 'deepseek-v4.1-flash';
  const msgs = Array.isArray(messages) ? messages
    : (typeof prompt === 'string' && prompt.trim() ? [{ role: 'user', content: prompt.trim() }] : []);
  const out = await runGateway({
    req, reply, user, keyId: null,
    body: { model: modelId, messages: msgs, temperature, max_tokens, top_p, stop, stream: stream === true },
    via: 'playground',
  });
  return out === undefined ? reply : out;
});

app.get('/dashboard/usage', async (req, reply) => {
  const user = await requireUser(req, reply);
  if (!user) return;
  return views.usagePage(user, userStats(user.id));
});
app.get('/dashboard/billing', async (req, reply) => {
  const user = await requireUser(req, reply);
  if (!user) return;
  const sub = ensureSubscription(user.id, user.plan);
  const plans = getDb().prepare('SELECT * FROM plans ORDER BY requests_per_day').all();
  const usage = {
    reqs: getDb().prepare('SELECT COUNT(*) c FROM requests WHERE user_id=? AND created_at>=?').get(user.id, dayStartIso()).c,
    toks: getDb().prepare('SELECT COALESCE(SUM(total_tokens),0) t FROM requests WHERE user_id=? AND created_at>=?').get(user.id, dayStartIso()).t,
  };
  return views.billing(user, sub, getPlan(user.plan), plans, usage);
});
app.get('/dashboard/settings', async (req, reply) => {
  const user = await requireUser(req, reply);
  if (!user) return;
  const q = req.query || {};
  return views.settings(user, q.ok ? 'Saved.' : null, q.err || null);
});
app.post('/dashboard/settings/profile', async (req, reply) => {
  const user = await requireUser(req, reply);
  if (!user) return;
  const name = String(req.body?.name || '').trim().slice(0, 80);
  getDb().prepare('UPDATE users SET name = ? WHERE id = ?').run(name || null, user.id);
  audit({ userId: user.id, action: 'user.profile_update', ip: req.ip });
  return reply.redirect('/dashboard/settings?ok=1');
});
app.post('/dashboard/settings/password', async (req, reply) => {
  const user = await requireUser(req, reply);
  if (!user) return;
  const bcrypt = require('bcryptjs');
  if (!req.body?.password || String(req.body.password).length < 8) {
    return reply.redirect('/dashboard/settings?err=' + encodeURIComponent('Password must be at least 8 characters.'));
  }
  getDb().prepare('UPDATE users SET password_hash=? WHERE id=?').run(bcrypt.hashSync(String(req.body.password), 10), user.id);
  audit({ userId: user.id, action: 'user.password_change', ip: req.ip });
  return reply.redirect('/dashboard/settings?ok=1');
});

// ---------- legacy console paths → new IA (redirects) ----------
for (const [oldPath, target] of [
  ['/keys', '/dashboard/api-keys'],
  ['/logs', '/dashboard/logs'],
  ['/playground', '/dashboard/playground'],
  ['/usage', '/dashboard/usage'],
  ['/billing', '/dashboard/billing'],
  ['/plan', '/dashboard/billing'],
  ['/settings', '/dashboard/settings'],
]) {
  app.get(oldPath, async (req, reply) => reply.redirect(target));
}

app.get('/sdk', async () => views.sdk());
app.get('/examples', async () => views.examples());

// ---------- docs ----------
app.get('/docs', async (req, reply) => reply.redirect('/docs/introduction'));
app.get('/docs/:slug', async (req, reply) => {
  const page = docsPage(req.params.slug);
  if (!page) return reply.code(404).type('text/html').send('<h1>404</h1><p>Doc not found. <a href="/docs">All docs</a></p>');
  return page;
});
app.get('/docs.json', async () => ({
  base_url: config.publicApiBaseUrl,
  pages: Object.entries(DOCS).map(([slug, d]) => ({ slug, title: d.title, phase2: d.phase2 })),
}));

// ============================================================
// Gateway — Phase 2: real OpenAI-compatible AI gateway.
// server.js owns the pipeline (auth → validation → limits → usage);
// provider HTTP lives ONLY in src/providers.js adapters.
// ============================================================
function authenticateGateway(req) {
  const h = req.headers.authorization || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return { error: 'missing' };
  const token = m[1].trim();
  // Format gate first so malformed values fail identically to unknown ones
  // (no oracle for whether a partial key exists).
  if (!/^sk-cm-live-[A-Za-z0-9_-]{10,}$/.test(token)) return { error: 'invalid' };
  const row = getDb().prepare(`SELECT k.*, u.email, u.plan, u.id AS uid FROM api_keys k
    JOIN users u ON u.id = k.user_id WHERE k.key_hash = ?`).get(hashSecret(token));
  if (!row || row.status !== 'active') return { error: 'invalid' };
  return { key: row, user: { id: row.uid, email: row.email, plan: row.plan } };
}

// Parse + validate the chat request BEFORE any rate-limit, quota, or
// upstream contact. Returns { ok, value } or { ok:false, status, message, type, code, param }.
function validateChatBody(body) {
  const g = config.gateway;
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    return { ok: false, status: 400, message: 'Request body must be a JSON object.', type: 'invalid_request_error', code: 'invalid_request', param: null };
  }
  const { model, messages, stream, temperature, max_tokens, top_p, stop } = body;
  if (typeof model !== 'string' || !model.trim() || model.length > 128) {
    return { ok: false, status: 400, message: "Field 'model' is required and must be a string.", type: 'invalid_request_error', code: 'invalid_request', param: 'model' };
  }
  if (!Array.isArray(messages) || messages.length === 0) {
    return { ok: false, status: 400, message: "Field 'messages' must be a non-empty array.", type: 'invalid_request_error', code: 'invalid_request', param: 'messages' };
  }
  if (messages.length > g.maxMessages) {
    return { ok: false, status: 400, message: `Field 'messages' exceeds the ${g.maxMessages}-message limit.`, type: 'invalid_request_error', code: 'invalid_request', param: 'messages' };
  }
  const clean = [];
  let totalChars = 0;
  for (let i = 0; i < messages.length; i++) {
    const m = messages[i];
    if (!m || typeof m !== 'object' || Array.isArray(m)) {
      return { ok: false, status: 400, message: `messages[${i}] must be an object with {role, content}.`, type: 'invalid_request_error', code: 'invalid_request', param: 'messages' };
    }
    if (!['system', 'user', 'assistant', 'tool'].includes(m.role)) {
      return { ok: false, status: 400, message: `messages[${i}].role must be system, user, assistant, or tool.`, type: 'invalid_request_error', code: 'invalid_request', param: 'messages' };
    }
    if (typeof m.content !== 'string') {
      return { ok: false, status: 400, message: `messages[${i}].content must be a string.`, type: 'invalid_request_error', code: 'invalid_request', param: 'messages' };
    }
    if (m.content.length > g.maxContentChars) {
      return { ok: false, status: 400, message: `messages[${i}].content exceeds the ${g.maxContentChars}-character limit.`, type: 'invalid_request_error', code: 'context_length_exceeded', param: 'messages' };
    }
    totalChars += m.content.length;
    if (totalChars > g.maxTotalChars) {
      return { ok: false, status: 400, message: `Total message content exceeds the ${g.maxTotalChars}-character limit.`, type: 'invalid_request_error', code: 'context_length_exceeded', param: 'messages' };
    }
    clean.push({ role: m.role, content: m.content });
  }
  if (stream !== undefined && typeof stream !== 'boolean') {
    return { ok: false, status: 400, message: "Field 'stream' must be a boolean.", type: 'invalid_request_error', code: 'invalid_request', param: 'stream' };
  }
  if (temperature !== undefined && (typeof temperature !== 'number' || Number.isNaN(temperature) || temperature < 0 || temperature > 2)) {
    return { ok: false, status: 400, message: "Field 'temperature' must be a number between 0 and 2.", type: 'invalid_request_error', code: 'invalid_request', param: 'temperature' };
  }
  if (max_tokens !== undefined && (!Number.isInteger(max_tokens) || max_tokens < 1 || max_tokens > 128000)) {
    return { ok: false, status: 400, message: "Field 'max_tokens' must be an integer between 1 and 128000.", type: 'invalid_request_error', code: 'invalid_request', param: 'max_tokens' };
  }
  if (top_p !== undefined && (typeof top_p !== 'number' || Number.isNaN(top_p) || top_p <= 0 || top_p > 1)) {
    return { ok: false, status: 400, message: "Field 'top_p' must be a number in (0, 1].", type: 'invalid_request_error', code: 'invalid_request', param: 'top_p' };
  }
  if (stop !== undefined) {
    const okStop = typeof stop === 'string' || (Array.isArray(stop) && stop.length <= 4 && stop.every((s) => typeof s === 'string'));
    if (!okStop) {
      return { ok: false, status: 400, message: "Field 'stop' must be a string or an array of up to 4 strings.", type: 'invalid_request_error', code: 'invalid_request', param: 'stop' };
    }
  }
  return {
    ok: true,
    value: {
      model: model.trim(), messages: clean, stream: stream === true,
      temperature, maxTokens: max_tokens, topP: top_p, stop,
    },
  };
}

function gatewayError(reply, requestId, { status, message, type, code, param, retryAfter }) {
  const rid = requestId || newRequestId();
  reply.header('X-Request-ID', rid);
  if (retryAfter) reply.header('Retry-After', String(retryAfter));
  const extra = { ...(param ? { param } : {}), request_id: rid };
  return sendErr(reply, status, message, type, code, extra);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Attempt one adapter call (non-stream), recording a provider_attempt row.
// Returns { ok, result } or { ok:false, error }.
async function attemptOnce({ requestId, adapter, upstreamModel, chatReq, attemptNo, signal, timeoutMs }) {
  const t0 = Date.now();
  try {
    const result = await adapter.chatCompletion({ ...chatReq, model: upstreamModel, timeoutMs, signal });
    logAttempt({ requestId, provider: adapter.name, model: upstreamModel, status: 'success', latencyMs: Date.now() - t0, attemptNo });
    return { ok: true, result };
  } catch (e) {
    const code = e && e.code ? e.code : 'provider_error';
    logAttempt({ requestId, provider: adapter.name, model: upstreamModel, status: 'error', errorCode: code, latencyMs: Date.now() - t0, attemptNo });
    return { ok: false, error: e };
  }
}

// Shared gateway pipeline for /v1/chat/completions AND /api/playground.
// Order: request-id → validation → registry → rate/quota → adapter (+retry,
// +fallback for transient failures only) → usage → OpenAI-compatible output.
// Non-stream returns the response object (undefined for stream: already written).
async function runGateway({ req, reply, user, keyId, body, via }) {
  const t0 = Date.now();
  const requestId = sanitizeRequestId(req.headers['x-request-id']) || newRequestId();
  reply.header('X-Request-ID', requestId);

  const v = validateChatBody(body);
  if (!v.ok) {
    logEvent({ level: 'warn', msg: 'gateway validation failed', request_id: requestId, code: v.code, via });
    if (keyId && v.code === 'context_length_exceeded') {
      // Count abusive oversize attempts against quota without contacting upstream.
      logUsage({ requestId, userId: user.id, keyId, modelId: String((body || {}).model || 'unknown'), provider: 'none', latencyMs: Date.now() - t0, status: 'error', errorCode: v.code });
    }
    return gatewayError(reply, requestId, v);
  }
  const chat = v.value;

  const router = getRouter();
  const resolved = router.resolve(chat.model);
  if (resolved.error === 'model_not_found') {
    return gatewayError(reply, requestId, {
      status: 404, message: `Model '${chat.model}' not found. See GET /v1/models.`,
      type: 'invalid_request_error', code: 'model_not_found', param: 'model',
    });
  }
  if (resolved.error === 'provider_not_connected' || !resolved.adapter) {
    logUsage({ requestId, userId: user.id, keyId, modelId: chat.model, provider: (resolved.entry && resolved.entry.provider) || 'none', latencyMs: Date.now() - t0, status: 'error', errorCode: 'provider_not_connected' });
    const name = resolved.entry ? resolved.entry.provider : 'provider';
    return gatewayError(reply, requestId, {
      status: 503, message: `The '${name}' provider is not connected yet. AI inference activates once provider credentials are configured.`,
      type: 'service_unavailable', code: 'provider_not_connected', param: 'model',
    });
  }
  const { entry, adapter } = resolved;

  // Rate limit + quota BEFORE any upstream contact.
  const plan = getPlan(user.plan);
  const rate = checkRate({ backend: limiter, userId: user.id, keyId: keyId || `session:${user.id}`, modelId: chat.model, ip: req.ip, rpm: plan.rpm });
  if (rate.limited) {
    logUsage({ requestId, userId: user.id, keyId, modelId: chat.model, provider: entry.provider, latencyMs: Date.now() - t0, status: 'error', errorCode: 'rate_limit_exceeded' });
    return gatewayError(reply, requestId, { status: 429, message: rate.message, type: 'rate_limit_error', code: 'rate_limit_exceeded', retryAfter: 60 });
  }
  const quota = checkQuota(getDb(), user.id, plan);
  if (quota.limited) {
    logUsage({ requestId, userId: user.id, keyId, modelId: chat.model, provider: entry.provider, latencyMs: Date.now() - t0, status: 'error', errorCode: 'insufficient_quota' });
    return gatewayError(reply, requestId, { status: 429, message: quota.message, type: 'insufficient_quota', code: 'insufficient_quota', retryAfter: 60 });
  }

  if (keyId) {
    try { getDb().prepare('UPDATE api_keys SET last_used_at=? WHERE id=?').run(new Date().toISOString(), keyId); } catch { /* ignore */ }
  }

  const upstreamModel = entry.upstream_model || entry.id || chat.model;
  const chatReq = {
    messages: chat.messages,
    maxTokens: chat.maxTokens, temperature: chat.temperature, topP: chat.topP, stop: chat.stop,
  };
  const chatId = 'cm_chat_' + requestId.replace(/^cm_req_/, '');
  const created = Math.floor(Date.now() / 1000);

  const finish = (extra = {}) => {
    logEvent({ level: 'info', msg: 'gateway request', request_id: requestId, user: user.id, model: chat.model, provider: entry.provider, stream: chat.stream, via, latency_ms: Date.now() - t0, ...extra });
  };

  // ---------------- non-streaming ----------------
  if (!chat.stream) {
    let attempt = await attemptOnce({ requestId, adapter, upstreamModel, chatReq, attemptNo: 1, timeoutMs: config.deepseek.timeoutMs });
    // Conservative retry: transient upstream failures only, non-stream only.
    if (!attempt.ok && attempt.error && attempt.error.retryable && !(attempt.error instanceof ProviderNotConnectedError)) {
      await sleep(config.gateway.retryBaseDelayMs);
      attempt = await attemptOnce({ requestId, adapter, upstreamModel, chatReq, attemptNo: 2, timeoutMs: config.deepseek.timeoutMs });
    }
    // Fallback: same transient class, configured fallback model only, single attempt.
    let servedBy = { provider: entry.provider, model: chat.model, fallback: false };
    if (!attempt.ok && attempt.error && attempt.error.retryable && entry.fallback && entry.fallback.model && entry.fallback.model !== chat.model) {
      const fb = router.resolve(entry.fallback.model);
      if (!fb.error && fb.adapter) {
        const fbModel = fb.entry.upstream_model || fb.entry.id || entry.fallback.model;
        const fbAttempt = await attemptOnce({ requestId, adapter: fb.adapter, upstreamModel: fbModel, chatReq, attemptNo: 3, timeoutMs: config.deepseek.timeoutMs });
        if (fbAttempt.ok) {
          attempt = fbAttempt;
          servedBy = { provider: fb.entry.provider, model: entry.fallback.model, fallback: true };
        }
      }
    }
    if (!attempt.ok) {
      const e = attempt.error || new ProviderError('Provider request failed.');
      const code = (e && e.code) || 'provider_error';
      // Map adapter failure class → gateway HTTP status (never leak internals).
      let status = 502;
      let type = 'server_error';
      if (e instanceof ProviderNotConnectedError) { status = 503; type = 'service_unavailable'; }
      else if (code === 'provider_timeout') { status = 504; type = 'timeout_error'; }
      else if (code === 'provider_rate_limit' || code === 'provider_unavailable') { status = 503; type = 'service_unavailable'; }
      else if (code === 'provider_authentication_error') { status = 502; type = 'server_error'; }
      logUsage({ requestId, userId: user.id, keyId, modelId: chat.model, provider: entry.provider, latencyMs: Date.now() - t0, status: 'error', errorCode: code });
      finish({ error: code });
      const messages = {
        provider_not_connected: 'The model provider is not connected yet.',
        provider_timeout: 'The model provider timed out. Please retry.',
        provider_rate_limit: 'The model provider is rate-limited. Please retry shortly.',
        provider_unavailable: 'The model provider is temporarily unavailable. Please retry.',
        provider_authentication_error: 'The gateway failed to authenticate with the model provider.',
        provider_invalid_response: 'The model provider returned an invalid response.',
      };
      return gatewayError(reply, requestId, { status, message: messages[code] || 'The model provider failed. Please retry.', type, code });
    }
    const out = attempt.result;
    const cost = estimateCost(entry, out.inputTokens, out.outputTokens);
    logUsage({
      requestId, userId: user.id, keyId, modelId: chat.model,
      provider: servedBy.fallback ? `${servedBy.provider}:fallback` : servedBy.provider,
      inputTokens: out.inputTokens || 0, outputTokens: out.outputTokens || 0,
      latencyMs: Date.now() - t0, status: 'success', estCost: cost,
    });
    finish({ fallback: servedBy.fallback || undefined });
    return {
      id: chatId, object: 'chat.completion', created, model: chat.model,
      choices: [{ index: 0, message: { role: 'assistant', content: out.content ?? '' }, finish_reason: out.finishReason || 'stop' }],
      usage: {
        prompt_tokens: out.inputTokens ?? 0,
        completion_tokens: out.outputTokens ?? 0,
        total_tokens: (out.inputTokens ?? 0) + (out.outputTokens ?? 0),
      },
      ...(cost === null ? {} : { _cost_estimate: cost }),
    };
  }

  // ---------------- SSE streaming ----------------
  // Conservative: NO retry and NO fallback once bytes are flowing (a retry
  // would double-bill upstream and corrupt the client stream).
  const ctrl = new AbortController();
  req.raw.on('close', () => { try { ctrl.abort(); } catch { /* ignore */ } });
  reply.raw.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
    'X-Request-ID': requestId,
  });
  const send = (obj) => { try { reply.raw.write(`data: ${JSON.stringify(obj)}\n\n`); } catch { /* client gone */ } };
  const chunk = (delta, finishReason) => send({
    id: chatId, object: 'chat.completion.chunk', created, model: chat.model,
    choices: [{ index: 0, delta, finish_reason: finishReason || null }],
  });
  chunk({ role: 'assistant' });
  const streamT0 = Date.now();
  let streamUsage = null;
  try {
    const out = await adapter.streamChatCompletion({
      ...chatReq,
      model: upstreamModel,
      timeoutMs: config.deepseek.timeoutMs,
      stallTimeoutMs: config.gateway.streamStallTimeoutMs,
      signal: ctrl.signal,
      onToken: async (tok) => { chunk({ content: tok }); },
      onUsage: async (u) => { streamUsage = u; },
    });
    logAttempt({ requestId, provider: adapter.name, model: upstreamModel, status: 'success', latencyMs: Date.now() - streamT0, attemptNo: 1 });
    const inT = streamUsage ? streamUsage.inputTokens : out.inputTokens;
    const outT = streamUsage ? streamUsage.outputTokens : out.outputTokens;
    const cost = estimateCost(entry, inT, outT);
    chunk({}, out.finishReason || 'stop');
    reply.raw.write('data: [DONE]\n\n');
    try { reply.raw.end(); } catch { /* ignore */ }
    logUsage({
      requestId, userId: user.id, keyId, modelId: chat.model, provider: entry.provider,
      inputTokens: inT || 0, outputTokens: outT || 0,
      latencyMs: Date.now() - t0, status: 'success', estCost: cost,
    });
    finish();
  } catch (e) {
    const code = (e && e.code) || 'provider_error';
    logAttempt({ requestId, provider: adapter.name, model: upstreamModel, status: 'error', errorCode: code, latencyMs: Date.now() - streamT0, attemptNo: 1 });
    logUsage({ requestId, userId: user.id, keyId, modelId: chat.model, provider: entry.provider, latencyMs: Date.now() - t0, status: 'error', errorCode: code });
    finish({ error: code });
    // Mid-stream errors must be OpenAI-shaped events, not HTTP status swaps.
    try {
      send({ id: chatId, object: 'chat.completion.chunk', created, model: chat.model, choices: [{ index: 0, delta: {}, finish_reason: 'error' }], error: { message: 'The model provider failed mid-stream.', code, request_id: requestId } });
      reply.raw.write('data: [DONE]\n\n');
      reply.raw.end();
    } catch { /* client gone */ }
  }
  return undefined;
}

app.get('/v1/models', async (req, reply) => {
  const auth = authenticateGateway(req);
  if (auth.error) {
    logEvent({ level: 'warn', msg: 'v1.models unauthorized' });
    return gatewayError(reply, sanitizeRequestId(req.headers['x-request-id']), {
      status: 401, message: 'Invalid or missing API key.', type: 'invalid_request_error', code: 'invalid_api_key',
    });
  }
  return { object: 'list', data: getRouter().enabledModels() };
});

app.post('/v1/chat/completions', async (req, reply) => {
  const auth = authenticateGateway(req);
  if (auth.error) {
    logEvent({ level: 'warn', msg: 'v1.chat unauthorized' });
    return gatewayError(reply, sanitizeRequestId(req.headers['x-request-id']), {
      status: 401, message: 'Invalid or missing API key.', type: 'invalid_request_error', code: 'invalid_api_key',
    });
  }
  const out = await runGateway({ req, reply, user: auth.user, keyId: auth.key.id, body: req.body, via: 'api' });
  return out === undefined ? reply : out;
});

// 404 + error shape
app.setNotFoundHandler(async (req, reply) => {
  if (req.url.startsWith('/v1/')) return sendErr(reply, 404, 'Unknown endpoint. See /docs.', 'not_found', 'not_found');
  if (req.url.startsWith('/api/')) return sendErr(reply, 404, 'Unknown endpoint.', 'not_found', 'not_found');
  return reply.code(404).type('text/html').send('<h1>404</h1><p><a href="/">CiptaModel home</a></p>');
});
app.setErrorHandler(async (err, req, reply) => {
  logEvent({ level: 'error', msg: 'unhandled', route: req.url });
  if (req.url.startsWith('/v1/') || req.url.startsWith('/api/')) {
    // Normalize Fastify parse/validation failures (e.g. malformed JSON,
    // oversize body) into the OpenAI-shaped contract; never leak stacks.
    const status = err && Number.isInteger(err.statusCode) && err.statusCode >= 400 && err.statusCode < 500 ? err.statusCode : 500;
    const code = status === 413 ? 'request_too_large' : 'invalid_request';
    const message = status === 413 ? 'Request body exceeds the size limit.'
      : status === 415 ? 'Content-Type must be application/json.'
      : status === 400 ? 'Malformed JSON request body.'
      : 'Internal server error.';
    return gatewayError(reply, sanitizeRequestId(req.headers && req.headers['x-request-id']), {
      status, message, type: status === 500 ? 'server_error' : 'invalid_request_error', code,
    });
  }
  return reply.code(500).type('text/html').send('<h1>500</h1><p>Something went wrong.</p>');
});

// ---------- boot ----------
async function start() {
  connect();
  await app.listen({ port: config.port, host: '0.0.0.0' });
  console.log(`CiptaModel listening on ${config.baseUrl} — gateway at ${config.baseUrl}/v1`);
}

if (require.main === module) {
  start().catch((e) => { console.error(e); process.exit(1); });
}

module.exports = { app, start, getRouter, setRouterOverrides, limiter, authenticateGateway, validateChatBody, estimateCost };
