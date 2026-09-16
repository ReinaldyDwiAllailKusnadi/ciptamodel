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

// HTML pages are returned as strings — serve them as text/html (Fastify
// defaults string payloads to text/plain, which browsers render as source).
app.addHook('onSend', async (req, reply, payload) => {
  if (typeof payload === 'string' && payload.startsWith('<!doctype html>')) {
    reply.header('Content-Type', 'text/html; charset=utf-8');
  }
  return payload;
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
  const secure = process.env.NODE_ENV === 'production';
  reply.setCookie('cm_session', token, { path: '/', httpOnly: true, sameSite: 'lax', secure, maxAge: 7 * 86400 });
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

// Display order: free → developer → pro → enterprise (DB has no rank column;
// requests_per_day would sort enterprise(-1) first).
const PLAN_ORDER = { free: 0, developer: 1, pro: 2, enterprise: 3 };
function orderedPlans() {
  return getDb().prepare('SELECT * FROM plans').all()
    .sort((a, b) => (PLAN_ORDER[a.name] ?? 9) - (PLAN_ORDER[b.name] ?? 9));
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
  if (!dash) return publicShell({ title, body: `<div class="wrap section tight">${body}</div>` });
  const links = DASH_NAV.map(([label, href, kind]) => kind === 'sec'
    ? `<div class="navsec">${label}</div>`
    : `<a href="${href}" class="${active === label ? 'active' : ''}"${active === label ? ' aria-current="page"' : ''}>${label}</a>`).join('');
  const side = `<aside class="sidebar" aria-label="Dashboard navigation"><div class="brand"><span class="mark">C<i>.</i></span>CiptaModel</div>
       <nav class="nav">${links}</nav>
       <div class="side-foot">${user ? `${esc(user.email)}<br><a href="/logout" style="color:#93c5fd">Sign out</a>` : '<a href="/login" style="color:#93c5fd">Sign in</a>'}</div></aside>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#08111F">
<title>${esc(title)} · CiptaModel</title><link rel="stylesheet" href="${CSS}"></head><body>
<a class="skip" href="#main">Skip to content</a>
<div class="shell">${side}
<div class="main"><div class="topbar"><button class="menu-btn" data-action="menu" aria-label="Toggle navigation">☰</button>
<strong>${esc(title)}</strong><span class="who"><span class="dot" aria-hidden="true"></span><span>Gateway <code class="inline">/v1</code> · OpenAI-compatible</span>${user ? `<span class="badge info">${esc(user.plan || 'free')}</span>` : ''}</span></div>
<main class="content" id="main">${body}</main></div></div>
<script src="/app.js" defer></script></body></html>`;
}

function publicShell({ title, body, desc }) {
  const d = desc || 'CiptaModel — one OpenAI-compatible API for multiple AI models. One key, one base URL.';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="${esc(d)}">
<meta name="theme-color" content="#08111F">
<title>${esc(title)} · CiptaModel</title><link rel="stylesheet" href="${CSS}"></head><body>
<a class="skip" href="#main">Skip to content</a>
<header class="pubnav" id="pubnav"><div class="pubnav-in"><a class="pubbrand" href="/"><span class="mark">C<i>.</i></span>Cipta<span>Model</span></a>
<button class="pubmenu-btn" data-action="pubmenu" aria-label="Toggle menu" aria-expanded="false">☰</button>
<nav aria-label="Public"><a class="navlink" href="/#how-it-works">Product</a><a class="navlink" href="/models">Models</a><a class="navlink" href="/docs">Docs</a><a class="navlink" href="/pricing">Pricing</a><a class="navlink" href="https://github.com/ReinaldyDwiAllailKusnadi/ciptamodel">GitHub</a><a class="navlink" href="/login">Sign in</a><a class="btn sm" href="/register">Get Started</a></nav></div></header>
<main id="main">${body}</main>
<footer class="pubfoot"><div class="pubfoot-in">
<div><a class="pubbrand" href="/"><span class="mark">C<i>.</i></span>Cipta<span>Model</span></a>
<p class="brandline">One OpenAI-compatible API for multiple AI models. One key, one base URL — swap providers without rewriting your integration.</p></div>
<div><h4>PRODUCT</h4><ul><li><a href="/models">Models</a></li><li><a href="/pricing">Pricing</a></li><li><a href="/dashboard">Dashboard</a></li><li><a href="/dashboard/playground">Playground</a></li></ul></div>
<div><h4>DEVELOPERS</h4><ul><li><a href="/docs">Documentation</a></li><li><a href="/docs/quickstart">Quickstart</a></li><li><a href="/sdk">SDK</a></li><li><a href="/examples">Examples</a></li><li><a href="/docs/cursor">Cursor setup</a></li><li><a href="/docs/open-webui">Open WebUI setup</a></li></ul></div>
<div><h4>CIPTAMODEL</h4><ul><li><a href="https://github.com/ReinaldyDwiAllailKusnadi/ciptamodel">GitHub</a></li><li><a href="/healthz">API status</a></li><li><a href="/login">Sign in</a></li><li><a href="/register">Get started</a></li></ul></div>
</div><div class="pubfoot-base"><span>© ${new Date().getFullYear()} CiptaModel</span><span>Gateway <code class="inline">/v1</code> · OpenAI-compatible · Base URL <code class="inline">${esc(config.publicApiBaseUrl)}</code></span></div></footer>
<script src="/app.js" defer></script></body></html>`;
}

function errPage(status, heading, msg) {
  return publicShell({ title: heading, body: `<div class="wrap"><div class="err"><div>
<p class="code">ERROR ${status}</p><h1>${esc(heading)}</h1><p>${esc(msg)}</p>
<p><a class="btn" href="/">Back home</a> &nbsp; <a class="btn ghost" href="/docs">Read the docs</a></p></div></div></div>` });
}

function phase2Badge() {
  return ' <span class="badge warn">Coming in Phase 2</span>';
}

const views = {
  landing(providers, plans) {
    const provs = providers || [];
    const chips = provs.map((pr) =>
      `<span class="pchip${pr.enabled ? ' on' : ''}">${esc(pr.name)} · ${pr.enabled ? 'enabled' : 'disabled'}</span>`).join('');
    const route = `<div class="route" aria-label="Gateway routing diagram">
<div class="route-flow">
<div class="rnode"><div class="rl">CLIENT</div><div class="rv mono">your app</div></div><span class="rarrow" aria-hidden="true">→</span>
<div class="rnode lit"><div class="rl">GATEWAY</div><div class="rv mono">ciptamodel /v1</div></div><span class="rarrow" aria-hidden="true">→</span>
<div class="rnode"><div class="rl">ROUTER</div><div class="rv mono">stable model IDs</div></div>
</div>
<div class="route-provs"><span class="route-cap">PROVIDERS</span>${chips || '<span class="pchip">—</span>'}</div></div>`;
    const planStrip = (plans || []).map((p) =>
      `<div class="plan${p.name === 'free' ? ' hot' : ''}"><h3>${esc(String(p.name).toUpperCase())}</h3>
<div class="price">${p.name === 'free' ? '$0' : 'Soon'}</div>
<ul><li>${p.requests_per_day < 0 ? 'Unlimited requests' : `${Number(p.requests_per_day).toLocaleString()} req/day`}</li>
<li>${p.tokens_per_day < 0 ? 'Unlimited tokens' : `${Number(p.tokens_per_day).toLocaleString()} tokens/day`}</li>
<li>${p.rpm < 0 ? 'No rate cap' : `${p.rpm} req/min`}</li></ul></div>`).join('');
    return publicShell({ title: 'One API. Multiple AI Models', body: `
<section class="hero-band"><div class="wrap hero-grid">
<div><p class="eyebrow">OPENAI-COMPATIBLE AI GATEWAY</p>
<h1>One API.<br>Multiple AI Models.</h1>
<p class="hero-sub">CiptaModel gives developers a single OpenAI-compatible interface for many AI models. One <code class="inline">sk-cm-…</code> key, one base URL — swap providers without rewriting your integration.</p>
<div class="hero-cta"><a class="btn lg" href="/register">Start building</a><a class="btn light lg" href="/docs">Read documentation</a></div>
<div class="hero-meta"><span><span class="dot"></span>OpenAI-compatible</span><span><span class="dot"></span>Streaming (SSE)</span><span><span class="dot"></span>X-Request-ID tracing</span></div></div>
<div class="term" role="img" aria-label="Example API request through the CiptaModel gateway">
<div class="term-bar"><span class="tdot"></span><span class="tdot"></span><span class="tdot"></span><span class="term-title">POST /v1/chat/completions</span><span class="term-live"><i></i>EXAMPLE</span></div>
<pre class="term-body"><span class="c"># one base URL, one key — any OpenAI client</span>
<span class="k">curl</span> ${esc(config.publicApiBaseUrl)}/chat/completions \\
  -H <span class="s">"Authorization: Bearer sk-cm-live-••••••••"</span> \\
  -H <span class="s">"Content-Type: application/json"</span> \\
  -d <span class="s">'{"model": "deepseek-v4.1-flash",
       "messages": [{"role": "user",
                     "content": "Hello"}]}'</span>

<span class="c"># → 200 OK · OpenAI-shaped response + usage</span>
<span class="c"># x-request-id: cm_req_… on every reply</span></pre>
<div class="term-meta"><span><span class="ok">200 OK</span> · chat.completion</span><span>usage: prompt / completion / total</span><span>stream: SSE + [DONE]</span></div>
</div></div>
<div class="wrap" style="padding-bottom:var(--s12)">${route}</div></section>

<section class="section" id="how-it-works"><div class="wrap">
<div class="section-head"><p class="kicker">HOW IT WORKS</p><h2>From key to inference in four steps.</h2>
<p>Your client only ever talks to CiptaModel. Everything behind the base URL — providers, failover, metering — is our problem.</p></div>
<div class="steps">
<div class="step"><div class="n">01</div><h3>Create an API key</h3><p>One <code class="inline">sk-cm-live-…</code> key in the dashboard. Hashed at rest, shown once.</p></div>
<div class="step"><div class="n">02</div><h3>Use one base URL</h3><p>Point any OpenAI-compatible client at the gateway base URL (<code class="inline">/v1</code>).</p></div>
<div class="step"><div class="n">03</div><h3>Select a model</h3><p>Your code never names a provider — it uses stable public IDs.</p></div>
<div class="step"><div class="n">04</div><h3>CiptaModel routes it</h3><p>Validation → router → provider adapter, with retry and fallback on transient failures.</p></div>
</div></div></section>

<section class="section split"><div class="wrap">
<div class="section-head"><p class="kicker">MODEL REGISTRY</p><h2>One API, backed by a provider registry.</h2>
<p>Public model IDs stay stable even when upstream providers change. Only enabled models accept traffic. <a href="/models">Open the registry →</a></p></div>
<div class="table-scroll"><table><tr><th scope="col">MODEL</th><th scope="col">PROVIDER</th><th scope="col">CONTEXT</th><th scope="col">STATUS</th><th scope="col">CAPABILITIES</th></tr>
${(listModelsSafe()).map((m) => `<tr><td><strong>${esc(m.display_name)}</strong><span class="sub mono">${esc(m.id)}</span></td>
<td class="mono">${esc(m.provider)}</td><td style="white-space:nowrap">${Number(m.context_window).toLocaleString()}</td>
<td>${m.enabled ? '<span class="badge ok">Available</span>' : '<span class="badge bad">Disabled</span>'}</td>
<td>${(m.capabilities || []).map((c) => `<span class="badge info">${esc(c)}</span>`).join(' ')}</td></tr>`).join('')}</table></div>
<p><small class="muted">Configured providers serve live traffic; the rest stay honestly disabled until credentials are added server-side — the API shape never changes.</small></p>
</div></section>

<section class="section"><div class="wrap">
<div class="section-head"><p class="kicker">DEVELOPER EXPERIENCE</p><h2>Change the base URL. Keep your integration.</h2>
<p>CiptaModel speaks the OpenAI API — every OpenAI SDK works unmodified, including streaming, tool calls, and standard error shapes.</p></div>
<div class="grid c2">
<div><pre>from openai import OpenAI

client = OpenAI(
    base_url="${esc(config.publicApiBaseUrl)}",
    api_key="sk-cm-live-...",
)
r = client.chat.completions.create(
    model="deepseek-v4.1-flash",
    messages=[{"role": "user",
               "content": "Hello"}],
)
print(r.choices[0].message.content)</pre></div>
<div><h3 style="margin-top:0">Works where you already work</h3>
<p class="muted" style="font-size:14px">Drop-in OpenAI-compatible clients — no plugins, no rewrites:</p>
<div class="chips"><span class="chip">Cursor</span><span class="chip">Cline / Roo Code</span><span class="chip">Claude Code</span><span class="chip">Aider</span><span class="chip">Open WebUI</span><span class="chip">Python <small>openai</small></span><span class="chip">Node.js <small>openai</small></span><span class="chip">cURL</span></div>
<ul class="seclist" style="grid-template-columns:1fr"><li><strong>Stable model IDs</strong><span>Providers change behind the scenes; your code stays the same.</span></li>
<li><strong>Streaming included</strong><span>SSE chunks in OpenAI format, terminated by data: [DONE].</span></li></ul>
<p><a class="btn ghost sm" href="/docs/quickstart">Quickstart →</a> &nbsp; <a class="btn ghost sm" href="/sdk">SDK snippets →</a></p></div>
</div></div></section>

<section class="section split"><div class="wrap">
<div class="section-head"><p class="kicker">WHY CIPTAMODEL</p><h2>Infrastructure, not another chatbot wrapper.</h2></div>
<div class="frows">
<div class="frow"><h3><span class="n">01</span>ONE API</h3><p>Unified OpenAI-compatible interface — <code class="inline">/v1/models</code>, <code class="inline">/v1/chat/completions</code>, SSE streaming, standard errors. One integration covers every provider.</p></div>
<div class="frow"><h3><span class="n">02</span>MODEL ROUTING</h3><p>Registry-driven routing with per-model fallback. Transient upstream failures retry once, then fail over to a configured fallback — providers stay swappable without client changes.</p></div>
<div class="frow"><h3><span class="n">03</span>OBSERVABILITY</h3><p>Every call records model, provider, input/output tokens, latency, status, and error code. Per-key usage, request logs, and <code class="inline">X-Request-ID</code> tracing from day one.</p></div>
<div class="frow"><h3><span class="n">04</span>SECURITY</h3><p>API-key isolation per account, server-side provider credentials, hashed secrets, rate limits, and request validation before any upstream contact.</p></div>
</div></div></section>

<section class="section"><div class="wrap">
<div class="section-head"><p class="kicker">SECURITY</p><h2>Serious defaults for API infrastructure.</h2>
<p>Verified in the running codebase — not marketing claims. Provider credentials never leave the server; gateway errors never leak secrets, stacks, or paths.</p></div>
<ul class="seclist">
<li><strong>Hashed secrets</strong><span>API keys stored as SHA-256, passwords as bcrypt. Full key shown once, never recoverable.</span></li>
<li><strong>Server-side credentials</strong><span>Provider API keys live in server config only — never in logs, errors, DB, or browser.</span></li>
<li><strong>Key isolation</strong><span>Keys are scoped per account; revoked keys fail closed with 401.</span></li>
<li><strong>Rate limits + quotas</strong><span>Per key, user, IP, and model — plus daily request/token quotas per plan.</span></li>
<li><strong>Request validation first</strong><span>Bodies validated before any rate-limit, quota, or upstream contact.</span></li>
<li><strong>SSRF-safe by construction</strong><span>Clients can never supply a fetch URL; adapters use fixed server-side endpoints.</span></li>
<li><strong>Secure sessions + CSRF</strong><span>HttpOnly, SameSite=Lax cookies (Secure in production) with per-session CSRF tokens.</span></li>
<li><strong>Traceable errors</strong><span>OpenAI-shaped errors with request_id + X-Request-ID header on every gateway reply.</span></li>
</ul></div></section>

<section class="section split"><div class="wrap">
<div class="section-head"><p class="kicker">PRICING</p><h2>Start free. Upgrade when usage grows.</h2>
<p>Quotas are enforced per plan — no surprise bills. Platform pricing below; per-model metering activates with billing. <a href="/pricing">Full details →</a></p></div>
<div class="plans">${planStrip}</div>
</div></section>

<section class="section"><div class="wrap">
<div class="section-head"><p class="kicker">FAQ</p><h2>Honest answers.</h2></div>
<div class="faq">
<details open><summary>Is the API live?</summary><p>Yes — <code class="inline">POST /v1/chat/completions</code> proxies real DeepSeek inference when <code class="inline">DEEPSEEK_API_KEY</code> is configured server-side. Without provider credentials it returns an honest <code class="inline">503 provider_not_connected</code> instead of a fake reply.</p></details>
<details><summary>Which clients are supported?</summary><p>Anything speaking OpenAI-compatible HTTP: Cursor, Cline, Roo Code, Claude Code, Aider, Open WebUI, and the official OpenAI SDKs. Setup guides live in <a href="/docs">Docs</a>.</p></details>
<details><summary>Can I change providers later?</summary><p>Yes — that is the point. Your client talks to CiptaModel; the router picks the provider. Model IDs stay stable.</p></details>
</div></div></section>

<section class="section tight"><div class="wrap">
<div class="cta-band"><div class="grow"><h2>One endpoint. Multiple models. Built for developers.</h2>
<p>Free tier included · No credit card required · Live in minutes</p></div>
<div class="row-btns"><a class="btn lg" href="/register">Get started</a><a class="btn light lg" href="/docs">Read the docs</a></div></div>
</div></section>` });
  },

  pricing(plans) {
    const cards = plans.map((p) => {
      const name = String(p.name).toUpperCase();
      const req = p.requests_per_day < 0 ? 'Unlimited requests' : `${Number(p.requests_per_day).toLocaleString()} req/day`;
      const tok = p.tokens_per_day < 0 ? 'Unlimited tokens' : `${Number(p.tokens_per_day).toLocaleString()} tokens/day`;
      const rpm = p.rpm < 0 ? 'no rate cap' : `${p.rpm}/min`;
      return `<div class="plan${p.name === 'free' ? ' hot' : ''}"><h3>${esc(name)}${p.name === 'free' ? ' · CURRENT DEFAULT' : ''}</h3>
<div class="price">${p.name === 'free' ? '$0' : 'Soon'}</div>
<ul><li>${req}</li><li>${tok}</li><li>${rpm}</li></ul></div>`;
    }).join('');
    return publicShell({ title: 'Pricing', body: `
<div class="wrap section"><div class="section-head"><p class="kicker">PRICING</p><h2>Start free. Upgrade when your usage grows.</h2>
<p>Quotas are enforced per plan — no surprise bills. These are platform quotas; per-model metered costs activate with billing.</p></div>
<div class="plans">${cards}</div>
<div class="grid c2" style="margin-top:var(--s8)">
<div class="card"><h3>PLATFORM VS MODEL COSTS</h3><p class="muted" style="font-size:14px;margin:0">Plans above control gateway throughput (requests, tokens, rate). Individual model prices are tracked in the registry and appear as cost estimates on responses once billing activates.</p></div>
<div class="card"><h3>CURRENT STATE</h3><p class="muted" style="font-size:14px;margin:0 0 12px">Payments activate after Phase 1. Your plan, quota, and usage are already tracked in the dashboard.</p><p style="margin:0"><a class="btn sm" href="/register">Start free</a> &nbsp; <a class="btn ghost sm" href="/dashboard/billing">Open billing</a></p></div>
</div></div>` });
  },

  auth(mode, error) {
    const isReg = mode === 'register';
    return layout({ title: isReg ? 'Create account' : 'Sign in', user: null, active: '', dash: false, body: `
<div class="auth-card"><h1>${isReg ? 'Create your account' : 'Welcome back'}</h1>
<p class="sub">${isReg ? 'Free tier included. No credit card required.' : 'Sign in to your CiptaModel console.'}</p>
${error ? `<div class="alert bad" role="alert">${esc(error)}</div>` : ''}
<form method="post" action="/${mode}">
<label for="email">Email</label><input id="email" type="email" name="email" required autocomplete="email" placeholder="you@company.com">
<label for="password">Password${isReg ? ' <span class="muted" style="font-weight:400">(min 8 characters)</span>' : ''}</label><input id="password" type="password" name="password" required minlength="8" autocomplete="${isReg ? 'new-password' : 'current-password'}" placeholder="••••••••••">
<p style="margin-top:16px"><button class="btn" style="width:100%" type="submit">${isReg ? 'Create account' : 'Sign in'}</button></p>
<p><small class="muted">${isReg ? 'Have an account? <a href="/login">Sign in</a>' : 'New here? <a href="/register">Create an account</a>'}</small></p>
</form></div>` });
  },

  dashboard(user, s, providers) {
    const stat = (l, v, sub) => `<div class="stat-cell"><div class="l">${l}</div><div class="v">${v}</div><div class="s">${sub}</div></div>`;
    const badgeFor = (st) => st === 'connected' || st === 'configured'
      ? `<span class="badge ok">${esc(st)}</span>`
      : (st === 'not_configured' || st === 'pending_credentials' ? `<span class="badge warn">${esc(st)}</span>` : `<span class="badge dim">${esc(st)}</span>`);
    const provRows = providers.map((p) =>
      `<tr><td><strong>${esc(p.display_name)}</strong><span class="sub mono">${esc(p.name)}</span></td>
       <td>${p.enabled ? '<span class="badge info">Enabled</span>' : '<span class="badge dim">Disabled</span>'}</td>
       <td>${badgeFor(p.status)}</td></tr>`).join('');
    const recent = (s.recent || []).map((r) => `<tr><td class="mono"><small>${esc(r.created_at)}</small></td>
<td class="mono">${esc(r.model_id)}</td><td>${r.total_tokens}</td>
<td>${r.status === 'success' ? '<span class="badge ok">ok</span>' : `<span class="badge bad">${esc(r.error_code || r.status)}</span>`}</td></tr>`).join('');
    return layout({ title: 'Dashboard', user, active: 'Dashboard', body: `
<h1>Dashboard</h1><p class="sub">Plan <span class="badge info">${esc(user.plan)}</span> · Gateway <code class="inline">${esc(config.publicApiBaseUrl)}</code></p>
<div class="stats">
${stat('Total requests', s.total ?? 0, 'logged gateway calls')}
${stat('Total tokens', Number(s.tokens ?? 0).toLocaleString(), 'input + output')}
${stat('Active API keys', s.activeKeys ?? 0, '<a href="/dashboard/api-keys">manage keys →</a>')}
${stat('Error rate', (s.errRate ?? '0%'), 'failed / total · p50 ' + (s.p50 ?? '—') + ' ms')}
</div>
<div class="grid c2">
<div class="card"><div class="panel-head"><h3>SYSTEM STATUS — PROVIDERS</h3></div>
<div class="table-scroll"><table style="min-width:0"><tr><th scope="col">PROVIDER</th><th scope="col">REGISTRY</th><th scope="col">CONNECTION</th></tr>${provRows}</table></div>
<p><small class="muted">Live DeepSeek adapter when <code class="inline">DEEPSEEK_API_KEY</code> is configured server-side, otherwise honest <code class="inline">503 provider_not_connected</code> — statuses flip without API changes.</small></p></div>
<div class="card"><div class="panel-head"><h3>RECENT REQUESTS</h3><span class="spacer" style="flex:1"></span><a href="/dashboard/logs"><small>All logs →</small></a></div>
${recent ? `<div class="table-scroll"><table><tr><th scope="col">TIME</th><th scope="col">MODEL</th><th scope="col">TOKENS</th><th scope="col">STATUS</th></tr>${recent}</table></div>`
  : '<div class="empty"><strong>No requests yet</strong>Logs will appear here once the gateway is used.</div>'}</div>
</div>` });
  },

  keys(user, keys, usageByKey, newSecret) {
    const rows = keys.map((k) => {
      const u = (usageByKey || {})[k.id] || { n: 0, t: 0 };
      return `<tr>
<td><strong>${esc(k.name)}</strong><span class="sub">${esc(shortId(k.id))} · created ${esc((k.created_at || '').slice(0, 10))}</span></td>
<td class="mono">${esc(maskKey(k.key_prefix))}</td>
<td>${Number(u.n).toLocaleString()} req<span class="sub">${Number(u.t).toLocaleString()} tok</span></td>
<td>${timeAgo(k.last_used_at)}</td>
<td>${k.status === 'active' ? '<span class="badge ok">Active</span>' : '<span class="badge bad">Revoked</span>'}</td>
<td>${k.status === 'active'
  ? `<form method="post" action="/dashboard/api-keys/${k.id}/revoke" style="display:inline" data-confirm="Revoke this key? Integrations using it will stop working."><input type="hidden" name="_csrf" value="${esc(user.csrf || '')}"><button class="btn danger sm">Revoke</button></form>`
  : `<form method="post" action="/dashboard/api-keys/${k.id}/delete" style="display:inline" data-confirm="Permanently delete this key record?"><input type="hidden" name="_csrf" value="${esc(user.csrf || '')}"><button class="btn ghost sm">Delete</button></form>`}</td>
</tr>`;
    }).join('');
    return layout({ title: 'API Keys', user, active: 'API Keys', body: `
<h1>API Keys</h1>
<p class="sub">Create keys for Cursor, Cline, Open WebUI, or any OpenAI-compatible client. Secrets are SHA-256 hashed and shown once.</p>
${newSecret ? `<div class="alert warn" role="alert"><strong>Copy this key now — it is shown in full only once.</strong> Afterwards only the masked value is visible.</div>
<div class="secret-box"><code>${esc(newSecret)}</code>
<button class="btn sm" data-action="copy" data-copy="${esc(newSecret)}" data-label="Copy">Copy</button></div><br>` : ''}
<div class="card"><div class="panel-head"><h3>CREATE KEY</h3></div>
<form method="post" action="/dashboard/api-keys" class="row" aria-label="Create API key"><input type="hidden" name="_csrf" value="${esc(user.csrf || '')}"><label class="sr" for="keyname">Key name</label><input id="keyname" type="text" name="name" placeholder="Key name, e.g. Cursor Development" required maxlength="80" style="max-width:280px;flex:1"><button class="btn">+ Create new key</button></form></div><br>
<div class="table-scroll"><table><tr><th scope="col">KEY NAME</th><th scope="col">API KEY</th><th scope="col">USAGE</th><th scope="col">LAST USED</th><th scope="col">STATUS</th><th scope="col">ACTIONS</th></tr>
${rows || '<tr><td colspan="6"><div class="empty"><strong>No API keys yet.</strong> Create your first key to start using the gateway.</div></td></tr>'}</table></div>
<p><small class="muted">Secrets can never be recovered after this page. Quotas follow your <a href="/dashboard/billing">plan</a>.</small></p>` });
  },

  modelsPage(user, models, providers) {
    const provName = Object.fromEntries(providers.map((p) => [p.name, p]));
    const rows = models.map((m) => {
      const p = provName[m.provider];
      const conn = p ? p.status : 'unknown';
      return `<tr><td><strong>${esc(m.display_name)}</strong><span class="sub mono">${esc(m.id)}${m.fallback ? ` · fallback → ${esc(m.fallback.model)}` : ''}</span><span class="sub">${esc(m.description || '')}</span></td>
<td class="mono">${esc(m.provider)}<span class="sub">${esc(conn)}</span></td>
<td>${Number(m.context_window).toLocaleString()}<span class="sub">max out ${Number(m.max_output_tokens).toLocaleString()}</span></td>
<td>${(m.capabilities || []).map((c) => `<span class="badge info">${esc(c)}</span>`).join(' ')}</td>
<td><small class="mono">in $${m.price_input_per_1k}/1K<br>out $${m.price_output_per_1k}/1K</small></td>
<td>${m.enabled ? '<span class="badge ok">Available</span>' : '<span class="badge bad">Disabled</span>'}</td></tr>`;
    }).join('');
    return layout({ title: 'Models', user, active: 'Models', body: `
<h1>Models</h1><p class="sub">Registry data — public model IDs stay stable even when upstream providers change. Only enabled models accept traffic.</p>
<div class="table-scroll"><table><tr><th scope="col">MODEL</th><th scope="col">PROVIDER</th><th scope="col">CONTEXT</th><th scope="col">CAPABILITIES</th><th scope="col">PRICING</th><th scope="col">STATUS</th></tr>
${rows || '<tr><td colspan="6"><div class="empty"><strong>No models in registry.</strong></div></td></tr>'}</table></div>
<p><small class="muted">Prices are registry values per 1K tokens; metered billing activates with payments. Disabled providers return honest <code class="inline">503 provider_not_connected</code>.</small></p>` });
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
${tr ? `<div class="table-scroll"><table><tr><th scope="col">TIMESTAMP</th><th scope="col">REQUEST</th><th scope="col">API KEY</th><th scope="col">MODEL</th><th scope="col">PROVIDER</th><th scope="col">TOKENS</th><th scope="col">LATENCY</th><th scope="col">STATUS</th></tr>${tr}</table></div>`
  : '<div class="empty"><strong>No requests logged yet.</strong>Logs will appear here after the API is used — nothing is fabricated.</div>'}` });
  },

  playground(user, models) {
    const opts = models.filter((m) => m.enabled).map((m) => `<option value="${esc(m.id)}">${esc(m.id)}</option>`).join('') || '<option value="" disabled selected>No enabled models</option>';
    return layout({ title: 'Playground', user, active: 'Playground', body: `
<h1>Playground</h1><p class="sub">Developer test console — runs the same gateway pipeline as <code class="inline">/v1</code> using your signed-in session (no API key needed in the browser). <span class="pg-meta" id="pgmeta"></span></p>
<meta name="csrf-token" content="${esc(user.csrf || '')}">
<form id="pgform" aria-label="Playground"><div class="pg">
<div class="pg-side">
<label for="pgmodel">Model</label><select id="pgmodel" name="model">${opts}</select>
<label for="pgtemp">Temperature <span class="muted" style="font-weight:400">(0–2)</span></label><input id="pgtemp" type="number" name="temperature" min="0" max="2" step="0.1" value="0.7">
<label for="pgmax">Max tokens</label><input id="pgmax" type="number" name="max_tokens" min="1" max="32000" value="512">
<label for="pgsys">System prompt <span class="muted" style="font-weight:400">(optional)</span></label><textarea id="pgsys" name="system" rows="2" placeholder="You are concise."></textarea>
<label style="display:flex;align-items:center;gap:8px;font-weight:400;margin-top:14px"><input type="checkbox" name="stream" checked style="width:auto"> Stream tokens (SSE)</label>
<p class="field-hint">Same validation, rate limits, and router as the API. Usage is logged to your account.</p></div>
<div class="pg-main">
<div class="chatlog" id="chatlog" aria-live="polite"><div class="msg sys">Send a prompt below. Responses stream token-by-token when the provider is connected; usage is logged to your account.</div></div>
<div class="pg-input"><label class="sr" for="pgprompt">Prompt</label><input id="pgprompt" type="text" name="prompt" placeholder="Type a prompt…" required autocomplete="off"><button class="btn" type="submit">Send</button></div>
</div></div></form>` });
  },

  billing(user, sub, plan, plans, usage) {
    const cards = plans.map((p) => {
      const cur = p.name === sub.plan;
      return `<div class="plan${cur ? ' hot' : ''}"><h3>${esc(p.name.toUpperCase())}${cur ? ' · CURRENT' : ''}</h3>
<div class="price">${p.requests_per_day < 0 ? 'Unlimited' : Number(p.requests_per_day).toLocaleString() + '/day'}</div>
<ul><li>${p.tokens_per_day < 0 ? 'Unlimited tokens' : Number(p.tokens_per_day).toLocaleString() + ' tokens/day'}</li><li>${p.rpm < 0 ? 'no rate cap' : p.rpm + '/min'}</li></ul></div>`;
    }).join('');
    return layout({ title: 'Billing', user, active: 'Plan', body: `
<h1>Billing</h1><p class="sub">Plan, usage, and limits. Payments are not yet enabled — the schema already tracks plan, quota, usage, and subscription status.</p>
<div class="grid c2">
<div class="card"><h3>CURRENT PLAN</h3><div class="stat" style="font-size:26px;font-weight:750">${esc(sub.plan)}</div><small class="muted">Status: ${esc(sub.status)} · Used today: ${usage.reqs} req / ${Number(usage.toks).toLocaleString()} tokens</small></div>
<div class="card"><h3>UPGRADE</h3><p class="muted" style="font-size:14px">Self-serve upgrades and usage-based invoicing land after Phase 1. Contact us to change plans meanwhile.</p><p style="margin:0"><a class="btn ghost sm" href="/pricing">Compare plans</a></p></div>
</div><br><div class="plans">${cards}</div>` });
  },

  usagePage(user, s) {
    const stat = (l, v, sub) => `<div class="stat-cell"><div class="l">${l}</div><div class="v">${v}</div><div class="s">${sub || ''}</div></div>`;
    const rows = (s.daily || []).map((r) =>
      `<tr><td class="mono">${esc(r.d)}</td><td>${r.n}</td><td>${Number(r.t).toLocaleString()}</td></tr>`).join('');
    const byModel = (s.byModel || []).map((r) =>
      `<tr><td class="mono">${esc(r.model_id)}</td><td>${r.n}</td><td>${Number(r.i).toLocaleString()}</td><td>${Number(r.o).toLocaleString()}</td><td>${Number(r.t).toLocaleString()}</td></tr>`).join('');
    const byKey = (s.byKey || []).map((r) =>
      `<tr><td><strong>${esc(r.name)}</strong> <small class="mono">${esc(maskKey(r.key_prefix))}</small></td><td>${r.n}</td><td>${Number(r.t).toLocaleString()}</td></tr>`).join('');
    const empty = '<div class="empty"><strong>No data yet</strong>Metrics populate automatically once the gateway is used.</div>';
    return layout({ title: 'Usage', user, active: 'Usage', body: `
<h1>Usage</h1><p class="sub">Requests, tokens, cost estimate, and breakdowns on your account. Nothing here is fabricated.</p>
<div class="stats">
${stat('REQUESTS', s.total, s.month + ' this month')}
${stat('INPUT TOKENS', Number(s.inTok).toLocaleString(), '')}
${stat('OUTPUT TOKENS', Number(s.outTok).toLocaleString(), '')}
${stat('EST. COST', '$0.00', 'metered pricing activates with billing')}
</div>
<div class="card"><div class="panel-head"><h3>USAGE BY MODEL</h3></div>${byModel ? `<div class="table-scroll"><table><tr><th scope="col">MODEL</th><th scope="col">REQUESTS</th><th scope="col">IN</th><th scope="col">OUT</th><th scope="col">TOTAL</th></tr>${byModel}</table></div>` : empty}</div><br>
<div class="card"><div class="panel-head"><h3>USAGE BY API KEY</h3></div>${byKey ? `<div class="table-scroll"><table><tr><th scope="col">KEY</th><th scope="col">REQUESTS</th><th scope="col">TOKENS</th></tr>${byKey}</table></div>` : empty}</div><br>
<div class="card"><div class="panel-head"><h3>DAILY (14 DAYS)</h3></div>${rows ? `<div class="table-scroll"><table><tr><th scope="col">DATE</th><th scope="col">REQUESTS</th><th scope="col">TOKENS</th></tr>${rows}</table></div>` : empty}</div>` });
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
<p class="field-hint">Email identifies your account and cannot be changed here.</p>
<p><button class="btn" type="submit">Save profile</button></p></form></div>
<div class="card"><h3>SECURITY</h3>
<form method="post" action="/dashboard/settings/password" class="form-narrow">
<input type="hidden" name="_csrf" value="${esc(user.csrf || '')}">
<label for="setpass">New password (min 8 chars)</label><input id="setpass" type="password" name="password" minlength="8" required autocomplete="new-password">
<p><button class="btn" type="submit">Update password</button></p></form>
<p><small class="muted">Sessions expire after 7 days. Passwords are bcrypt-hashed; API keys are SHA-256 hashed.</small></p></div>
</div>` });
  },

  sdk() {
    return layout({ title: 'SDK', user: null, active: 'SDK', dash: false, body: `
<div class="docpage-head"><p class="kicker">SDK</p><h1>Any OpenAI SDK works.</h1>
<p class="sub" style="margin:0">CiptaModel speaks the OpenAI API — point the base URL at us and keep your code.</p></div>
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
<div class="docpage-head"><p class="kicker">EXAMPLES</p><h1>Copy-paste recipes.</h1>
<p class="sub" style="margin:0">cURL, streaming, and model listing against the live gateway.</p></div>
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

  publicModels(models, providers) {
    const provName = Object.fromEntries((providers || []).map((pr) => [pr.name, pr]));
    const rows = (models || []).map((m) => {
      return `<tr><td><strong>${esc(m.display_name)}</strong><span class="sub mono">${esc(m.id)}</span><span class="sub">${esc(m.description || '')}</span></td>
<td class="mono">${esc(m.provider)}</td>
<td style="white-space:nowrap">${Number(m.context_window).toLocaleString()}<span class="sub">max out ${Number(m.max_output_tokens).toLocaleString()}</span></td>
<td>${(m.capabilities || []).map((c) => `<span class="badge info">${esc(c)}</span>`).join(' ')}</td>
<td>${m.enabled ? '<span class="badge ok">Available</span>' : '<span class="badge bad">Disabled</span>'}</td></tr>`;
    }).join('');
    return publicShell({ title: 'Models', body: `
<div class="wrap section"><div class="section-head"><p class="kicker">MODEL REGISTRY</p><h2>Models on the gateway.</h2>
<p>Public IDs stay stable even when upstream providers change. Only enabled models accept traffic. <a href="/register">Get a key →</a></p></div>
<div class="table-scroll"><table><tr><th scope="col">MODEL</th><th scope="col">PROVIDER</th><th scope="col">CONTEXT</th><th scope="col">CAPABILITIES</th><th scope="col">STATUS</th></tr>
${rows || '<tr><td colspan="5">No models in registry.</td></tr>'}</table></div>
<p><small class="muted">Full pricing, fallbacks, and per-key usage live in the <a href="/dashboard">dashboard</a> after sign-in.</small></p></div>` });
  },
};

function listModelsSafe() {
  try { return listModels({ enabledOnly: false }); } catch { return []; }
}

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
<table><tr><th scope="col">HTTP</th><th scope="col">CODE</th><th scope="col">MEANING</th></tr>
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
    `<a href="/docs/${k}" class="${k === slug ? 'active' : ''}"${k === slug ? ' aria-current="page"' : ''}>${v.title}${v.phase2 ? ' ⏳' : ''}</a>`).join('');
  return layout({ title: d.title, user: null, active: 'Documentation', dash: false, body: `
<div class="docpage-head"><p class="kicker">DOCS</p><h1>${esc(d.title)}${d.phase2 ? phase2Badge() : ''}</h1></div>
<button class="btn ghost sm docsnav-btn" data-action="docsnav" aria-expanded="false" style="margin-bottom:12px">Sections</button>
<div class="docs"><nav aria-label="Documentation sections" id="docsnav">${items}</nav><div class="doc-body">${d.body}</div></div>` });
}

// ============================================================
// Routes — public
// ============================================================
app.get('/', async () => views.landing(listProviders(), orderedPlans()));
app.get('/pricing', async () => views.pricing(orderedPlans()));

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
  const secure = process.env.NODE_ENV === 'production';
  reply.setCookie('cm_newkey', Buffer.from(secret).toString('base64url'), { path: '/', httpOnly: true, sameSite: 'lax', secure, maxAge: 120 });
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
  if (user) return views.modelsPage(user, listModels({ enabledOnly: false }), listProviders());
  return views.publicModels(listModels({ enabledOnly: false }), listProviders());
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
  const plans = orderedPlans();
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
  if (!page) return reply.code(404).type('text/html').send(errPage(404, 'Doc not found', 'That documentation page does not exist. Start from the introduction.'));
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
  return reply.code(404).type('text/html').send(errPage(404, 'Page not found', 'The page you requested does not exist.'));
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
  return reply.code(500).type('text/html').send(errPage(500, 'Something went wrong', 'An unexpected error occurred. Please retry — every gateway reply carries an X-Request-ID for support.'));
});

// ---------- boot ----------
async function start() {
  connect();
  await app.listen({ port: config.port, host: config.host });
  console.log(`CiptaModel listening on ${config.baseUrl} — gateway at ${config.baseUrl}/v1`);
}

if (require.main === module) {
  start().catch((e) => { console.error(e); process.exit(1); });
}

module.exports = { app, start, getRouter, setRouterOverrides, limiter, authenticateGateway, validateChatBody, estimateCost };
