'use strict';
// Phase 1 platform tests: auth, API keys, authorization, registries, limits,
// validation, dashboard routes, docs, security. No upstream AI calls anywhere.
const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');
const fs = require('fs');

process.env.DATABASE_PATH = './data/test.db';
process.env.SESSION_SECRET = 'test-secret-min-32-characters-long-ok';
process.env.PUBLIC_API_BASE_URL = 'https://ciptamodel.com/v1';

for (const suffix of ['', '-wal', '-shm', '-journal']) {
  try { fs.unlinkSync('./data/test.db' + suffix); } catch {}
}

const db = require('../src/db.js');
const { generateApiKey, hashSecret } = db;
const { app, setRouterOverrides, limiter } = require('../src/server.js');
const { createMemoryBackend, checkRate, checkQuota } = require('../src/limits.js');
const { ProviderAdapter, ProviderNotConnectedError, ProviderError, MockAdapter, Router, DeepSeekAdapter } = require('../src/providers.js');

let userId;
let sessionCookie;
let csrf;

function cookiesOf(res) {
  const set = res.headers['set-cookie'];
  return Array.isArray(set) ? set.join('; ') : (set || '');
}

async function loginAs(email, password) {
  const r = await app.inject({ method: 'POST', url: '/login', payload: { email, password } });
  assert.equal(r.statusCode, 302);
  const jar = cookiesOf(r);
  const m = jar.match(/cm_session=([^;]+)/);
  assert.ok(m, 'session cookie set');
  const me = await app.inject({ method: 'GET', url: '/dashboard/api-keys', headers: { cookie: `cm_session=${m[1]}` } });
  assert.equal(me.statusCode, 200);
  const csrfMatch = me.body.match(/name="_csrf" value="([a-f0-9]+)"/);
  return { cookie: `cm_session=${m[1]}`, csrf: csrfMatch && csrfMatch[1] };
}

before(async () => {
  db.connect(process.env.DATABASE_PATH);
  const d = db.getDb();
  userId = 'usr_test1';
  d.prepare('INSERT INTO users (id, email, password_hash) VALUES (?,?,?)')
    .run(userId, 'dev@ciptamodel.test', bcrypt.hashSync('password123', 8));
  d.prepare('INSERT INTO subscriptions (user_id, plan, status) VALUES (?,?,?)').run(userId, 'free', 'active');
  await app.ready();
  const s = await loginAs('dev@ciptamodel.test', 'password123');
  sessionCookie = s.cookie;
  csrf = s.csrf;
  assert.ok(csrf, 'csrf token present in dashboard forms');
});

// ---------- authentication ----------
describe('authentication', () => {
  it('registers a new user with hashed password', async () => {
    const r = await app.inject({ method: 'POST', url: '/register', payload: { email: 'new@ciptamodel.test', password: 'supersecret1' } });
    assert.equal(r.statusCode, 302);
    assert.match(cookiesOf(r), /cm_session=/);
    const row = db.getDb().prepare('SELECT * FROM users WHERE email = ?').get('new@ciptamodel.test');
    assert.ok(row);
    assert.ok(!row.password_hash.includes('supersecret1'));
    assert.ok(bcrypt.compareSync('supersecret1', row.password_hash));
  });

  it('rejects duplicate email', async () => {
    const r = await app.inject({ method: 'POST', url: '/register', payload: { email: 'dev@ciptamodel.test', password: 'anotherpass1' } });
    assert.equal(r.statusCode, 200);
    assert.match(r.body, /already registered/);
  });

  it('rejects invalid email and short password', async () => {
    const bad1 = await app.inject({ method: 'POST', url: '/register', payload: { email: 'not-an-email', password: 'longenough1' } });
    assert.match(bad1.body, /valid email/);
    const bad2 = await app.inject({ method: 'POST', url: '/register', payload: { email: 'x@y.zz', password: 'short' } });
    assert.match(bad2.body, /at least 8/);
  });

  it('rejects wrong password', async () => {
    const r = await app.inject({ method: 'POST', url: '/login', payload: { email: 'dev@ciptamodel.test', password: 'wrongpass99' } });
    assert.equal(r.statusCode, 200);
    assert.match(r.body, /Invalid email or password/);
  });

  it('redirects unauthenticated dashboard to login', async () => {
    for (const url of ['/dashboard', '/dashboard/api-keys', '/dashboard/logs', '/dashboard/usage', '/dashboard/billing', '/dashboard/settings', '/dashboard/playground', '/dashboard/models']) {
      const r = await app.inject({ method: 'GET', url });
      assert.equal(r.statusCode, 302, url);
      assert.match(r.headers.location, /\/login/);
    }
  });

  it('logs out and invalidates session', async () => {
    const s = await loginAs('dev@ciptamodel.test', 'password123');
    const out = await app.inject({ method: 'GET', url: '/logout', headers: { cookie: s.cookie } });
    assert.equal(out.statusCode, 302);
    const after = await app.inject({ method: 'GET', url: '/dashboard', headers: { cookie: s.cookie } });
    assert.equal(after.statusCode, 302);
  });
});

// ---------- API key management ----------
describe('api keys', () => {
  let createdId;

  it('creates a key and shows the secret once', async () => {
    const r = await app.inject({
      method: 'POST', url: '/dashboard/api-keys',
      headers: { cookie: sessionCookie }, payload: { name: 'Cursor Development', _csrf: csrf },
    });
    assert.equal(r.statusCode, 302);
    const jar = cookiesOf(r);
    const m = jar.match(/cm_newkey=([^;]+)/);
    assert.ok(m, 'one-time secret cookie set');
    const secret = Buffer.from(m[1], 'base64url').toString();
    assert.match(secret, /^sk-cm-live-/);
    const row = db.getDb().prepare('SELECT * FROM api_keys WHERE key_hash = ?').get(hashSecret(secret));
    assert.ok(row);
    createdId = row.id;
    const page = await app.inject({ method: 'GET', url: '/dashboard/api-keys', headers: { cookie: `${sessionCookie}; cm_newkey=${m[1]}` } });
    assert.match(page.body, /Copy this key now/);
    const again = await app.inject({ method: 'GET', url: '/dashboard/api-keys', headers: { cookie: sessionCookie } });
    assert.ok(!again.body.includes(secret), 'secret must not persist on later views');
    assert.ok(again.body.includes('••••••••'), 'masked value shown');
  });

  it('stores only the hash, never plaintext', async () => {
    const row = db.getDb().prepare('SELECT * FROM api_keys WHERE id = ?').get(createdId);
    assert.match(row.key_hash, /^[a-f0-9]{64}$/);
    assert.equal(row.key_prefix.length, 14);
    assert.ok(!('secret' in row), 'no secret column');
    // key_prefix is an intentional identification prefix; the full secret
    // must not appear anywhere in the row.
    const rowText = JSON.stringify({ ...row, key_prefix: undefined });
    assert.ok(!rowText.includes('sk-cm-live-')); 
  });

  it('generates unique secrets', async () => {
    const a = generateApiKey();
    const b = generateApiKey();
    assert.notEqual(a.secret, b.secret);
    assert.equal(hashSecret(a.secret), a.hash);
  });

  it('revokes then deletes a key', async () => {
    const rev = await app.inject({ method: 'POST', url: `/dashboard/api-keys/${createdId}/revoke`, headers: { cookie: sessionCookie }, payload: { _csrf: csrf } });
    assert.equal(rev.statusCode, 302);
    assert.equal(db.getDb().prepare('SELECT status FROM api_keys WHERE id = ?').get(createdId).status, 'revoked');
    const del = await app.inject({ method: 'POST', url: `/dashboard/api-keys/${createdId}/delete`, headers: { cookie: sessionCookie }, payload: { _csrf: csrf } });
    assert.equal(del.statusCode, 302);
    assert.equal(db.getDb().prepare('SELECT * FROM api_keys WHERE id = ?').get(createdId), undefined);
  });

  it('rejects state changes without CSRF token', async () => {
    const r = await app.inject({ method: 'POST', url: '/dashboard/api-keys', headers: { cookie: sessionCookie }, payload: { name: 'x' } });
    assert.equal(r.statusCode, 403);
  });
});

// ---------- gateway: real Phase-2 pipeline (mock adapters — no network) ----------
describe('gateway', () => {
  let apiKey;

  before(async () => {
    const g = generateApiKey();
    apiKey = g.secret;
    db.getDb().prepare('INSERT INTO api_keys (id, user_id, name, key_hash, key_prefix) VALUES (?,?,?,?,?)')
      .run('key_gw1', userId, 'Gateway test', g.hash, g.prefix);
    // Default: deterministic mock behind the deepseek slot.
    setRouterOverrides({ adapters: { deepseek: new MockAdapter({ name: 'deepseek' }, { content: 'mock reply', inputTokens: 10, outputTokens: 5 }) } });
  });

  const chat = (payload, key = apiKey, extraHeaders = {}) => app.inject({
    method: 'POST', url: '/v1/chat/completions',
    headers: { authorization: `Bearer ${key}`, ...extraHeaders },
    payload,
  });

  // The limiter is process-global: reset per test so gateway tests are
  // hermetic regardless of execution order/count.
  const { beforeEach } = require('node:test');
  beforeEach(() => limiter.resetForTests());

  it('rejects missing/revoked keys with 401 OpenAI-shaped error', async () => {
    const r = await app.inject({ method: 'GET', url: '/v1/models' });
    assert.equal(r.statusCode, 401);
    assert.equal(r.json().error.code, 'invalid_api_key');
    assert.ok(r.headers['x-request-id']);
    const g = generateApiKey();
    db.getDb().prepare("INSERT INTO api_keys (id, user_id, name, key_hash, key_prefix, status) VALUES (?,?,?,?,?,'revoked')")
      .run('key_rev', userId, 'Revoked', g.hash, g.prefix);
    const r2 = await app.inject({ method: 'GET', url: '/v1/models', headers: { authorization: `Bearer ${g.secret}` } });
    assert.equal(r2.statusCode, 401);
  });

  it('lists registry models (no provider call)', async () => {
    const r = await app.inject({ method: 'GET', url: '/v1/models', headers: { authorization: `Bearer ${apiKey}` } });
    assert.equal(r.statusCode, 200);
    assert.equal(r.json().object, 'list');
    assert.ok(r.json().data.some((m) => m.id === 'deepseek-v4.1-flash'));
  });

  it('completes chat non-streaming with OpenAI shape + request id', async () => {
    const r = await chat({ model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 'Hello' }] });
    assert.equal(r.statusCode, 200);
    const body = r.json();
    assert.equal(body.object, 'chat.completion');
    assert.ok(body.id.startsWith('cm_chat_'));
    assert.equal(body.model, 'deepseek-v4.1-flash');
    assert.equal(body.choices[0].message.role, 'assistant');
    assert.equal(body.choices[0].message.content, 'mock reply');
    assert.deepEqual(body.usage, { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 });
    assert.ok(r.headers['x-request-id']);
    assert.equal(body.error, undefined);
  });

  it('reuses a valid client X-Request-ID, sanitizes a malicious one', async () => {
    const good = await chat({ model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 'Hi' }] }, apiKey, { 'x-request-id': 'client-123_ABC' });
    assert.equal(good.headers['x-request-id'], 'client-123_ABC');
    assert.equal(good.json().error, undefined);
    const bad = await chat({ model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 'Hi' }] }, apiKey, { 'x-request-id': 'evil\nHeader: injected' });
    assert.match(bad.headers['x-request-id'], /^cm_req_[0-9a-f]+$/);
  });

  it('streams SSE chunks ending in [DONE]', async () => {
    const r = await chat({ model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 'Hi' }], stream: true });
    assert.equal(r.statusCode, 200);
    assert.match(r.headers['content-type'], /text\/event-stream/);
    assert.ok(r.body.includes('data: [DONE]'));
    assert.ok(r.body.includes('chat.completion.chunk'));
    assert.ok(r.body.includes('"delta":{"role":"assistant"}'));
  });

  it('404s unknown model with param + request_id', async () => {
    const nf = await chat({ model: 'nope-1', messages: [{ role: 'user', content: 'Hi' }] });
    assert.equal(nf.statusCode, 404);
    assert.equal(nf.json().error.code, 'model_not_found');
    assert.equal(nf.json().error.param, 'model');
    assert.ok(nf.json().error.request_id);
  });

  it('validates: roles, temperature, max_tokens, stream, sizes, malformed JSON', async () => {
    const cases = [
      [{ model: 'deepseek-v4.1-flash', messages: [] }, 400],
      [{ model: 'deepseek-v4.1-flash', messages: [{ role: 'alien', content: 'x' }] }, 400],
      [{ model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 42 }] }, 400],
      [{ model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 'x' }], temperature: 9 }, 400],
      [{ model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 'x' }], max_tokens: -1 }, 400],
      [{ model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 'x' }], stream: 'yes' }, 400],
      [{ model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 'x' }], top_p: 0 }, 400],
      [{ messages: [{ role: 'user', content: 'x' }] }, 400],
      [[], 400],
    ];
    for (const [payload, status] of cases) {
      const r = await chat(payload);
      assert.equal(r.statusCode, status, JSON.stringify(payload));
      assert.equal(r.json().error.type, 'invalid_request_error');
    }
    const raw = await app.inject({
      method: 'POST', url: '/v1/chat/completions',
      headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' },
      payload: '{not json',
    });
    assert.equal(raw.statusCode, 400);
    assert.equal(raw.json().error.code, 'invalid_request');
  });

  it('enforces rate limits with 429 + Retry-After', async () => {
    const d = db.getDb();
    d.prepare("INSERT OR REPLACE INTO plans (name, requests_per_day, tokens_per_day, rpm) VALUES ('rltest', 100000, 100000000, 0)").run();
    d.prepare('UPDATE users SET plan = ? WHERE id = ?').run('rltest', userId);
    await chat({ model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 'Hi' }] });
    const r2 = await chat({ model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 'Hi' }] });
    assert.equal(r2.statusCode, 429);
    assert.equal(r2.json().error.code, 'rate_limit_exceeded');
    assert.equal(r2.headers['retry-after'], '60');
    d.prepare('UPDATE users SET plan = ? WHERE id = ?').run('free', userId);
  });

  it('enforces daily quota with 429 without contacting provider', async () => {
    const d = db.getDb();
    d.prepare("INSERT OR REPLACE INTO plans (name, requests_per_day, tokens_per_day, rpm) VALUES ('q0', 0, 0, 1000)").run();
    d.prepare('UPDATE users SET plan = ? WHERE id = ?').run('q0', userId);
    const probe = new MockAdapter({ name: 'deepseek' }, { content: 'should-not-happen' });
    setRouterOverrides({ adapters: { deepseek: probe } });
    const r = await chat({ model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 'Hi' }] });
    assert.equal(r.statusCode, 429);
    assert.equal(r.json().error.code, 'insufficient_quota');
    assert.equal(probe.calls.length, 0, 'provider must not be contacted after quota failure');
    d.prepare('UPDATE users SET plan = ? WHERE id = ?').run('free', userId);
    setRouterOverrides({ adapters: { deepseek: new MockAdapter({ name: 'deepseek' }, { content: 'mock reply', inputTokens: 10, outputTokens: 5 }) } });
  });

  it('records usage rows with request ids, tokens, cost', async () => {
    const d = db.getDb();
    const before = d.prepare('SELECT COUNT(*) c FROM requests WHERE user_id = ?').get(userId).c;
    const r = await chat({ model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 'meter me' }] }, apiKey, { 'x-request-id': 'meter-1' });
    assert.equal(r.statusCode, 200);
    const row = d.prepare('SELECT * FROM requests WHERE request_id = ?').get('meter-1');
    assert.ok(row, 'usage row keyed by request id');
    assert.equal(row.input_tokens, 10);
    assert.equal(row.output_tokens, 5);
    assert.equal(row.total_tokens, 15);
    assert.equal(row.status, 'success');
    assert.equal(row.provider, 'deepseek');
    assert.ok(d.prepare('SELECT COUNT(*) c FROM requests WHERE user_id = ?').get(userId).c > before);
  });

  it('provider errors are normalized (401/429/500/timeout/malformed)', async () => {
    const table = [
      [new ProviderError('x', { provider: 'deepseek', code: 'provider_authentication_error', httpStatus: 502 }), 502, 'provider_authentication_error'],
      [new ProviderError('x', { provider: 'deepseek', code: 'provider_rate_limit', httpStatus: 503, retryable: true }), 503, 'provider_rate_limit'],
      [new ProviderError('x', { provider: 'deepseek', code: 'provider_unavailable', httpStatus: 502, retryable: true }), 503, 'provider_unavailable'],
      [new ProviderError('x', { provider: 'deepseek', code: 'provider_timeout', httpStatus: 504, retryable: true }), 504, 'provider_timeout'],
      [new ProviderError('x', { provider: 'deepseek', code: 'provider_invalid_response', httpStatus: 502 }), 502, 'provider_invalid_response'],
    ];
    for (const [fail, status, code] of table) {
      setRouterOverrides({ adapters: { deepseek: new MockAdapter({ name: 'deepseek' }, { fail }) } });
      const r = await chat({ model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 'Hi' }] });
      assert.equal(r.statusCode, status, code);
      assert.equal(r.json().error.code, code);
      assert.ok(r.json().error.request_id, 'request id in error');
      assert.ok(!JSON.stringify(r.json()).includes('stack'), 'no stack leak');
    }
    setRouterOverrides({ adapters: { deepseek: new MockAdapter({ name: 'deepseek' }, { content: 'mock reply', inputTokens: 10, outputTokens: 5 }) } });
  });

  it('retries transient failure once, then succeeds (2 attempts logged)', async () => {
    let n = 0;
    const flaky = new MockAdapter({ name: 'deepseek' });
    flaky.chatCompletion = async (req) => {
      flaky.calls.push({ op: 'chat' });
      if (++n === 1) throw new ProviderError('boom', { provider: 'deepseek', code: 'provider_unavailable', retryable: true });
      return { content: 'recovered', finishReason: 'stop', inputTokens: 3, outputTokens: 4 };
    };
    setRouterOverrides({ adapters: { deepseek: flaky } });
    const r = await chat({ model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 'Hi' }] }, apiKey, { 'x-request-id': 'retry-1' });
    assert.equal(r.statusCode, 200);
    assert.equal(r.json().choices[0].message.content, 'recovered');
    const attempts = db.getDb().prepare('SELECT COUNT(*) c FROM provider_attempts WHERE request_id = ?').get('retry-1').c;
    assert.equal(attempts, 2);
    setRouterOverrides({ adapters: { deepseek: new MockAdapter({ name: 'deepseek' }, { content: 'mock reply', inputTokens: 10, outputTokens: 5 }) } });
  });

  it('falls back on transient failure when registry configures it', async () => {
    const d = db.getDb();
    d.prepare("INSERT OR IGNORE INTO models (id, model_id, display_name, provider, enabled, context_window, status) VALUES ('mdl_fb1','fb-primary','FB Primary','deepseek',1,1000,'active')").run();
    d.prepare("INSERT OR IGNORE INTO models (id, model_id, display_name, provider, enabled, context_window, status) VALUES ('mdl_fb2','fb-backup','FB Backup','deepseek',1,1000,'active')").run();
    d.prepare('UPDATE models SET fallback_model = ? WHERE model_id = ?').run('fb-backup', 'fb-primary');
    setRouterOverrides({
      adapters: {
        deepseek: new (class extends MockAdapter {
          async chatCompletion(req) {
            this.calls.push({ op: 'chat', model: req.model });
            if (req.model === 'fb-primary') throw new ProviderError('down', { provider: 'deepseek', code: 'provider_unavailable', retryable: true });
            return { content: 'via fallback', finishReason: 'stop', inputTokens: 1, outputTokens: 2 };
          }
        })({ name: 'deepseek' }),
      },
    });
    const r = await chat({ model: 'fb-primary', messages: [{ role: 'user', content: 'Hi' }] }, apiKey, { 'x-request-id': 'fb-1' });
    assert.equal(r.statusCode, 200);
    assert.equal(r.json().choices[0].message.content, 'via fallback');
    const row = d.prepare('SELECT * FROM requests WHERE request_id = ?').get('fb-1');
    assert.match(row.provider, /fallback/);
    d.prepare('DELETE FROM models WHERE model_id IN (?,?)').run('fb-primary', 'fb-backup');
    setRouterOverrides({ adapters: { deepseek: new MockAdapter({ name: 'deepseek' }, { content: 'mock reply', inputTokens: 10, outputTokens: 5 }) } });
  });

  it('does NOT fall back on client errors', async () => {
    const probe = new MockAdapter({ name: 'deepseek' }, { content: 'x' });
    setRouterOverrides({ adapters: { deepseek: probe } });
    const r = await chat({ model: 'deepseek-v4.1-flash', messages: [] });
    assert.equal(r.statusCode, 400);
    assert.equal(probe.calls.length, 0);
  });

  it('streaming provider failure arrives as error event + DONE', async () => {
    setRouterOverrides({ adapters: { deepseek: new MockAdapter({ name: 'deepseek' }, { fail: new ProviderError('mid', { provider: 'deepseek', code: 'provider_unavailable' }) }) } });
    const r = await chat({ model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 'Hi' }], stream: true });
    assert.equal(r.statusCode, 200);
    assert.ok(r.body.includes('finish_reason":"error') || r.body.includes('"finish_reason": "error') || r.body.includes('provider_unavailable'));
    assert.ok(r.body.includes('data: [DONE]'));
    setRouterOverrides({ adapters: { deepseek: new MockAdapter({ name: 'deepseek' }, { content: 'mock reply', inputTokens: 10, outputTokens: 5 }) } });
  });

  it('playground runs the same pipeline (no API key in browser)', async () => {
    const r = await app.inject({
      method: 'POST', url: '/api/playground', headers: { cookie: sessionCookie, 'x-csrf-token': csrf },
      payload: { model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 'Hi' }] },
    });
    assert.equal(r.statusCode, 200);
    assert.equal(r.json().choices[0].message.content, 'mock reply');
  });
});

// ---------- registries, limits unit, docs, security ----------
describe('platform', () => {
  it('model registry is DB-backed with required fields', async () => {
    const models = db.listModels({ enabledOnly: false });
    assert.ok(models.length >= 1);
    for (const m of models) {
      for (const f of ['id', 'display_name', 'provider', 'enabled', 'context_window', 'price_input_per_1k', 'price_output_per_1k', 'capabilities', 'status']) {
        assert.ok(m[f] !== undefined, `${m.id} missing ${f}`);
      }
    }
  });

  it('provider adapters expose interface and refuse without connection', async () => {
    const providers = db.listProviders();
    assert.ok(providers.some((p) => p.name === 'deepseek'));
    // Base adapter refuses on all ops when not connected.
    const bare = new ProviderAdapter({ name: 'deepseek', enabled: true, status: 'not_connected' });
    await assert.rejects(bare.chatCompletion({}), (e) => e instanceof ProviderNotConnectedError);
    await assert.rejects(bare.streamChatCompletion({}), (e) => e instanceof ProviderNotConnectedError);
    await assert.rejects(bare.getModels(), (e) => e instanceof ProviderNotConnectedError);
    // DeepSeek adapter without credentials reports not_configured, never connected.
    const unconfigured = new DeepSeekAdapter({ deepseek: { apiKey: '', baseUrl: 'https://api.deepseek.com', timeoutMs: 1000 } }, { name: 'deepseek', enabled: true });
    assert.equal(unconfigured.connected, false);
    assert.equal(unconfigured.status, 'not_configured');
    await assert.rejects(unconfigured.chatCompletion({}), (e) => e instanceof ProviderNotConnectedError);
    const router = new Router(
      [{ id: 'm1', provider: 'deepseek', enabled: true }],
      { deepseek: new ProviderAdapter({ name: 'deepseek', enabled: true, status: 'not_connected' }) });
    assert.equal(router.resolve('m1').error, 'provider_not_connected');
    assert.equal(router.resolve('nope').error, 'model_not_found');
  });

  it('deepseek adapter normalizes upstream failures without leaking secrets', async () => {
    const realFetch = global.fetch;
    try {
      // Upstream 401 → provider_authentication_error, no key in message.
      global.fetch = async () => new Response('{"error":{"message":"bad key"}}', { status: 401 });
      const a = new DeepSeekAdapter({ deepseek: { apiKey: 'sk-test-secret-xyz', baseUrl: 'https://api.deepseek.com', timeoutMs: 5000 } }, { name: 'deepseek', enabled: true, status: 'connected' });
      await assert.rejects(a.chatCompletion({ model: 'deepseek-chat', messages: [{ role: 'user', content: 'hi' }] }),
        (e) => e.code === 'provider_authentication_error' && !String(e.message).includes('sk-test-secret-xyz'));
      // Upstream 500 → retryable provider_unavailable.
      global.fetch = async () => new Response('oops', { status: 500 });
      await assert.rejects(a.chatCompletion({ model: 'deepseek-chat', messages: [{ role: 'user', content: 'hi' }] }),
        (e) => e.code === 'provider_unavailable' && e.retryable === true);
      // Malformed JSON → provider_invalid_response.
      global.fetch = async () => new Response('not json{{{', { status: 200 });
      await assert.rejects(a.chatCompletion({ model: 'deepseek-chat', messages: [{ role: 'user', content: 'hi' }] }),
        (e) => e.code === 'provider_invalid_response');
      // SSE stream parses deltas and terminates.
      const sse = 'data: {"choices":[{"delta":{"content":"Hello"}}]}\n\ndata: {"choices":[{"delta":{"content":" world"}}]}\n\ndata: [DONE]\n\n';
      global.fetch = async () => new Response(sse, { status: 200 });
      const tokens = [];
      const out = await a.streamChatCompletion({ model: 'deepseek-chat', messages: [{ role: 'user', content: 'hi' }], onToken: async (t) => tokens.push(t) });
      assert.equal(out.content, 'Hello world');
      assert.deepEqual(tokens, ['Hello', ' world']);
    } finally {
      global.fetch = realFetch;
    }
  });

  it('limits module: per-scope rate and daily quota', async () => {
    const b = createMemoryBackend();
    assert.equal(checkRate({ backend: b, userId: 'u', keyId: 'k', ip: '1.2.3.4', rpm: 1 }).limited, false);
    assert.equal(checkRate({ backend: b, userId: 'u', keyId: 'k', ip: '1.2.3.4', rpm: 1 }).limited, true);
    const b2 = createMemoryBackend();
    assert.equal(checkRate({ backend: b2, userId: 'u', keyId: 'k', ip: '1.2.3.4', rpm: -1 }).limited, false);
    const d = db.getDb();
    assert.equal(checkQuota(d, userId, { requests_per_day: 100000, tokens_per_day: 100000000 }).limited, false);
    assert.equal(checkQuota(d, userId, { requests_per_day: 0, tokens_per_day: 0 }).limited, true);
  });

  it('dashboard pages render with honest empty states', async () => {
    for (const [url, needle] of [
      ['/dashboard', 'SYSTEM STATUS'],
      ['/dashboard/api-keys', 'Manajemen API Keys'],
      ['/dashboard/models', 'Registry'],
      ['/dashboard/logs', 'API KEY'],
      ['/dashboard/usage', 'USAGE BY MODEL'],
      ['/dashboard/billing', 'CURRENT PLAN'],
      ['/dashboard/playground', 'same gateway pipeline'],
      ['/dashboard/settings', 'PROFILE'],
    ]) {
      const r = await app.inject({ method: 'GET', url, headers: { cookie: sessionCookie } });
      assert.equal(r.statusCode, 200, url);
      assert.ok(r.body.includes(needle), `${url} missing ${needle}`);
    }
    const fresh = await app.inject({ method: 'POST', url: '/register', payload: { email: 'empty@ciptamodel.test', password: 'supersecret2' } });
    const jar = cookiesOf(fresh);
    const ck = `cm_session=${jar.match(/cm_session=([^;]+)/)[1]}`;
    const logs = await app.inject({ method: 'GET', url: '/dashboard/logs', headers: { cookie: ck } });
    assert.match(logs.body, /No requests logged yet/);
  });

  it('public pages + docs render, live endpoints unbadged', async () => {
    const home = await app.inject({ method: 'GET', url: '/' });
    assert.equal(home.statusCode, 200);
    assert.match(home.body, /One API/);
    const pricing = await app.inject({ method: 'GET', url: '/pricing' });
    assert.match(pricing.body, /FREE/);
    const health = await app.inject({ method: 'GET', url: '/health' });
    assert.equal(health.statusCode, 200);
    assert.equal(health.json().ok, true);
    assert.ok(!JSON.stringify(health.json()).match(/sk-|Bearer|api[_-]?key/i), 'no secrets in health');
    const docIdx = await app.inject({ method: 'GET', url: '/docs.json' });
    const pages = docIdx.json().pages;
    const bySlug = Object.fromEntries(pages.map((p) => [p.slug, p]));
    for (const s of ['introduction', 'quickstart', 'authentication', 'models', 'chat-completions', 'streaming', 'api-keys', 'errors', 'rate-limits', 'usage', 'sdk', 'examples', 'cursor', 'cline', 'open-webui']) {
      assert.ok(bySlug[s], `docs missing ${s}`);
      const p = await app.inject({ method: 'GET', url: `/docs/${s}` });
      assert.equal(p.statusCode, 200, s);
    }
    assert.equal(bySlug['chat-completions'].phase2, false, 'chat docs are live');
    assert.equal(bySlug['streaming'].phase2, false, 'streaming docs are live');
    const no = await app.inject({ method: 'GET', url: '/docs/nope' });
    assert.equal(no.statusCode, 404);
  });

  it('legacy console paths redirect to new IA', async () => {
    for (const [oldP, target] of [['/keys', '/dashboard/api-keys'], ['/logs', '/dashboard/logs'], ['/playground', '/dashboard/playground'], ['/usage', '/dashboard/usage'], ['/billing', '/dashboard/billing'], ['/plan', '/dashboard/billing'], ['/settings', '/dashboard/settings']]) {
      const r = await app.inject({ method: 'GET', url: oldP });
      assert.equal(r.statusCode, 302, oldP);
      assert.equal(r.headers.location, target);
    }
  });

  it('security headers present, no secrets leak', async () => {
    const r = await app.inject({ method: 'GET', url: '/' });
    for (const h of ['x-content-type-options', 'x-frame-options', 'content-security-policy', 'referrer-policy']) {
      assert.ok(r.headers[h], `missing ${h}`);
    }
    const err = await app.inject({ method: 'GET', url: '/v1/models' });
    assert.ok(!err.body.includes('stack'));
    const prov = await app.inject({ method: 'GET', url: '/healthz' });
    assert.ok(!prov.body.includes('sk-'), 'no secrets in health output');
  });

  it('database schema has Phase-2 entities, indexes, FKs', async () => {
    const d = db.getDb();
    const tables = d.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map((r) => r.name);
    for (const t of ['users', 'api_keys', 'requests', 'plans', 'sessions', 'models', 'providers', 'subscriptions', 'audit_logs', 'provider_attempts']) {
      assert.ok(tables.includes(t), `missing table ${t}`);
    }
    const reqCols = d.prepare('PRAGMA table_info(requests)').all().map((c) => c.name);
    assert.ok(reqCols.includes('request_id'), 'requests.request_id migrated');
    assert.ok(reqCols.includes('est_cost'), 'requests.est_cost migrated');
    assert.equal(d.pragma('foreign_key_list(api_keys)').length > 0, true);
    const idx = d.prepare("SELECT name FROM sqlite_master WHERE type='index'").all().map((r) => r.name);
    assert.ok(idx.some((n) => n.includes('api_keys')));
    assert.ok(d.prepare('SELECT COUNT(*) c FROM plans').get().c >= 4);
    assert.ok(d.prepare('SELECT COUNT(*) c FROM providers').get().c >= 5);
  });
});
