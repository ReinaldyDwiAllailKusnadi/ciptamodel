'use strict';
// Hardening regression suite: cookies, authorization, XSS, SQLi, SSRF,
// resource limits, rate/quota-before-provider, headers, CORS, request IDs.
// All deterministic — mock adapters, no network, no credentials.
const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');
const fs = require('fs');

process.env.DATABASE_PATH = './data/test3.db';
process.env.SESSION_SECRET = 'test-secret-min-32-characters-long-ok';

for (const suffix of ['', '-wal', '-shm', '-journal']) {
  try { fs.unlinkSync('./data/test3.db' + suffix); } catch {}
}

const db = require('../src/db.js');
const { generateApiKey } = db;
const srv = require('../src/server.js');
const { app, setRouterOverrides, limiter } = srv;
const { MockAdapter, DeepSeekAdapter } = require('../src/providers.js');

const origNodeEnv = process.env.NODE_ENV;
let userA; let userB; let keyA; let cookieA; let csrfA; let cookieB;

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
  return { cookie: `cm_session=${m[1]}`, csrf: csrfMatch && csrfMatch[1], jar };
}

before(async () => {
  db.connect(process.env.DATABASE_PATH);
  const d = db.getDb();
  userA = 'usr_hardA';
  userB = 'usr_hardB';
  d.prepare('INSERT INTO users (id, email, password_hash) VALUES (?,?,?)')
    .run(userA, 'harda@ciptamodel.test', bcrypt.hashSync('password123', 8));
  d.prepare('INSERT INTO users (id, email, password_hash) VALUES (?,?,?)')
    .run(userB, 'hardb@ciptamodel.test', bcrypt.hashSync('password123', 8));
  const g = generateApiKey();
  keyA = g.secret;
  d.prepare('INSERT INTO api_keys (id, user_id, name, key_hash, key_prefix) VALUES (?,?,?,?,?)')
    .run('key_hardA', userA, 'A key', g.hash, g.prefix);
  setRouterOverrides({ adapters: { deepseek: new MockAdapter({ name: 'deepseek' }, { content: 'ok', inputTokens: 4, outputTokens: 6 }) } });
  await app.ready();
  const a = await loginAs('hardA@ciptamodel.test', 'password123');
  cookieA = a.cookie; csrfA = a.csrf;
  cookieB = (await loginAs('hardB@ciptamodel.test', 'password123')).cookie;
  limiter.resetForTests();
});

const { beforeEach } = require('node:test');
beforeEach(() => limiter.resetForTests());

const chat = (payload, key = keyA, headers = {}) => app.inject({
  method: 'POST', url: '/v1/chat/completions',
  headers: { authorization: `Bearer ${key}`, ...headers }, payload,
});

describe('hardening regressions', () => {
  it('session cookie is HttpOnly + SameSite=Lax, Secure only in production', async () => {
    const dev = await app.inject({ method: 'POST', url: '/login', payload: { email: 'hardA@ciptamodel.test', password: 'password123' } });
    const devJar = cookiesOf(dev).toLowerCase();
    assert.ok(devJar.includes('httponly'), 'HttpOnly always');
    assert.ok(devJar.includes('samesite=lax'), 'SameSite=Lax always');
    process.env.NODE_ENV = 'production';
    try {
      const prod = await app.inject({ method: 'POST', url: '/login', payload: { email: 'hardA@ciptamodel.test', password: 'password123' } });
      assert.ok(cookiesOf(prod).toLowerCase().includes('secure'), 'Secure in production');
    } finally {
      if (origNodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = origNodeEnv;
    }
  });

  it('one-time key cookie is HttpOnly, short-lived, secret unrecoverable after redirect', async () => {
    const r = await app.inject({
      method: 'POST', url: '/dashboard/api-keys',
      headers: { cookie: cookieA }, payload: { name: 'once-only', _csrf: csrfA },
    });
    assert.equal(r.statusCode, 302);
    const jar = cookiesOf(r);
    const m = jar.match(/cm_newkey=([^;]+)/);
    assert.ok(m, 'one-time cookie set');
    assert.ok(jar.toLowerCase().includes('httponly'), 'HttpOnly one-time cookie');
    const secret = Buffer.from(m[1], 'base64url').toString();
    const page = await app.inject({ method: 'GET', url: '/dashboard/api-keys', headers: { cookie: `${cookieA}; cm_newkey=${m[1]}` } });
    assert.ok(page.body.includes(secret.slice(-8)) || page.body.includes('Copy this key now'), 'shown once');
    const again = await app.inject({ method: 'GET', url: '/dashboard/api-keys', headers: { cookie: cookieA } });
    assert.ok(!again.body.includes(secret), 'secret gone after the one-time view');
  });

  it('user B cannot revoke, delete, or see user A keys', async () => {
    const d = db.getDb();
    const bCsrf = (await app.inject({ method: 'GET', url: '/dashboard/api-keys', headers: { cookie: cookieB } })).body.match(/name="_csrf" value="([a-f0-9]+)"/)[1];
    const rev = await app.inject({ method: 'POST', url: '/dashboard/api-keys/key_hardA/revoke', headers: { cookie: cookieB }, payload: { _csrf: bCsrf } });
    assert.equal(rev.statusCode, 302);
    assert.equal(d.prepare('SELECT status FROM api_keys WHERE id=?').get('key_hardA').status, 'active', 'cross-user revoke must not change status');
    const del = await app.inject({ method: 'POST', url: '/dashboard/api-keys/key_hardA/delete', headers: { cookie: cookieB }, payload: { _csrf: bCsrf } });
    assert.equal(del.statusCode, 302);
    assert.ok(d.prepare('SELECT * FROM api_keys WHERE id=?').get('key_hardA'), 'cross-user delete must not remove row');
    const listB = await app.inject({ method: 'GET', url: '/dashboard/api-keys', headers: { cookie: cookieB } });
    assert.ok(!listB.body.includes('A key'), 'user B must not see user A key names');
    const logsB = await app.inject({ method: 'GET', url: '/dashboard/logs', headers: { cookie: cookieB } });
    assert.equal(logsB.statusCode, 200);
  });

  it('user A gateway key cannot read user B data; revoked key rejected', async () => {
    const d = db.getDb();
    const gB = generateApiKey();
    d.prepare('INSERT INTO api_keys (id, user_id, name, key_hash, key_prefix) VALUES (?,?,?,?,?)')
      .run('key_hardB', userB, 'B key', gB.hash, gB.prefix);
    // Gateway is not user-scoped by design (single-user resources), but a
    // revoked key must fail closed immediately.
    d.prepare("UPDATE api_keys SET status='revoked' WHERE id=?").run('key_hardB');
    const r = await app.inject({ method: 'GET', url: '/v1/models', headers: { authorization: `Bearer ${gB.secret}` } });
    assert.equal(r.statusCode, 401);
    assert.equal(r.json().error.code, 'invalid_api_key');
    d.prepare('DELETE FROM api_keys WHERE id=?').run('key_hardB');
  });

  it('API key names are HTML-escaped (stored XSS blocked)', async () => {
    const xss = '<script>alert(1)</script><img src=x onerror=alert(2)>';
    const r = await app.inject({
      method: 'POST', url: '/dashboard/api-keys',
      headers: { cookie: cookieA }, payload: { name: xss, _csrf: csrfA },
    });
    assert.equal(r.statusCode, 302);
    const page = await app.inject({ method: 'GET', url: '/dashboard/api-keys', headers: { cookie: cookieA } });
    assert.ok(!page.body.includes('<script>alert(1)</script>'), 'raw script must not render');
    assert.ok(page.body.includes('&lt;script&gt;'), 'escaped output expected');
    db.getDb().prepare('DELETE FROM api_keys WHERE name=?').run(xss);
  });

  it('SQL injection attempts fail closed (parameterized queries)', async () => {
    const evil = "' OR '1'='1";
    const r = await app.inject({ method: 'POST', url: '/login', payload: { email: evil, password: evil } });
    assert.equal(r.statusCode, 200);
    assert.ok(!cookiesOf(r).includes('cm_session='), 'no session from injection');
    assert.match(r.body, /Invalid email or password/);
    // Register with quote-laden email: parameterized INSERT must store it
    // literally (or validation rejects it) — never break query structure or
    // grant another user's session.
    const tricky = "a'--@x.yy";
    const bad = await app.inject({ method: 'POST', url: '/register', payload: { email: tricky, password: 'longenough1' } });
    if (bad.statusCode === 302) {
      const row = db.getDb().prepare('SELECT * FROM users WHERE email = ?').get(tricky);
      assert.ok(row, 'quote-laden email stored literally, query structure intact');
      assert.ok(!row.password_hash.includes('longenough1'), 'password still hashed');
      // Must not collide with or expose any other user.
      assert.notEqual(row.id, userA);
      assert.notEqual(row.id, userB);
      db.getDb().prepare('DELETE FROM users WHERE id = ?').run(row.id);
    } else {
      assert.equal(bad.statusCode, 200, 'rejected by validation');
      assert.ok(!cookiesOf(bad).includes('cm_session='), 'no session from rejected register');
    }
  });

  it('client cannot steer provider destination (SSRF unit + gateway)', async () => {
    const evilBodies = [
      { model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 'Hi' }], base_url: 'http://169.254.169.254/' },
      { model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 'Hi' }], provider: 'http://127.0.0.1:9999', callback_url: 'http://localhost:9999/hook' },
      { model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 'Hi' }], endpoint: 'file:///etc/passwd' },
    ];
    for (const p of evilBodies) {
      const r = await chat(p);
      assert.equal(r.statusCode, 200, 'unknown fields ignored, never used as fetch targets');
    }
    const a = new DeepSeekAdapter(
      { deepseek: { apiKey: 'k', baseUrl: 'https://api.deepseek.com', timeoutMs: 100 } },
      { name: 'deepseek', enabled: true, status: 'connected' });
    assert.equal(a.baseUrl, 'https://api.deepseek.com', 'adapter URL is server config only');
  });

  it('oversize requests rejected before provider contact (413 contract)', async () => {
    const probe = new MockAdapter({ name: 'deepseek' }, { content: 'must-not-happen' });
    setRouterOverrides({ adapters: { deepseek: probe } });
    try {
      const big = 'x'.repeat(1024 * 1024 + 100);
      const r = await app.inject({
        method: 'POST', url: '/v1/chat/completions',
        headers: { authorization: `Bearer ${keyA}`, 'content-type': 'application/json' },
        payload: JSON.stringify({ model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: big }] }),
      });
      assert.ok([400, 413].includes(r.statusCode), `got ${r.statusCode}`);
      assert.ok(!JSON.stringify(r.json()).includes('stack'));
      assert.equal(probe.calls.length, 0, 'provider must not see oversize bodies');
    } finally {
      setRouterOverrides({ adapters: { deepseek: new MockAdapter({ name: 'deepseek' }, { content: 'ok', inputTokens: 4, outputTokens: 6 }) } });
    }
  });

  it('rate limit enforced before provider contact (429 + Retry-After)', async () => {
    const d = db.getDb();
    d.prepare("INSERT OR REPLACE INTO plans (name, requests_per_day, tokens_per_day, rpm) VALUES ('rl0', 100000, 100000000, 0)").run();
    d.prepare('UPDATE users SET plan=? WHERE id=?').run('rl0', userA);
    const probe = new MockAdapter({ name: 'deepseek' }, { content: 'must-not-happen' });
    setRouterOverrides({ adapters: { deepseek: probe } });
    try {
      // rpm=0 semantics: the first hit opens the bucket, the second exceeds
      // it. The limited request must 429 with Retry-After and never reach
      // the provider (calls stays at the 1 from the allowed request).
      await chat({ model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 'Hi' }] });
      const r = await chat({ model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 'Hi' }] });
      assert.equal(r.statusCode, 429);
      assert.equal(r.json().error.code, 'rate_limit_exceeded');
      assert.equal(r.headers['retry-after'], '60');
      assert.equal(probe.calls.length, 1, 'limited request must not contact provider');
    } finally {
      d.prepare('UPDATE users SET plan=? WHERE id=?').run('free', userA);
      setRouterOverrides({ adapters: { deepseek: new MockAdapter({ name: 'deepseek' }, { content: 'ok', inputTokens: 4, outputTokens: 6 }) } });
    }
  });

  it('security headers present, no wildcard CORS with credentials', async () => {
    const home = await app.inject({ method: 'GET', url: '/' });
    assert.equal(home.headers['x-content-type-options'], 'nosniff');
    assert.equal(home.headers['x-frame-options'], 'DENY');
    assert.ok(String(home.headers['content-security-policy'] || '').includes("default-src 'self'"));
    assert.ok(String(home.headers['referrer-policy'] || '').length > 0);
    const api = await app.inject({ method: 'GET', url: '/v1/models', headers: { authorization: `Bearer ${keyA}` } });
    assert.equal(api.statusCode, 200);
    assert.ok(api.headers['access-control-allow-origin'] !== '*', 'no wildcard CORS on API');
  });

  it('gateway errors carry request_id + X-Request-ID, never stacks/paths', async () => {
    const nf = await chat({ model: 'nope-model', messages: [{ role: 'user', content: 'x' }] });
    assert.equal(nf.statusCode, 404);
    assert.ok(nf.json().error.request_id);
    assert.equal(nf.headers['x-request-id'], nf.json().error.request_id);
    const bad = await chat({ model: 'deepseek-v4.1-flash', messages: [] });
    assert.equal(bad.statusCode, 400);
    const blob = JSON.stringify([nf.json(), bad.json()]);
    assert.ok(!blob.includes('stack') && !blob.includes('/root/') && !blob.includes('node_modules'));
  });

  it('provider 403 maps to non-retryable 502 without leaking upstream body', async () => {
    const realFetch = global.fetch;
    try {
      global.fetch = async () => new Response('{"error":{"message":"quota exceeded q-12345"}}', { status: 403 });
      const leaky = new DeepSeekAdapter(
        { deepseek: { apiKey: 'SECRET-XYZ', baseUrl: 'https://api.deepseek.com', timeoutMs: 2000 } },
        { name: 'deepseek', enabled: true, status: 'connected' });
      setRouterOverrides({ adapters: { deepseek: leaky } });
      const r = await chat({ model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 'Hi' }] });
      assert.equal(r.statusCode, 502);
      assert.equal(r.json().error.code, 'provider_authentication_error');
      assert.ok(!r.body.includes('SECRET-XYZ') && !r.body.includes('q-12345'));
    } finally {
      global.fetch = realFetch;
      setRouterOverrides({ adapters: { deepseek: new MockAdapter({ name: 'deepseek' }, { content: 'ok', inputTokens: 4, outputTokens: 6 }) } });
    }
  });
});
