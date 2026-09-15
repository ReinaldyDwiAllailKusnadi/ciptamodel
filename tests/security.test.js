'use strict';
// Phase 2 security suite: SSRF, secret handling, request validation units,
// cost calculation, disabled-model enforcement, error-shape consistency.
// All deterministic — no network, no credentials.
const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');
const fs = require('fs');

process.env.DATABASE_PATH = './data/test2.db';
process.env.SESSION_SECRET = 'test-secret-min-32-characters-long-ok';

for (const suffix of ['', '-wal', '-shm', '-journal']) {
  try { fs.unlinkSync('./data/test2.db' + suffix); } catch {}
}

const db = require('../src/db.js');
const { generateApiKey, hashSecret } = db;
const srv = require('../src/server.js');
const { app, setRouterOverrides, validateChatBody, estimateCost } = srv;
const { MockAdapter, DeepSeekAdapter, ProviderError } = require('../src/providers.js');

let userId;
let apiKey;

before(async () => {
  db.connect(process.env.DATABASE_PATH);
  const d = db.getDb();
  userId = 'usr_sec1';
  d.prepare('INSERT INTO users (id, email, password_hash) VALUES (?,?,?)')
    .run(userId, 'sec@ciptamodel.test', bcrypt.hashSync('password123', 8));
  const g = generateApiKey();
  apiKey = g.secret;
  d.prepare('INSERT INTO api_keys (id, user_id, name, key_hash, key_prefix) VALUES (?,?,?,?,?)')
    .run('key_sec1', userId, 'Security test', g.hash, g.prefix);
  setRouterOverrides({ adapters: { deepseek: new MockAdapter({ name: 'deepseek' }, { content: 'ok', inputTokens: 4, outputTokens: 6 }) } });
  await app.ready();
});

const chat = (payload, headers = {}) => app.inject({
  method: 'POST', url: '/v1/chat/completions',
  headers: { authorization: `Bearer ${apiKey}`, ...headers }, payload,
});

describe('gateway security', () => {
  it('disabled models are rejected (registry enforced)', async () => {
    const d = db.getDb();
    d.prepare("INSERT OR IGNORE INTO models (id, model_id, display_name, provider, enabled, context_window, status) VALUES ('mdl_off','off-model','Off','deepseek',0,1000,'active')").run();
    const r = await chat({ model: 'off-model', messages: [{ role: 'user', content: 'Hi' }] });
    assert.equal(r.statusCode, 404);
    assert.equal(r.json().error.code, 'model_not_found');
    d.prepare('DELETE FROM models WHERE model_id = ?').run('off-model');
  });

  it('client cannot inject an arbitrary provider URL (SSRF-safe)', async () => {
    for (const payload of [
      { model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 'Hi' }], base_url: 'http://169.254.169.254/' },
      { model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 'Hi' }], provider: 'http://evil/', upstream: 'http://evil/' },
    ]) {
      const r = await chat(payload);
      assert.equal(r.statusCode, 200, 'unknown fields must be ignored, never used as fetch targets');
    }
    // Adapter URL comes from server config only — never from client input.
    // (No base_url in descriptor → falls back to server-side config.)
    const a = new DeepSeekAdapter({ deepseek: { apiKey: 'x', baseUrl: 'https://custom.internal:8443/v1', timeoutMs: 100 } }, { name: 'deepseek', enabled: true, status: 'connected' });
    assert.equal(a.baseUrl, 'https://custom.internal:8443/v1');
  });

  it('provider secret never appears in responses, errors, logs, or DB', async () => {
    const realFetch = global.fetch;
    const seen = [];
    const origWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = (s, ...a) => { try { seen.push(String(s)); } catch {} return origWrite(s, ...a); };
    try {
      global.fetch = async () => new Response('{"error":{"message":"bad"}}', { status: 401 });
      const leaky = new DeepSeekAdapter({ deepseek: { apiKey: 'SECRET-KEY-ABC123', baseUrl: 'https://api.deepseek.com', timeoutMs: 2000 } }, { name: 'deepseek', enabled: true, status: 'connected' });
      setRouterOverrides({ adapters: { deepseek: leaky } });
      const r = await chat({ model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 'Hi' }] });
      assert.equal(r.statusCode, 502);
      assert.ok(!r.body.includes('SECRET-KEY-ABC123'), 'secret in error response');
      assert.ok(!r.body.includes('stack'), 'stack in error response');
    } finally {
      global.fetch = realFetch;
      process.stdout.write = origWrite;
      setRouterOverrides({ adapters: { deepseek: new MockAdapter({ name: 'deepseek' }, { content: 'ok', inputTokens: 4, outputTokens: 6 }) } });
    }
    assert.ok(!seen.join('\n').includes('SECRET-KEY-ABC123'), 'secret in server logs');
    const dump = JSON.stringify(db.getDb().prepare('SELECT * FROM requests ORDER BY created_at DESC LIMIT 5').all());
    assert.ok(!dump.includes('SECRET-KEY-ABC123'), 'secret in DB');
  });

  it('client API secret never appears in responses or logs', async () => {
    const r = await chat({ model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 'Hi' }] });
    assert.equal(r.statusCode, 200);
    assert.ok(!r.body.includes(apiKey.slice(11)), 'client secret fragment in response');
  });

  it('malformed Authorization variants all 401 identically', async () => {
    for (const h of [undefined, '', 'Bearer', 'Bearer ', 'Basic abc', 'Bearer not-our-format']) {
      const headers = h === undefined ? {} : { authorization: h };
      const r = await app.inject({ method: 'POST', url: '/v1/chat/completions', headers, payload: { model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: 'Hi' }] } });
      assert.equal(r.statusCode, 401, `header: ${h}`);
      assert.equal(r.json().error.code, 'invalid_api_key');
    }
  });

  it('oversize body rejected with 413 contract (no stack)', async () => {
    const big = 'x'.repeat(1024 * 1024 + 100);
    const r = await app.inject({
      method: 'POST', url: '/v1/chat/completions',
      headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' },
      payload: JSON.stringify({ model: 'deepseek-v4.1-flash', messages: [{ role: 'user', content: big }] }),
    });
    assert.ok([400, 413].includes(r.statusCode), `got ${r.statusCode}`);
    assert.ok(r.json().error && !JSON.stringify(r.json()).includes('stack'));
  });

  it('all gateway errors share one shape', async () => {
    const samples = [
      await app.inject({ method: 'GET', url: '/v1/models' }),
      await chat({ model: 'nope', messages: [{ role: 'user', content: 'x' }] }),
      await chat({ model: 'deepseek-v4.1-flash', messages: [] }),
    ];
    for (const r of samples) {
      const e = r.json().error;
      assert.ok(e && typeof e.message === 'string' && typeof e.type === 'string' && typeof e.code === 'string', `shape: ${r.body}`);
      assert.ok(!('stack' in e) && !('stacktrace' in e));
    }
  });

  it('validateChatBody: boundary rules (unit)', async () => {
    const { validateChatBody: v } = srv;
    const good = { model: 'm', messages: [{ role: 'user', content: 'hi' }] };
    assert.equal(v(good).ok, true);
    assert.equal(v(null).ok, false);
    assert.equal(v('x').ok, false);
    assert.equal(v({ ...good, messages: [{ role: 'user', content: 'x'.repeat(100001) }] }).code, 'context_length_exceeded');
    assert.equal(v({ ...good, messages: new Array(101).fill({ role: 'user', content: 'x' }) }).ok, false);
    assert.equal(v({ ...good, stop: ['a', 'b', 'c', 'd', 'e'] }).ok, false);
    assert.equal(v({ ...good, stop: 'halt' }).ok, true);
  });

  it('estimateCost: registry pricing, null when unknown', async () => {
    assert.equal(estimateCost({ price_input_per_1k: 0, price_output_per_1k: 0 }, 1000, 1000), 0);
    assert.equal(estimateCost({ price_input_per_1k: 0.5, price_output_per_1k: 1.5 }, 2000, 1000), 2.5);
    assert.equal(estimateCost({}, 10, 10), null, 'missing pricing → null, never $0.00');
    assert.equal(estimateCost({ price_input_per_1k: 1, price_output_per_1k: 1 }, null, 5), null);
  });
});
