'use strict';
// Optional live-provider smoke test. NEVER runs in the normal suite.
// Enable explicitly: RUN_PROVIDER_SMOKE_TESTS=true DEEPSEEK_API_KEY=... npm test
// Prints no secrets; asserts only shape + latency.
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const enabled = process.env.RUN_PROVIDER_SMOKE_TESTS === 'true' && Boolean(process.env.DEEPSEEK_API_KEY);

describe('provider smoke (opt-in, live network)', () => {
  it('deepseek chat completion shape', async (t) => {
    if (!enabled) { t.skip('set RUN_PROVIDER_SMOKE_TESTS=true + DEEPSEEK_API_KEY to run'); return; }
    const { DeepSeekAdapter } = require('../src/providers.js');
    const a = new DeepSeekAdapter({
      deepseek: {
        apiKey: process.env.DEEPSEEK_API_KEY,
        baseUrl: process.env.DEEPSEEK_BASE_URL || 'https://api.deepseek.com',
        timeoutMs: 60000,
      },
    }, { name: 'deepseek', enabled: true, status: 'connected' });
    const t0 = Date.now();
    const out = await a.chatCompletion({ model: 'deepseek-chat', messages: [{ role: 'user', content: 'Reply with the word OK.' }], maxTokens: 16 });
    assert.ok(typeof out.content === 'string' && out.content.length > 0);
    assert.ok(Date.now() - t0 < 60000);
  });
});
