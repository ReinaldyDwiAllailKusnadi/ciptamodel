'use strict';

// Central configuration. Quotas/pricing live here as defaults but can be
// overridden per-plan via the `plans` table (DB wins over these values).
// Nothing provider-specific is hardcoded in controllers — see providers.js.

function env(name, fallback = '') {
  const v = process.env[name];
  return v === undefined || v === '' ? fallback : v;
}

const config = {
  port: parseInt(env('PORT', '3000'), 10),
  baseUrl: env('BASE_URL', 'http://localhost:3000'),
  publicApiBaseUrl: env('PUBLIC_API_BASE_URL', 'https://ciptamodel.com/v1'),
  dbPath: env('DATABASE_PATH', './data/ciptamodel.db'),
  sessionSecret: env('SESSION_SECRET', 'dev-only-secret-change-me-32-chars-min'),
  redisUrl: env('REDIS_URL', ''), // empty => in-memory limiter (see limits.js)

  // Default plan quotas. Admins can change these at runtime via the
  // `plans` table without touching code.
  defaultPlans: {
    free:       { requests_per_day: 100,   tokens_per_day: 50000,    rpm: 10,  price_input_per_1k: 0, price_output_per_1k: 0 },
    developer:  { requests_per_day: 5000,  tokens_per_day: 2000000,  rpm: 60,  price_input_per_1k: 0, price_output_per_1k: 0 },
    pro:        { requests_per_day: 100000,tokens_per_day: 50000000, rpm: 300, price_input_per_1k: 0, price_output_per_1k: 0 },
    enterprise: { requests_per_day: -1,    tokens_per_day: -1,       rpm: -1,  price_input_per_1k: 0, price_output_per_1k: 0 },
  },

  // Provider catalog (Phase 1: registry/interface only — no upstream calls).
  // `enabled` + `status` are mirrored into the providers DB table (DB wins).
  providers: [
    { name: 'deepseek',    display_name: 'DeepSeek',    type: 'openai-compatible', base_url: 'https://api.deepseek.com', enabled: 1, status: 'pending_credentials' },
    { name: 'openrouter',  display_name: 'OpenRouter',  type: 'openai-compatible', base_url: 'https://openrouter.ai/api/v1', enabled: 0, status: 'not_connected' },
    { name: 'huggingface', display_name: 'Hugging Face', type: 'openai-compatible', base_url: '', enabled: 0, status: 'not_connected' },
    { name: 'anthropic',   display_name: 'Anthropic',   type: 'native', base_url: '', enabled: 0, status: 'not_connected' },
    { name: 'google',      display_name: 'Google',      type: 'native', base_url: '', enabled: 0, status: 'not_connected' },
  ],

  // Model registry: the single source of truth for routing.
  // `provider` names a provider adapter (see providers.js); `upstream_model`
  // is the provider-side model id used when Phase 2 connects adapters;
  // `fallback` is an optional { model } for failover.
  models: [
    {
      id: 'deepseek-v4.1-flash',
      display_name: 'DeepSeek V4.1 Flash',
      provider: 'deepseek',
      upstream_model: 'deepseek-chat',
      enabled: true,
      context_window: 1000000,
      max_output_tokens: 8192,
      price_input_per_1k: 0,
      price_output_per_1k: 0,
      capabilities: ['chat', 'coding', 'streaming', 'long-context', 'tool-calling'],
      description: 'Fast long-context chat/coding model. Default CiptaModel gateway model.',
      fallback: null,
    },
  ],
};

module.exports = config;
