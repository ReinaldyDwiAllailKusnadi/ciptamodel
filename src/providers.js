'use strict';

// Provider abstraction — Phase 1: registry/interface ONLY.
// No upstream network calls exist in this module (no fetch, no API keys,
// no credentials). Phase 2 will add connected adapters behind this interface.
//
// Model -> Router -> ProviderAdapter. Public API contract never changes
// when providers are added, removed, or swapped.
//
// ProviderAdapter interface:
//   adapter.name
//   adapter.status            // 'connected' | 'pending_credentials' | 'not_connected'
//   adapter.getModels()       // -> [{ id }]
//   adapter.chatCompletion({ model, messages, maxTokens, temperature })
//   adapter.streamChatCompletion({ ...same, onToken })

class ProviderNotConnectedError extends Error {
  constructor(providerName) {
    super(`Provider '${providerName}' is not connected yet (Phase 2).`);
    this.name = 'ProviderNotConnectedError';
    this.code = 'provider_not_connected';
    this.provider = providerName;
  }
}

class ProviderAdapter {
  constructor(descriptor) {
    if (!descriptor || !descriptor.name) throw new Error('ProviderAdapter requires a descriptor with a name');
    this.name = descriptor.name;
    this.displayName = descriptor.display_name || descriptor.name;
    this.type = descriptor.type || 'openai-compatible';
    this.baseUrl = descriptor.base_url || '';
    this.enabled = descriptor.enabled === true;
    this.status = descriptor.status || 'not_connected';
  }

  get connected() { return this.enabled && this.status === 'connected'; }

  _notConnected(op) {
    return new ProviderNotConnectedError(this.name);
  }

  async getModels() { throw this._notConnected('getModels'); }
  async chatCompletion() { throw this._notConnected('chatCompletion'); }
  async streamChatCompletion() { throw this._notConnected('streamChatCompletion'); }

  toJSON() {
    return { name: this.name, display_name: this.displayName, type: this.type, enabled: this.enabled, status: this.status };
  }
}

// Registry + router: resolves a public model id to { entry, adapter }.
// Pure routing — never performs inference.
class Router {
  constructor(modelRegistry, adapters) {
    this.models = new Map((modelRegistry || []).map((m) => [m.id, m]));
    this.adapters = adapters || {}; // { name: ProviderAdapter }
  }

  resolve(modelId) {
    const entry = this.models.get(modelId);
    if (!entry || entry.enabled === false) return { error: 'model_not_found', entry: null, adapter: null };
    const adapter = this.adapters[entry.provider];
    if (!adapter || !adapter.connected) return { error: 'provider_not_connected', entry, adapter: adapter || null };
    return { entry, adapter };
  }

  // OpenAI-compatible model list (registry read — no provider call).
  enabledModels() {
    return [...this.models.values()]
      .filter((m) => m.enabled !== false)
      .map((m) => ({ id: m.id, object: 'model', created: 0, owned_by: m.provider }));
  }

  modelDetails({ enabledOnly = true } = {}) {
    const all = [...this.models.values()];
    return enabledOnly ? all.filter((m) => m.enabled !== false) : all;
  }
}

// Build a router from the DB-backed registries (db.listModels/listProviders).
// `db` is the src/db.js module (injected to keep this module dependency-free).
function buildRouter(db) {
  const models = db.listModels({ enabledOnly: false });
  const adapters = {};
  for (const p of db.listProviders()) adapters[p.name] = new ProviderAdapter(p);
  return new Router(models, adapters);
}

module.exports = { ProviderAdapter, ProviderNotConnectedError, Router, buildRouter };
