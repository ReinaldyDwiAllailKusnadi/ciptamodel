'use strict';

// Provider abstraction — Phase 2: real gateway adapters.
//
// Model -> Router -> ProviderAdapter. The gateway (server.js) only talks to
// the ProviderAdapter interface; all upstream HTTP lives in adapter classes.
// Provider base URLs / credentials come from server-side config ONLY — a
// client can never supply an arbitrary fetch URL (SSRF-safe by construction).
//
// ProviderAdapter interface:
//   adapter.name / .displayName / .type / .enabled / .status
//   adapter.connected            // enabled && status === 'connected'
//   adapter.getModels()          // -> [{ id }]
//   adapter.chatCompletion({ model, messages, maxTokens, temperature, topP, stop, timeoutMs, signal })
//     -> { content, finishReason, inputTokens|null, outputTokens|null }
//   adapter.streamChatCompletion({ ...same, onToken, onUsage })
//     -> same shape (onToken(delta) per chunk; onUsage({inputTokens, outputTokens}) if upstream reports it)
//   adapter.healthCheck()        // -> { ok, latencyMs } — cheap, rate-limited by caller

class ProviderNotConnectedError extends Error {
  constructor(providerName) {
    super(`Provider '${providerName}' is not connected.`);
    this.name = 'ProviderNotConnectedError';
    this.code = 'provider_not_connected';
    this.provider = providerName;
    this.retryable = false;
    this.httpStatus = 503;
  }
}

// Normalized upstream failure. `retryable` drives gateway retry/fallback:
// client errors (4xx validation/auth) are never retried; timeouts and 5xx are.
class ProviderError extends Error {
  constructor(message, { provider = 'unknown', code = 'provider_error', httpStatus = 502, retryable = false, upstreamStatus = null } = {}) {
    super(message);
    this.name = 'ProviderError';
    this.code = code;
    this.provider = provider;
    this.httpStatus = httpStatus;
    this.retryable = retryable;
    this.upstreamStatus = upstreamStatus;
  }
}

function sanitizeRequestId(v) {
  const s = String(v || '');
  return /^[A-Za-z0-9_-]{1,64}$/.test(s) ? s : null;
}

function newRequestId() {
  const crypto = require('crypto');
  return 'cm_req_' + crypto.randomBytes(12).toString('hex');
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

  _notConnected() {
    return new ProviderNotConnectedError(this.name);
  }

  async getModels() { throw this._notConnected(); }
  async chatCompletion() { throw this._notConnected(); }
  async streamChatCompletion() { throw this._notConnected(); }
  async healthCheck() { return { ok: this.connected, latencyMs: 0 }; }

  toJSON() {
    return { name: this.name, display_name: this.displayName, type: this.type, enabled: this.enabled, status: this.status };
  }
}

// Shared OpenAI-compatible HTTP logic (request build, timeout, SSE parsing,
// error normalization). DeepSeek speaks this contract; future OpenAI-style
// providers reuse it. Credentials stay inside the adapter instance.
class OpenAICompatibleAdapter extends ProviderAdapter {
  constructor(descriptor, { apiKey = '', timeoutMs = 60000 } = {}) {
    super(descriptor);
    this.apiKey = apiKey;
    this.timeoutMs = timeoutMs;
    if (this.enabled && !this.apiKey) this.status = 'not_configured';
    else if (this.enabled && this.apiKey && (this.status === 'not_connected' || this.status === 'pending_credentials')) {
      this.status = 'connected';
    }
  }

  get configured() { return Boolean(this.apiKey); }

  async getModels() {
    this._assertConnected();
    const res = await this._fetch('/models', { method: 'GET' }, this.timeoutMs);
    if (!res.ok) throw this._httpError('list models', res);
    const data = await this._safeJson(res);
    if (!data || !Array.isArray(data.data)) throw new ProviderError('Malformed model list from provider.', { provider: this.name, code: 'provider_invalid_response', upstreamStatus: 200 });
    return data.data.filter((m) => m && m.id).map((m) => ({ id: String(m.id) }));
  }

  async chatCompletion({ model, messages, maxTokens, temperature, topP, stop, timeoutMs, signal } = {}) {
    this._assertConnected();
    const data = await this._post('/chat/completions', {
      model, messages,
      ...(maxTokens !== undefined ? { max_tokens: maxTokens } : {}),
      ...(temperature !== undefined ? { temperature } : {}),
      ...(topP !== undefined ? { top_p: topP } : {}),
      ...(stop !== undefined ? { stop } : {}),
      stream: false,
    }, timeoutMs || this.timeoutMs, signal);
    const choice = data && Array.isArray(data.choices) ? data.choices[0] : null;
    if (!choice || !choice.message) throw new ProviderError('Malformed completion response from provider.', { provider: this.name, code: 'provider_invalid_response', upstreamStatus: 200 });
    const usage = data.usage || {};
    return {
      content: choice.message.content ?? '',
      finishReason: choice.finish_reason || 'stop',
      inputTokens: Number.isFinite(usage.prompt_tokens) ? usage.prompt_tokens : null,
      outputTokens: Number.isFinite(usage.completion_tokens) ? usage.completion_tokens : null,
    };
  }

  async streamChatCompletion({ model, messages, maxTokens, temperature, topP, stop, timeoutMs, stallTimeoutMs, signal, onToken, onUsage } = {}) {
    this._assertConnected();
    const res = await this._fetch('/chat/completions', {
      method: 'POST',
      body: JSON.stringify({
        model, messages,
        ...(maxTokens !== undefined ? { max_tokens: maxTokens } : {}),
        ...(temperature !== undefined ? { temperature } : {}),
        ...(topP !== undefined ? { top_p: topP } : {}),
        ...(stop !== undefined ? { stop } : {}),
        stream: true,
        stream_options: { include_usage: true },
      }),
    }, timeoutMs || this.timeoutMs, signal);
    if (!res.ok || !res.body) throw this._httpError('stream completions', res);
    let full = '';
    let finishReason = 'stop';
    let usage = null;
    let buffer = '';
    const decoder = new TextDecoder();
    const stallMs = stallTimeoutMs || 60000;
    let lastChunkAt = Date.now();
    const reader = res.body.getReader();
    const finish = async () => { try { await reader.cancel(); } catch { /* ignore */ } };
    for (;;) {
      const remaining = stallMs - (Date.now() - lastChunkAt);
      if (remaining <= 0) { await finish(); throw new ProviderError('Provider stream stalled.', { provider: this.name, code: 'provider_timeout', httpStatus: 504, retryable: false }); }
      const readP = reader.read();
      const timerP = new Promise((_, rej) => setTimeout(() => rej(new ProviderError('Provider stream stalled.', { provider: this.name, code: 'provider_timeout', httpStatus: 504, retryable: false })), remaining));
      let chunk;
      try {
        chunk = await Promise.race([readP, timerP]);
      } catch (e) {
        if (e instanceof ProviderError) { await finish(); throw e; }
        throw e;
      }
      if (chunk.done) break;
      lastChunkAt = Date.now();
      buffer += decoder.decode(chunk.value, { stream: true });
      const parts = buffer.split('\n\n');
      buffer = parts.pop();
      for (const part of parts) {
        for (const line of part.split('\n')) {
          const t = line.trim();
          if (!t.startsWith('data:')) continue;
          const payload = t.slice(5).trim();
          if (!payload || payload === '[DONE]') continue;
          let evt;
          try { evt = JSON.parse(payload); } catch { continue; }
          if (evt.usage && Number.isFinite(evt.usage.prompt_tokens)) {
            usage = { inputTokens: evt.usage.prompt_tokens, outputTokens: Number.isFinite(evt.usage.completion_tokens) ? evt.usage.completion_tokens : 0 };
            if (onUsage) { try { await onUsage(usage); } catch { /* ignore */ } }
            continue;
          }
          const delta = evt.choices && evt.choices[0] ? (evt.choices[0].delta || {}) : {};
          if (evt.choices && evt.choices[0] && evt.choices[0].finish_reason) finishReason = evt.choices[0].finish_reason;
          const text = typeof delta.content === 'string' ? delta.content : '';
          if (text) { full += text; if (onToken) { try { await onToken(text); } catch { /* ignore */ } } }
        }
      }
    }
    return { content: full, finishReason, inputTokens: usage ? usage.inputTokens : null, outputTokens: usage ? usage.outputTokens : null };
  }

  async healthCheck() {
    if (!this.connected) return { ok: false, latencyMs: 0, status: this.status };
    const t0 = Date.now();
    try {
      await this.getModels();
      return { ok: true, latencyMs: Date.now() - t0 };
    } catch {
      return { ok: false, latencyMs: Date.now() - t0 };
    }
  }

  _assertConnected() {
    if (!this.connected) throw this._notConnected();
  }

  // URL is always descriptor baseUrl + fixed path — never client-controlled.
  async _fetch(pathname, init, timeoutMs, outerSignal) {
    if (!/^https?:\/\//.test(this.baseUrl)) {
      throw new ProviderError(`Provider '${this.name}' has no valid base URL configured.`, { provider: this.name, code: 'provider_not_connected', httpStatus: 503 });
    }
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(new Error('upstream timeout')), timeoutMs || this.timeoutMs);
    if (outerSignal) {
      if (outerSignal.aborted) ctrl.abort(outerSignal.reason);
      else outerSignal.addEventListener('abort', () => ctrl.abort(outerSignal.reason), { once: true });
    }
    try {
      return await fetch(this.baseUrl.replace(/\/$/, '') + pathname, {
        ...init,
        signal: ctrl.signal,
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${this.apiKey}`, ...(init.headers || {}) },
      });
    } catch (e) {
      throw new ProviderError(`Provider request failed: ${e.name === 'AbortError' ? 'timeout' : 'network error'}.`, {
        provider: this.name,
        code: e.name === 'AbortError' ? 'provider_timeout' : 'provider_unavailable',
        httpStatus: e.name === 'AbortError' ? 504 : 502,
        retryable: true,
      });
    } finally { clearTimeout(timer); }
  }

  async _post(pathname, body, timeoutMs, signal) {
    const res = await this._fetch(pathname, { method: 'POST', body: JSON.stringify(body) }, timeoutMs, signal);
    if (!res.ok) throw this._httpError('completions', res);
    const data = await this._safeJson(res);
    if (!data) throw new ProviderError('Malformed completion response from provider.', { provider: this.name, code: 'provider_invalid_response', upstreamStatus: res.status });
    return data;
  }

  _httpError(op, res) {
    const s = res.status;
    if (s === 401 || s === 403) {
      return new ProviderError(`Provider authentication failed during ${op}.`, { provider: this.name, code: 'provider_authentication_error', httpStatus: 502, retryable: false, upstreamStatus: s });
    }
    if (s === 429) {
      return new ProviderError(`Provider rate limit hit during ${op}.`, { provider: this.name, code: 'provider_rate_limit', httpStatus: 503, retryable: true, upstreamStatus: s });
    }
    if (s === 408 || s === 504) {
      return new ProviderError(`Provider timeout during ${op}.`, { provider: this.name, code: 'provider_timeout', httpStatus: 504, retryable: true, upstreamStatus: s });
    }
    if (s >= 500) {
      return new ProviderError(`Provider unavailable during ${op}.`, { provider: this.name, code: 'provider_unavailable', httpStatus: 502, retryable: true, upstreamStatus: s });
    }
    return new ProviderError(`Provider request failed during ${op} (status ${s}).`, { provider: this.name, code: 'provider_error', httpStatus: 502, retryable: false, upstreamStatus: s });
  }

  async _safeJson(res) {
    try { return await res.json(); } catch { return null; }
  }
}

// DeepSeek adapter: official OpenAI-compatible API. Only reads server-side
// config (base URL + key from env); nothing here is client-influenced.
// base_url falls back to config when the registry descriptor lacks one.
class DeepSeekAdapter extends OpenAICompatibleAdapter {
  constructor(config, descriptor) {
    const d = { name: 'deepseek', display_name: 'DeepSeek', type: 'openai-compatible', enabled: true, ...(descriptor || {}) };
    if (!d.base_url) d.base_url = config.deepseek.baseUrl;
    super(d, {
      apiKey: config.deepseek.apiKey,
      timeoutMs: config.deepseek.timeoutMs,
    });
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

// Build a router from the DB-backed registries. DeepSeek becomes a live
// adapter when DEEPSEEK_API_KEY is set; otherwise registry/interface only
// and the app still boots (chat returns honest 503).
// `overrides.adapters` lets tests inject deterministic mock adapters.
function buildRouter(db, config, overrides = {}) {
  const models = db.listModels({ enabledOnly: false });
  const adapters = {};
  for (const p of db.listProviders()) {
    if (overrides.adapters && overrides.adapters[p.name]) {
      adapters[p.name] = overrides.adapters[p.name];
      continue;
    }
    if (p.name === 'deepseek' && config) {
      adapters[p.name] = new DeepSeekAdapter(config, p);
    } else {
      adapters[p.name] = new ProviderAdapter(p);
    }
  }
  return new Router(models, adapters);
}

// Test double: deterministic adapter implementing the same interface.
// No network — scripted responses / failures for gateway tests.
class MockAdapter extends ProviderAdapter {
  constructor(descriptor = { name: 'mock', display_name: 'Mock', enabled: true, status: 'connected' }, script = {}) {
    super({ ...descriptor, enabled: true, status: 'connected' });
    this.script = script;
    this.calls = [];
  }
  async getModels() { return [{ id: 'mock-model' }]; }
  async chatCompletion(req = {}) {
    this.calls.push({ op: 'chat', req });
    if (this.script.fail) throw this.script.fail;
    return {
      content: this.script.content ?? 'mock reply',
      finishReason: 'stop',
      inputTokens: this.script.inputTokens ?? 10,
      outputTokens: this.script.outputTokens ?? 5,
    };
  }
  async streamChatCompletion({ onToken, onUsage } = {}) {
    this.calls.push({ op: 'stream' });
    if (this.script.fail) throw this.script.fail;
    const text = this.script.content ?? 'mock streamed reply';
    for (const word of text.split(' ')) {
      if (onToken) await onToken(word + ' ');
    }
    if (onUsage && this.script.reportUsage !== false) {
      await onUsage({ inputTokens: this.script.inputTokens ?? 10, outputTokens: this.script.outputTokens ?? 5 });
    }
    return { content: text, finishReason: 'stop', inputTokens: this.script.inputTokens ?? 10, outputTokens: this.script.outputTokens ?? 5 };
  }
  async healthCheck() { return { ok: true, latencyMs: 1 }; }
}

module.exports = {
  ProviderAdapter,
  OpenAICompatibleAdapter,
  DeepSeekAdapter,
  MockAdapter,
  ProviderError,
  ProviderNotConnectedError,
  Router,
  buildRouter,
  newRequestId,
  sanitizeRequestId,
};
