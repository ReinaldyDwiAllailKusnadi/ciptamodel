'use strict';

// SQLite (better-sqlite3) storage layer.
// Schema is Postgres-compatible by design (plain tables, no exotic types) so
// migration is a DDL port, not a rewrite. All secrets stored hashed.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const config = require('./config');

let db;

function connect(dbPath = config.dbPath) {
  if (db) return db;
  const dir = path.dirname(path.resolve(dbPath));
  fs.mkdirSync(dir, { recursive: true });
  db = new Database(path.resolve(dbPath));
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  migrate(db);
  seed(db);
  return db;
}

function migrate(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      plan TEXT NOT NULL DEFAULT 'free',
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    CREATE TABLE IF NOT EXISTS api_keys (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      key_hash TEXT NOT NULL UNIQUE,
      key_prefix TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      last_used_at TEXT,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      revoked_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
    CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
    CREATE TABLE IF NOT EXISTS requests (
      id TEXT PRIMARY KEY,
      user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
      api_key_id TEXT REFERENCES api_keys(id) ON DELETE SET NULL,
      model_id TEXT NOT NULL,
      provider TEXT NOT NULL,
      input_tokens INTEGER NOT NULL DEFAULT 0,
      output_tokens INTEGER NOT NULL DEFAULT 0,
      total_tokens INTEGER NOT NULL DEFAULT 0,
      latency_ms INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'success',
      error_code TEXT,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    CREATE INDEX IF NOT EXISTS idx_requests_user_created ON requests(user_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_requests_key_created ON requests(api_key_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_requests_model_created ON requests(model_id, created_at);
    CREATE TABLE IF NOT EXISTS plans (
      name TEXT PRIMARY KEY,
      requests_per_day INTEGER NOT NULL,
      tokens_per_day INTEGER NOT NULL,
      rpm INTEGER NOT NULL,
      price_input_per_1k REAL NOT NULL DEFAULT 0,
      price_output_per_1k REAL NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      expires_at TEXT NOT NULL
    );
    -- Model registry: DB-backed so models can be enabled/priced without deploys.
    CREATE TABLE IF NOT EXISTS models (
      id TEXT PRIMARY KEY,
      model_id TEXT NOT NULL UNIQUE,
      display_name TEXT NOT NULL,
      provider TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      context_window INTEGER NOT NULL DEFAULT 0,
      max_output_tokens INTEGER NOT NULL DEFAULT 0,
      price_input_per_1k REAL NOT NULL DEFAULT 0,
      price_output_per_1k REAL NOT NULL DEFAULT 0,
      capabilities TEXT NOT NULL DEFAULT '[]',
      fallback_model TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    CREATE INDEX IF NOT EXISTS idx_models_provider ON models(provider);
    -- Provider catalog: Phase 1 = registry/interface only, no upstream calls.
    CREATE TABLE IF NOT EXISTS providers (
      name TEXT PRIMARY KEY,
      display_name TEXT NOT NULL,
      type TEXT NOT NULL DEFAULT 'openai-compatible',
      base_url TEXT NOT NULL DEFAULT '',
      enabled INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'not_connected',
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    -- Billing foundation: one subscription row per user.
    CREATE TABLE IF NOT EXISTS subscriptions (
      user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      plan TEXT NOT NULL DEFAULT 'free',
      status TEXT NOT NULL DEFAULT 'active',
      current_period_end TEXT,
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    -- Audit trail for security-sensitive actions.
    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      target_type TEXT,
      target_id TEXT,
      ip TEXT,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    CREATE INDEX IF NOT EXISTS idx_audit_user_created ON audit_logs(user_id, created_at);
  `);
  // Additive migrations for databases created before these columns existed.
  for (const sql of [
    `ALTER TABLE sessions ADD COLUMN csrf_token TEXT`,
    `ALTER TABLE users ADD COLUMN name TEXT`,
  ]) {
    try { db.exec(sql); } catch { /* already migrated */ }
  }
}

function seed(db) {
  const planStmt = db.prepare(`INSERT OR IGNORE INTO plans
    (name, requests_per_day, tokens_per_day, rpm, price_input_per_1k, price_output_per_1k)
    VALUES (@name, @requests_per_day, @tokens_per_day, @rpm, @price_input_per_1k, @price_output_per_1k)`);
  for (const [name, p] of Object.entries(config.defaultPlans)) {
    planStmt.run({ name, ...p });
  }
  const modelStmt = db.prepare(`INSERT OR IGNORE INTO models
    (id, model_id, display_name, provider, enabled, context_window, max_output_tokens,
     price_input_per_1k, price_output_per_1k, capabilities, fallback_model, status)
    VALUES (@id, @model_id, @display_name, @provider, @enabled, @context_window, @max_output_tokens,
     @price_input_per_1k, @price_output_per_1k, @capabilities, @fallback_model, 'active')`);
  for (const m of config.models) {
    modelStmt.run({
      id: `mdl_${m.id.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}`,
      model_id: m.id,
      display_name: m.display_name,
      provider: m.provider,
      enabled: m.enabled ? 1 : 0,
      context_window: m.context_window || 0,
      max_output_tokens: m.max_output_tokens || 0,
      price_input_per_1k: m.price_input_per_1k || 0,
      price_output_per_1k: m.price_output_per_1k || 0,
      capabilities: JSON.stringify(m.capabilities || []),
      fallback_model: (m.fallback && m.fallback.model) || null,
    });
  }
  const provStmt = db.prepare(`INSERT OR IGNORE INTO providers (name, display_name, type, base_url, enabled, status)
    VALUES (@name, @display_name, @type, @base_url, @enabled, @status)`);
  for (const p of config.providers) {
    provStmt.run(p);
  }
}

function uid(prefix = 'id') {
  return `${prefix}_${crypto.randomBytes(12).toString('hex')}`;
}

// API keys: format sk-cm-live-<base64url 32B>. Only sha256 hash is stored.
function generateApiKey() {
  const secret = 'sk-cm-live-' + crypto.randomBytes(32).toString('base64url');
  const hash = crypto.createHash('sha256').update(secret).digest('hex');
  return { secret, hash, prefix: secret.slice(0, 14) };
}

function hashSecret(secret) {
  return crypto.createHash('sha256').update(secret).digest('hex');
}

function maskKey(prefix) {
  return `${prefix}••••••••`;
}

// Model registry read: DB is source of truth, config is fallback seed.
function listModels({ enabledOnly = true } = {}) {
  const d = getDb();
  const rows = d.prepare(`SELECT * FROM models ${enabledOnly ? 'WHERE enabled = 1' : ''} ORDER BY model_id`).all();
  return rows.map((r) => ({
    id: r.model_id,
    display_name: r.display_name,
    provider: r.provider,
    upstream_model: (config.models.find((m) => m.id === r.model_id) || {}).upstream_model || r.model_id,
    enabled: r.enabled === 1,
    context_window: r.context_window,
    max_output_tokens: r.max_output_tokens,
    price_input_per_1k: r.price_input_per_1k,
    price_output_per_1k: r.price_output_per_1k,
    capabilities: JSON.parse(r.capabilities || '[]'),
    description: (config.models.find((m) => m.id === r.model_id) || {}).description || '',
    fallback: r.fallback_model ? { model: r.fallback_model } : null,
    status: r.status,
  }));
}

function listProviders() {
  return getDb().prepare('SELECT * FROM providers ORDER BY name').all()
    .map((r) => ({ ...r, enabled: r.enabled === 1 }));
}

function audit({ userId = null, action, targetType = null, targetId = null, ip = null }) {
  try {
    getDb().prepare(`INSERT INTO audit_logs (id, user_id, action, target_type, target_id, ip)
      VALUES (?,?,?,?,?,?)`).run(uid('aud'), userId, action, targetType, targetId, ip);
  } catch { /* audit must never break the request */ }
}

function getDb() {
  if (!db) throw new Error('DB not connected — call connect() first');
  return db;
}

// Test-only: drop the singleton so another file can connect to its own DB.
function _reset() { db = null; }

module.exports = { connect, getDb, _reset, uid, generateApiKey, hashSecret, maskKey, listModels, listProviders, audit };
