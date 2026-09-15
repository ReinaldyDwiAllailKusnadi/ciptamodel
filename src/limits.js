'use strict';

// Rate-limit / quota foundation.
// Abstraction boundary: everything goes through these functions, so moving
// from the in-memory backend to Redis only changes this module.
// Backend interface: { hit(key, rpm) -> { limited } , resetForTests() }.

function createMemoryBackend() {
  const buckets = new Map(); // key -> { windowStart, count }
  const timer = setInterval(() => {
    const now = Date.now();
    for (const [k, b] of buckets) if (now - b.windowStart > 120000) buckets.delete(k);
  }, 60000);
  if (timer.unref) timer.unref();
  return {
    hit(key, rpm) {
      if (rpm === undefined || rpm === null || rpm < 0) return { limited: false };
      const now = Date.now();
      const b = buckets.get(key);
      if (!b || now - b.windowStart > 60000) {
        buckets.set(key, { windowStart: now, count: 1 });
        return { limited: false };
      }
      b.count += 1;
      return { limited: b.count > rpm, count: b.count };
    },
    resetForTests() { buckets.clear(); },
    _buckets: buckets,
  };
}

// Per-scope minute-rate check. Returns { limited, scope?, message? }.
function checkRate({ backend, userId, keyId, modelId, ip, rpm }) {
  const scopes = [
    [`rpm:key:${keyId}`, rpm],
    [`rpm:user:${userId}`, rpm === undefined || rpm === null ? rpm : rpm * 5],
    [`rpm:ip:${ip}`, Math.max((rpm ?? 10) * 5, 60)],
  ];
  if (modelId) scopes.push([`rpm:model:${modelId}`, rpm === undefined || rpm === null ? rpm : rpm * 5]);
  for (const [scope, val] of scopes) {
    if (backend.hit(scope, val).limited) {
      const kind = scope.split(':')[1];
      return { limited: true, scope, message: `Rate limit exceeded (${kind}). Retry in a minute.` };
    }
  }
  return { limited: false };
}

// Daily quota check against the plans table. -1 = unlimited.
function checkQuota(db, userId, plan) {
  const dayStart = new Date();
  dayStart.setHours(0, 0, 0, 0);
  if (plan.requests_per_day >= 0) {
    const c = db.prepare('SELECT COUNT(*) c FROM requests WHERE user_id = ? AND created_at >= ?')
      .get(userId, dayStart.toISOString()).c;
    if (c >= plan.requests_per_day) {
      return { limited: true, message: 'Daily request quota exceeded for your plan.' };
    }
  }
  if (plan.tokens_per_day >= 0) {
    const t = db.prepare('SELECT COALESCE(SUM(total_tokens),0) t FROM requests WHERE user_id = ? AND created_at >= ?')
      .get(userId, dayStart.toISOString()).t;
    if (t >= plan.tokens_per_day) {
      return { limited: true, message: 'Daily token quota exceeded for your plan.' };
    }
  }
  return { limited: false };
}

module.exports = { createMemoryBackend, checkRate, checkQuota };
