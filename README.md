# CiptaModel — Unified AI API Gateway

One API key, multiple AI models. OpenAI-compatible HTTP API.

Public contract: `https://ciptamodel.web.id/v1`

- `GET /v1/models` — model registry (Bearer key required)
- `POST /v1/chat/completions` — chat inference, JSON + SSE streaming

## Architecture

```
client (your app / Cursor / Open WebUI)
  |  Authorization: Bearer sk-cm-live-...
  v
CiptaModel gateway (Fastify, 127.0.0.1:3000)
  |-- session auth + CSRF (console) / Bearer keys (/v1)
  |-- validate -> model registry -> rate/quota (before upstream)
  |-- router -> provider adapter (DeepSeek first)
  v
upstream provider (server-side credentials only)
  |
  v
normalized OpenAI-compatible response + usage logging
```

- `src/server.js` — Fastify app: console, `/v1` gateway pipeline,
  session auth + CSRF, `X-Request-ID` tracing, retry (transient,
  non-stream only), registry-driven fallback, cost estimation.
- `src/providers.js` — `ProviderAdapter` interface,
  `OpenAICompatibleAdapter` (timeout, SSE parsing, error normalization),
  `DeepSeekAdapter` (server-side env credentials only),
  `MockAdapter` test double.
- `src/db.js` — SQLite (`better-sqlite3`, Postgres-compatible DDL):
  users, api_keys (hash only), requests, provider_attempts, plans,
  sessions, models, providers, subscriptions, audit_logs.
  Additive `migrate()` + `seed()`.
- `src/limits.js` — rate/quota abstraction (in-memory; Redis-ready).
- `src/config.js` — plan defaults, model/provider seeds, gateway tuning.
- `public/` — vanilla CSS + JS console, no build step, no CDN deps.
- `tests/` — gateway/auth/registry/limits/docs (`platform`),
  SSRF/secret-leak/validation/cost (`security`, `hardening`),
  opt-in live DeepSeek (`smoke`).

## Features

- OpenAI-compatible `/v1` (works with existing clients/tools)
- Per-account API keys, shown once, revocable immediately
- Model + provider registries (stable model IDs, swappable upstreams)
- Rate limits + daily quotas enforced before any upstream contact
- JSON + SSE streaming, long-timeout safe behind a reverse proxy
- Per-key usage, request logs, `X-Request-ID` tracing
- Honest errors: without provider credentials chat returns
  `503 provider_not_connected`, never a fake reply

## Tech stack

Node 22 · Fastify 5 · better-sqlite3 · bcryptjs ·
@fastify/cookie + @fastify/formbody · vanilla HTML/CSS/JS ·
Apache or nginx reverse proxy · systemd · SQLite (Postgres-compatible DDL)

## Installation

```bash
cp .env.example .env   # set SESSION_SECRET (min 32 chars) + DEEPSEEK_API_KEY
npm install
npm run init-db
npm start              # http://localhost:3000
```

## Environment variables

| Name | Default | Notes |
|---|---|---|
| `NODE_ENV` | — | `production` on the server (Secure cookies) |
| `HOST` | `127.0.0.1` | loopback behind reverse proxy; `0.0.0.0` for Docker |
| `PORT` | `3000` | app listen port |
| `BASE_URL` | `http://localhost:3000` | production: `https://ciptamodel.web.id` |
| `PUBLIC_API_BASE_URL` | `https://ciptamodel.web.id/v1` | shown in console + docs |
| `DATABASE_PATH` | `./data/ciptamodel.db` | SQLite file |
| `SESSION_SECRET` | — | required, min 32 chars, never commit |
| `DEEPSEEK_API_KEY` | empty | server-side only; empty = boot without inference |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com` | server-side only |
| `DEEPSEEK_TIMEOUT_MS` | `60000` | upstream timeout |
| `GATEWAY_BODY_LIMIT_BYTES` | `1048576` | max JSON body |
| `GATEWAY_STREAM_STALL_MS` | `60000` | stall timeout for streams |
| `REDIS_URL` | empty | empty = in-memory limiter |

`.env` is git-ignored (mode `0600` in production). Never commit secrets.

## Local development

```bash
npm run dev          # watch mode, http://localhost:3000
npm test             # mock adapters only, no credentials needed
npm run lint
```

Live upstream smoke (opt-in only):

```bash
RUN_PROVIDER_SMOKE_TESTS=true DEEPSEEK_API_KEY=... npm test
```

## Production deployment

VPS layout: app on `127.0.0.1:3000` → Apache reverse proxy → public
`https://ciptamodel.web.id` (HTTP/301 → HTTPS; TLS terminates at the edge).

```bash
# 1. deploy code to /root/ciptamodel (branch main), install deps
# 2. production .env (0600): NODE_ENV=production, HOST=127.0.0.1,
#    PORT=3000, BASE_URL + PUBLIC_API_BASE_URL on https://ciptamodel.web.id
systemctl daemon-reload
systemctl enable --now ciptamodel
systemctl status ciptamodel
apache2ctl configtest && systemctl reload apache2
```

Notes: proxy needs long timeouts + unbuffered streaming for SSE
(`ProxyTimeout 300`, `flushpackets=on`, no `DEFLATE` on the proxy path);
`X-Forwarded-Proto https` + `mod_remoteip` so the app sees the real
client IP. Staged configs live in `deploy/` (systemd unit, Apache vhost).

## API usage

```bash
export CIPTAMODEL_API_KEY="sk-cm-live-..."   # Dashboard > API Keys, shown once

curl https://ciptamodel.web.id/v1/models \
  -H "Authorization: Bearer $CIPTAMODEL_API_KEY"

curl https://ciptamodel.web.id/v1/chat/completions \
  -H "Authorization: Bearer $CIPTAMODEL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"deepseek-v4.1-flash","messages":[{"role":"user","content":"Hello"}]}'

# streaming
curl -N https://ciptamodel.web.id/v1/chat/completions \
  -H "Authorization: Bearer $CIPTAMODEL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"deepseek-v4.1-flash","messages":[{"role":"user","content":"Hello"}],"stream":true}'
```

```python
from openai import OpenAI
client = OpenAI(
    api_key="sk-cm-live-...",               # Dashboard > API Keys
    base_url="https://ciptamodel.web.id/v1",
)
resp = client.chat.completions.create(
    model="deepseek-v4.1-flash",
    messages=[{"role": "user", "content": "Hello"}],
)
print(resp.choices[0].message.content)
```

Cursor / Cline / Open WebUI: base URL `https://ciptamodel.web.id/v1`
(or `http://localhost:3000/v1` locally), model `deepseek-v4.1-flash`.
Full reference at `/docs` on the running server.

## Security notes

- API keys stored as SHA-256 hashes; passwords as bcrypt. Full key
  shown once, never recoverable; revocation returns `401` immediately.
- Provider credentials are server-side env only — never in frontend,
  logs, errors, or DB. Gateway errors never leak secrets, stacks, or paths.
- Sessions: `HttpOnly`, `SameSite=Lax`, `Secure` in production + per-session
  CSRF tokens on console POSTs. `/v1/*` uses Bearer keys (CSRF-exempt).
- Headers on every response: `nosniff`, `DENY` framing, strict
  `Referrer-Policy`, minimal `Permissions-Policy`, self-only CSP.
- SSRF guard: client cannot choose provider URLs; callback/redirect
  targets restricted to http(s).
- Request logs carry IDs, model, tokens, latency, status — no headers,
  keys, or bodies. No CORS allowlist: browser clients call same-origin
  or server-side.
