# CiptaModel — Unified AI API Gateway (Phase 2: Real Gateway)

One API key (`sk-cm-live-…`), multiple AI models, OpenAI-compatible API.

Public contract: `https://ciptamodel.com/v1`
- `GET /v1/models` — registry read, Bearer key required
- `POST /v1/chat/completions` — **live**: real DeepSeek inference, JSON + SSE streaming

## Quickstart

```bash
cp .env.example .env   # set SESSION_SECRET (min 32 chars) + DEEPSEEK_API_KEY
npm install
npm run init-db        # create + migrate + seed ./data/ciptamodel.db
npm start              # http://localhost:3000
npm test               # 45 tests, mock adapters (no credentials needed)
```

Without `DEEPSEEK_API_KEY` the app still boots; chat returns honest
`503 provider_not_connected`. Provider status: `/health`.

```bash
curl localhost:3000/v1/chat/completions \
  -H "Authorization: Bearer sk-cm-live-..." \
  -H "Content-Type: application/json" \
  -d '{"model":"deepseek-v4.1-flash","messages":[{"role":"user","content":"Hello"}]}'
```

Cursor / Cline / Open WebUI: base URL `https://ciptamodel.com/v1`
(or `http://localhost:3000/v1` locally), model `deepseek-v4.1-flash`. Full docs at `/docs`.

## Architecture

Request flow: Bearer key → authenticate → validate → model registry →
rate/quota (before upstream) → router → provider adapter → normalized
OpenAI-compatible response → usage + attempt logging.

- `src/server.js` — Fastify app: console, `/v1` gateway pipeline (`runGateway`),
  session auth + CSRF, request IDs (`X-Request-ID`), retry (transient, non-stream
  only), registry-driven fallback, cost estimation from registry pricing.
- `src/providers.js` — `ProviderAdapter` interface, `OpenAICompatibleAdapter`
  (timeout, SSE parsing, error normalization), `DeepSeekAdapter` (server-side
  env credentials only — never client-controlled URLs), `MockAdapter` test double.
- `src/db.js` — SQLite (Postgres-compatible DDL): users, api_keys (hash only),
  requests (+`request_id`, +`est_cost`), provider_attempts, plans, sessions,
  models, providers, subscriptions, audit_logs. Additive `migrate()` + `seed()`.
- `src/limits.js` — rate/quota abstraction (in-memory backend; Redis-ready).
- `src/config.js` — plan defaults, model/provider seeds, gateway tuning
  (`DEEPSEEK_TIMEOUT_MS`, `GATEWAY_BODY_LIMIT_BYTES`, `GATEWAY_STREAM_STALL_MS`).
- `public/` — console CSS + playground JS (OpenAI-shaped responses).
- `tests/` — `platform.test.js` (gateway/auth/registry/limits/docs),
  `security.test.js` (SSRF, secret leakage, validation, cost), `smoke.test.js`
  (opt-in live DeepSeek: `RUN_PROVIDER_SMOKE_TESTS=true DEEPSEEK_API_KEY=...`).

## Tests / deploy

```bash
npm test   # mock adapters only; live smoke skipped unless explicitly enabled
npm run lint
```

Docker: `docker compose up --build` (SQLite volume `./data`). Inject
`DEEPSEEK_API_KEY` via environment (never bake into images). Behind a reverse
proxy, route `ciptamodel.com/*` here and keep the public contract
`ciptamodel.com/v1/*`.
