# CiptaModel — Unified AI API Gateway (Phase 1: Platform Foundation)

One API key (`sk-cm-live-…`), multiple AI models, OpenAI-compatible API.

Public contract: `https://ciptamodel.com/v1`
- `GET /v1/models` — live in Phase 1 (registry read, Bearer key required)
- `POST /v1/chat/completions` — contract final, returns honest `503 provider_not_connected` until Phase 2 wires providers

## Quickstart

```bash
cp .env.example .env   # set SESSION_SECRET (min 32 chars)
npm install
npm run init-db        # create + migrate + seed ./data/ciptamodel.db
npm start              # http://localhost:3000
npm test               # platform test suite (no credentials needed)
```

1. Register at `/register`, open `/dashboard/api-keys`, create a key (full secret shown once, masked afterwards).
2. Verify the registry:
```bash
curl localhost:3000/v1/models -H "Authorization: Bearer sk-cm-live-..."
```

Cursor / Cline / Open WebUI integration snippets: `/docs`, `/sdk`, `/examples`
(base URL `https://ciptamodel.com/v1`, model `deepseek-v4.1-flash` — active in Phase 2).

## Architecture

- `src/server.js` — Fastify app: public pages, authenticated `/dashboard/*` console, `/v1` contract stub, CSRF/session auth, rate-limit + quota enforcement, usage logging.
- `src/providers.js` — **Phase 1: interface only.** `ProviderAdapter` (`getModels`/`chatCompletion`/`streamChatCompletion`, all refusing with `provider_not_connected`) + pure `Router` (model id → adapter). No network calls, no credentials.
- `src/limits.js` — rate-limit/quota foundation (`createMemoryBackend`, `checkRate`, `checkQuota`); Redis can replace the backend without touching routes.
- `src/db.js` — SQLite (Postgres-compatible DDL): `users`, `api_keys` (SHA-256 hash + prefix only), `requests`, `plans`, `sessions` (+CSRF), `models` (registry), `providers` (catalog), `subscriptions`, `audit_logs`. Additive `migrate()` + `seed()`.
- `src/config.js` — plan defaults + model/provider seeds (DB wins at runtime).
- `public/` — console CSS (responsive, keyboard focus states) + playground JS. `tests/platform.test.js` — 26 auth/keys/gateway/registry/limits/docs/security tests.

Request flow (Phase 1): Bearer key → authenticate → validate model → minute-rate + daily quota checks → registry resolve → `503 provider_not_connected` (logged to `requests`, audited). Phase 2 adds connected adapters behind the same router; the public contract does not change.

## Tests / deploy

```bash
npm test   # 26 tests, 4 suites
npm run lint
```

Docker: `docker compose up --build` (SQLite volume `./data`). Behind a reverse
proxy, route `ciptamodel.com/*` to this service and `ciptamodel.com/v1/*` to the
same service to meet the public contract.
