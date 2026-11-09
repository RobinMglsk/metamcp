# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

MetaMCP is an MCP proxy/aggregator: users register upstream MCP servers (STDIO, SSE, Streamable HTTP), group them into **namespaces**, apply middleware (tool filtering, overrides, auditing), and expose each namespace through an **endpoint** that is itself an MCP server (SSE, Streamable HTTP, or OpenAPI). The `ai-dev` branch is the forward dev branch and includes AI-agent-authored changes.

## Commands

pnpm + Turborepo monorepo (`apps/*`, `packages/*`). Run from the repo root unless noted.

```bash
pnpm install
pnpm dev                 # turbo dev, loads env from .env.local (not .env)
pnpm build               # turbo build (packages build before apps)
pnpm lint                # eslint --max-warnings 0 in every package
pnpm lint:fix
pnpm check-types         # tsc --noEmit (frontend, zod-types)
pnpm format              # prettier

pnpm dev:docker          # full stack w/ hot reload + Postgres (docker-compose.dev.yml)
pnpm dev:docker:down     # stop; dev:docker:clean also drops volumes
```

Ports: frontend 12008, backend 12009, dev Postgres 9433 (host).

Backend (`apps/backend`):

```bash
pnpm --filter backend test                          # vitest run
pnpm --filter backend exec vitest run src/lib/metamcp/tools-sync-cache.test.ts   # single file
pnpm --filter backend exec vitest run -t "name"     # single test by name
pnpm --filter backend db:generate                   # drizzle-kit generate from src/db/schema.ts (uses ../../.env)
pnpm --filter backend db:migrate                    # apply migrations (uses ../../.env); :dev variants use .env.local
```

Only the backend has tests (vitest, `*.test.ts` colocated with source; `@/` alias maps to `src/`). Schema changes go in `apps/backend/src/db/schema.ts` followed by `db:generate`; migrations live in `apps/backend/drizzle/` and are run automatically by `docker-entrypoint.sh` on container start.

## Architecture

### Packages

- `apps/backend` — Express server on :12009. Hosts better-auth (`/api/auth`), tRPC (`/trpc/frontend`), public MCP endpoints (`/metamcp/...`), the inspector proxy (`/mcp-proxy/...`), and OAuth server routes (`/oauth`, `/.well-known`). Built with tsup.
- `apps/frontend` — Next.js app router on :12008 (`app/[locale]/...`, i18n via `public/locales/{en,es,ko,pt,zh}`; see `README-i18n.md` — add English strings first). `next.config.js` rewrites `/api/auth`, `/trpc`, `/mcp-proxy`, `/metamcp`, `/oauth`, `/.well-known`, `/health` to the backend, so the browser only ever talks to the frontend origin (`APP_URL`, which is also enforced by CORS).
- `packages/zod-types` (`@repo/zod-types`) — shared request/response Zod schemas (`*.zod.ts`) used by both sides.
- `packages/trpc` (`@repo/trpc`) — tRPC router **definitions only**. Each `routers/frontend/*.ts` exports a `createXRouter(implementations)` factory that declares procedures and their Zod I/O but takes the actual logic as injected functions.

### tRPC wiring (spans 3 packages)

To add or change an API: (1) schema in `packages/zod-types/src/*.zod.ts`, (2) procedure + implementation signature in `packages/trpc/src/routers/frontend/*.ts`, (3) implementation in `apps/backend/src/trpc/*.impl.ts`, wired up in `apps/backend/src/routers/trpc.ts` via `createAppRouter({ frontend: {...} })`. Implementations call repositories in `apps/backend/src/db/repositories/*.repo.ts` (Drizzle/Postgres) and use `db/serializers` to shape output. `protectedProcedure` requires the better-auth user/session from the backend's tRPC context. Shared packages must be built (`pnpm build` or `pnpm dev`, which watches them) before apps see changes.

### MCP proxy core (`apps/backend/src/lib/metamcp/`)

- `metamcp-proxy.ts` builds the aggregated MCP `Server` for a namespace: fetches the namespace's upstream servers (`fetch-metamcp.ts`), lists/calls tools, prompts, resources across them, and also exposes admin tools (`lib/admin-mcp/`) when enabled.
- Tool names are prefixed `{ServerName}__{toolName}`; the **first** `__` splits server from tool (`tool-name-parser.ts`, mirrored in `apps/frontend/lib/tool-name-parser.ts`).
- Middleware is functional composition over `ListToolsHandler` / `CallToolHandler` (`metamcp-middleware/functional-middleware.ts`): filter inactive tools, apply per-namespace tool overrides/annotations, audit-log requests.
- Two singleton pools keep warm connections: `mcp-server-pool.ts` (upstream MCP client sessions per server, incl. idle pre-spawned sessions, crash/error tracking) and `metamcp-server-pool.ts` (aggregated MetaMCP servers per namespace/session, plus OpenAPI sessions). Config changes must invalidate the relevant idle sessions/servers in these pools; startup (`lib/startup.ts`) and SIGTERM cleanup in `src/index.ts` manage them so STDIO child processes don't leak.
- `lib/stdio-transport/` handles STDIO upstreams; `lib/oauth-upstream/` handles OAuth to upstream MCP servers (token exchange, refresh-on-401, post-auth retry).

### Public endpoints (`apps/backend/src/routers/public-metamcp/`)

`sse.ts`, `streamable-http.ts`, and `openapi/` expose an endpoint's namespace; auth is API key (header or query) or MCP-spec OAuth served by `routers/oauth/`. These routes and `/mcp-proxy` are deliberately excluded from the global JSON body parser in `src/index.ts` so raw streams pass through — keep that when adding routes.

### Auth & config

better-auth (`apps/backend/src/auth.ts`) with email/password and optional OIDC (`OIDC_*` env). `lib/bootstrap.service.ts` provisions users/API keys/namespaces/endpoints from `BOOTSTRAP_*` env on startup. Any new env var needed by `pnpm dev` / `dev:docker` must be added to `globalEnv` in `turbo.json` or Turbo won't pass it through. STDIO server env values support `${VAR}` references resolved from the backend's environment.
